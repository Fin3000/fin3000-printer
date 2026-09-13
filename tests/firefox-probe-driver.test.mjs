import assert from 'node:assert/strict';
import test from 'node:test';
import { FirefoxProbeDriver } from '../scripts/firefox-probe-driver.mjs';

test('driver is loopback-only and rejects invalid ports before I/O', async () => {
  for (const port of [0, -1, 65536, 1.5, '443', 'example.com'])
    assert.throws(() => new FirefoxProbeDriver(port), /invalid_driver_port/);
  const driver = new FirefoxProbeDriver(12345);
  assert.equal(driver.base, 'http://127.0.0.1:12345');
  await assert.rejects(driver.call('GET', '/url'), /webdriver_session_missing/);
  assert.equal(await driver.script('return true').catch(() => null), null);
});

test('fresh headed session excludes extension, host binary and existing profile', async t => {
  const calls = [];
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    calls.push({url, options, data: options.body && JSON.parse(options.body)});
    return Response.json({value: calls.length === 1 ? {
      sessionId: 'synthetic-session', capabilities: {browserVersion: '154.0'},
    } : null});
  });
  const driver = new FirefoxProbeDriver(12345);
  await driver.start();
  assert.deepEqual(calls[0].data.capabilities.alwaysMatch, {
    browserName: 'firefox', 'moz:firefoxOptions': {args: [], prefs: {
      'browser.shell.checkDefaultBrowser': false, 'intl.locale.requested': 'de',
    }},
  });
  assert.equal(driver.version, '154.0');
  await driver.chrome();
  await driver.script('return arguments[0]', ['synthetic']);
  await driver.close();
  assert.deepEqual(calls.map(c => [c.options.method, new URL(c.url).pathname]), [
    ['POST','/session'], ['POST','/session/synthetic-session/window/rect'],
    ['POST','/session/synthetic-session/timeouts'], ['POST','/session/synthetic-session/moz/context'],
    ['POST','/session/synthetic-session/execute/sync'], ['DELETE','/session/synthetic-session'],
  ]);
  assert.ok(calls.every(c => c.options.redirect === 'error' && c.options.signal instanceof AbortSignal));
  assert.equal(driver.sid, null);
});

test('protocol errors surface and failed deletion clears the session', async t => {
  t.mock.method(globalThis, 'fetch', async () => Response.json({value: {
    error: 'invalid session id', message: 'synthetic missing session',
  }}, {status: 404}));
  const driver = new FirefoxProbeDriver(12345);
  driver.sid = 'synthetic';
  await assert.rejects(driver.script('return true'), {message: 'invalid session id',
    webdriverMessage: 'synthetic missing session'});
  await driver.close();
  assert.equal(driver.sid, null);
});

test('malformed sessions fail and bounded waits do not silently succeed', async t => {
  t.mock.method(globalThis, 'fetch', async () => Response.json({value: {sessionId: ''}}));
  const driver = new FirefoxProbeDriver(12345);
  await assert.rejects(driver.start(), /invalid_driver_session/);
  assert.equal(driver.sid, null);
  assert.equal(await driver.wait(async () => 'ready'), 'ready');
  await assert.rejects(driver.wait(async () => false, 0), /qa_state_timeout/);
});

test('fatal startup errors and cancellation bypass transient-dialog retries', async () => {
  const driver = new FirefoxProbeDriver(12345);
  const missingDriver = Object.assign(new Error('spawn geckodriver ENOENT'), {code: 'ENOENT'});
  let checks = 0;
  const check = async () => { checks++; return false; };
  await assert.rejects(driver.wait(check, 20_000, {fatal: () => missingDriver}),
    error => error === missingDriver);
  const abort = new AbortController();
  const interrupted = new Error('Firefox probe interrupted');
  abort.abort(interrupted);
  await assert.rejects(driver.wait(check, 20_000, {signal: abort.signal}),
    error => error === interrupted);
  assert.equal(checks, 0);
});

test('wait recovers after a transient exception and an absent dialog', async () => {
  const driver = new FirefoxProbeDriver(12345);
  let attempts = 0;
  const value = await driver.wait(async () => {
    attempts++;
    if (attempts === 1) throw new Error('stale native dialog');
    return attempts === 3 ? 'ready' : false;
  }, 2000);
  assert.equal(value, 'ready');
  assert.equal(attempts, 3);
});

test('wait times out after unsuccessful polling, not only an expired initial bound', async t => {
  const driver = new FirefoxProbeDriver(12345);
  let clockReads = 0;
  t.mock.method(Date, 'now', () => ++clockReads <= 2 ? 1000 : 1002);
  let attempts = 0;
  await assert.rejects(driver.wait(async () => { attempts++; return false; }, 1), /qa_state_timeout/);
  assert.equal(attempts, 1);
});

test('fatal driver failure during polling preserves its cause and stops further I/O', async () => {
  const driver = new FirefoxProbeDriver(12345);
  const failure = new Error('spawn geckodriver ENOENT');
  let error, attempts = 0;
  await assert.rejects(driver.wait(async () => {
    attempts++; error = failure; return false;
  }, 2000, {fatal: () => error}), reason => reason === failure);
  assert.equal(attempts, 1);
});

test('cancellation during polling stops before a further dialog request', async () => {
  const driver = new FirefoxProbeDriver(12345);
  const abort = new AbortController(), failure = new Error('Firefox probe interrupted');
  let attempts = 0;
  await assert.rejects(driver.wait(async () => {
    attempts++; abort.abort(failure); return false;
  }, 2000, {signal: abort.signal}), reason => reason === failure);
  assert.equal(attempts, 1);
});
