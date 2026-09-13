import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

// Exercise the actual GTK bridge function without launching a browser or GTK.
const source = readFileSync(new URL('../../platforms/linux/app.js', import.meta.url), 'utf8');
const browserSource = source.slice(source.indexOf('function browser(message) {'), source.indexOf('\nfunction receive(message) {'));
const requestId = '12345678-1234-1234-1234-123456789abc';
function fixture({ missing = false, fail = false, qa = false } = {}) {
  const replies = [], launches = [], schemes = [], removedEnvironment = [];
  const handler = {
    launch_uris_async(uris, context, cancellable, callback) {
      assert.deepEqual(removedEnvironment, ['G_DEBUG'], 'browser must not inherit GTK fatal policy');
      launches.push([...uris]); callback(handler, {});
    },
    launch_uris_finish() { if (fail) throw new Error('unavailable'); return true; },
  };
  const scope = vm.createContext({
    QA_BUILD: qa, send: reply => replies.push({ ...reply }),
    Gio: { AppInfo: { get_default_for_uri_scheme(scheme) { schemes.push(scheme); return missing ? null : handler; } } },
    Gdk: { Display: { get_default: () => ({ get_app_launch_context: () => ({ unsetenv: name => removedEnvironment.push(name) }) }) } },
    GLib: { UriFlags: { NONE: 0 }, Uri: { parse(raw) {
      const value = new URL(raw);
      return { get_scheme: () => value.protocol.slice(0, -1), get_host: () => value.hostname,
        get_port: () => value.port ? Number(value.port) : -1, get_userinfo: () => value.username || value.password,
        get_fragment: () => value.hash, get_path: () => value.pathname };
    } } },
  });
  vm.runInContext(browserSource, scope);
  return { run: url => scope.browser({ requestId, url }), replies, launches, schemes };
}

test('native links use the selected scheme handler, with no content-type/editor fallback', () => {
  const f = fixture(), url = 'https://app.fin3000.com/oauth/authorize?state=synthetic';
  f.run(url);
  assert.deepEqual(f.schemes, ['https']); assert.deepEqual(f.launches, [[url]]);
  assert.deepEqual(f.replies, [{ action: 'browserResult', requestId, ok: true }]);
});

test('missing browser and failed launch report failure exactly once', () => {
  for (const options of [{ missing: true }, { fail: true }]) {
    const f = fixture(options); f.run('https://app.fin3000.com/oauth/authorize');
    assert.deepEqual(f.replies, [{ action: 'browserResult', requestId, ok: false }]);
    assert.equal(f.launches.length, options.missing ? 0 : 1);
  }
});

test('native bridge still rejects foreign origins and paths before handler lookup', () => {
  for (const url of ['https://foreign.invalid/oauth/authorize', 'http://127.0.0.1:4763/oauth/authorize',
    'https://app.fin3000.com/elsewhere', 'https://user@app.fin3000.com/oauth/authorize',
    'https://app.fin3000.com/oauth/authorize#fragment']) {
    const f = fixture(); f.run(url);
    assert.deepEqual(f.schemes, []); assert.deepEqual(f.launches, []);
    assert.equal(f.replies.length, 1); assert.equal(f.replies[0].ok, false);
  }
  const f = fixture({ qa: true }); f.run('http://127.0.0.1:4763/oauth/authorize');
  assert.deepEqual(f.schemes, ['http']); assert.equal(f.replies[0].ok, true);
});
