import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { desktopEnvironment, assertRootOwned, boundedSetupResult, LinuxAutostart } from '../../platforms/linux/process.ts';

function fakeSetupChild() {
  const child = new EventEmitter();
  child.stdout = new PassThrough(); child.kill = () => false; child.unref = () => {};
  return child;
}

test('root setup timeout completes even when signaling is denied and the child never exits', async () => {
  const child = fakeSetupChild();
  await assert.rejects(boundedSetupResult(child, 10), { code: 'SETUP_UNAVAILABLE' });
  assert.equal(child.stdout.destroyed, true);
  child.emit('error', Object.assign(new Error(), { code: 'EPERM' }));
});

test('root setup waits for output close, bounds bytes, and handles spawn failure', async () => {
  const child = fakeSetupChild(), result = boundedSetupResult(child, 1000);
  child.stdout.write('{"ok":'); child.emit('exit', 0); child.stdout.write('true}\n'); child.emit('close', 0);
  assert.deepEqual(await result, { code: 0, raw: '{"ok":true}\n' });
  const oversized = fakeSetupChild(), failure = boundedSetupResult(oversized, 1000);
  oversized.stdout.write(Buffer.alloc(4097));
  await assert.rejects(failure, { code: 'SETUP_UNAVAILABLE' });
  const unavailable = fakeSetupChild(), absent = boundedSetupResult(unavailable, 1000);
  unavailable.emit('error', new Error());
  await assert.rejects(absent, { code: 'SETUP_UNAVAILABLE' });
});

test('helper environment drops executable/library injection and requires the exact desktop bus', () => {
  const uid = process.getuid();
  const safe = { XDG_RUNTIME_DIR: `/run/user/${uid}`, DBUS_SESSION_BUS_ADDRESS: `unix:path=/run/user/${uid}/bus`,
    WAYLAND_DISPLAY: 'wayland-0', LANG: 'de_DE.UTF-8' };
  const env = desktopEnvironment({ ...safe, NODE_OPTIONS: '--import=evil', LD_PRELOAD: '/evil', PYTHONPATH: '/evil',
    GI_TYPELIB_PATH: '/evil', GJS_PATH: '/evil', PATH: '/evil', HOME: '/evil' });
  for (const key of ['NODE_OPTIONS', 'LD_PRELOAD', 'PYTHONPATH', 'GI_TYPELIB_PATH', 'GJS_PATH', 'HOME']) assert.equal(env[key], undefined);
  assert.equal(env.PATH, '/usr/bin:/bin'); assert.equal(env.WAYLAND_DISPLAY, 'wayland-0');
  for (const change of [{ XDG_RUNTIME_DIR: '/tmp/foreign' }, { DBUS_SESSION_BUS_ADDRESS: 'tcp:host=example.test' },
    { DBUS_SESSION_BUS_ADDRESS: `${safe.DBUS_SESSION_BUS_ADDRESS};unix:path=/tmp/other` }]) assert.throws(() => desktopEnvironment({ ...safe, ...change }), { code: 'DESKTOP_SESSION_UNAVAILABLE' });
});

test('helpers must be regular files with root-owned non-writable ancestors', async () => {
  await assertRootOwned('/usr/bin/gjs-console');
  await assert.rejects(assertRootOwned('/usr/bin/gjs'), { code: 'HELPER_TRUST_INVALID' });
  await assert.rejects(assertRootOwned(new URL(import.meta.url).pathname), { code: 'HELPER_TRUST_INVALID' });
  await assert.rejects(assertRootOwned('/usr/bin'), { code: 'HELPER_TRUST_INVALID' });
});

const unit = 'fin3000-printer.service', unitPath = `/usr/lib/systemd/user/${unit}`;
function autostartFixture(overrides = {}, change = true) {
  const calls = [], trusted = [], properties = { Id: unit, LoadState: 'loaded', FragmentPath: unitPath,
    DropInPaths: '', UnitFileState: 'disabled', ...overrides };
  const autostart = new LinuxAutostart(async args => {
    calls.push(args);
    if (args[0] === 'show') return Object.entries(properties).map(([key, value]) => `${key}=${value}\n`).join('');
    if (change && args[0] === 'enable') properties.UnitFileState = 'enabled';
    if (change && args[0] === 'disable') properties.UnitFileState = 'disabled';
    return '';
  }, async path => { trusted.push(path); });
  return { autostart, calls, trusted, properties };
}

test('autostart enables only the packaged user unit and verifies it without a second process', async () => {
  const f = autostartFixture();
  await assert.rejects(f.autostart.requireEnabled(), { code: 'AUTOSTART_UNAVAILABLE' });
  await f.autostart.set(true); await f.autostart.requireEnabled(); await f.autostart.set(true);
  assert.deepEqual(f.calls.filter(args => args[0] !== 'show'), [
    ['daemon-reload'], ['enable', unit], ['daemon-reload'],
  ]);
  assert.ok(f.trusted.length >= 7); assert.ok(f.trusted.every(path => path === unitPath));
  assert.ok(f.calls.filter(args => args[0] === 'show').every(args => args.includes('--all') && args.at(-1) === unit));
  assert.ok(f.calls.every(args => !args.some(arg => ['--now', 'start', 'stop', 'restart', 'unmask', '--force', '--global'].includes(arg))));
});

test('autostart removal is idempotent and does not stop its own GTK parent', async () => {
  const f = autostartFixture({ UnitFileState: 'enabled' });
  await f.autostart.set(false); await f.autostart.set(false);
  assert.deepEqual(f.calls.filter(args => args[0] !== 'show'), [
    ['daemon-reload'], ['disable', unit], ['daemon-reload'],
  ]);
  await assert.rejects(f.autostart.requireEnabled(), { code: 'AUTOSTART_UNAVAILABLE' });
});

test('autostart preserves masks, aliases, foreign fragments and all drop-in overrides', async () => {
  for (const change of [{ Id: 'foreign.service' }, { LoadState: 'masked' }, { LoadState: 'not-found' },
    { FragmentPath: '/home/test/.config/systemd/user/fin3000-printer.service' },
    { DropInPaths: '/etc/systemd/user/fin3000-printer.service.d/local.conf' },
    ...['masked', 'enabled-runtime', 'linked', 'alias', 'static', ''].map(UnitFileState => ({ UnitFileState }))]) {
    for (const enabled of [true, false]) {
      const f = autostartFixture(change);
      await assert.rejects(f.autostart.set(enabled), { code: 'AUTOSTART_UNAVAILABLE' });
      assert.deepEqual(f.calls.map(args => args[0]), ['show']);
    }
  }
});

test('autostart rejects malformed, duplicate, extra and overlong manager output', async () => {
  const valid = `Id=${unit}\nLoadState=loaded\nFragmentPath=${unitPath}\nDropInPaths=\nUnitFileState=enabled\n`;
  for (const raw of ['', valid.trimEnd(), valid + 'Id=foreign\n', valid + 'Unknown=value\n',
    valid.replace('DropInPaths=\n', ''), valid.replace('enabled\n', 'enabled\r\n'), 'x'.repeat(4097) + '\n']) {
    const client = new LinuxAutostart(async () => raw, async () => {});
    await assert.rejects(client.inspect(), { code: 'AUTOSTART_UNAVAILABLE' });
  }
});

test('autostart fails closed on trust/process failures, drift after reload, or failed enablement', async () => {
  let calls = 0;
  const untrusted = new LinuxAutostart(async () => { calls++; return ''; }, async () => { throw new Error('/private/path'); });
  await assert.rejects(untrusted.set(true), { code: 'AUTOSTART_UNAVAILABLE', message: 'AUTOSTART_UNAVAILABLE' });
  assert.equal(calls, 0);
  const failed = new LinuxAutostart(async () => { throw new Error('private systemctl details'); }, async () => {});
  await assert.rejects(failed.inspect(), { code: 'AUTOSTART_UNAVAILABLE', message: 'AUTOSTART_UNAVAILABLE' });
  for (const enabled of [true, false]) {
    const f = autostartFixture({ UnitFileState: enabled ? 'disabled' : 'enabled' }, false);
    await assert.rejects(f.autostart.set(enabled), { code: 'AUTOSTART_UNAVAILABLE' });
  }
  const f = autostartFixture(), run = f.autostart.run;
  f.autostart.run = async args => {
    const result = await run(args);
    if (args[0] === 'daemon-reload') f.properties.DropInPaths = '/foreign.conf';
    return result;
  };
  await assert.rejects(f.autostart.set(true), { code: 'AUTOSTART_UNAVAILABLE' });
  assert.equal(f.calls.some(args => ['enable', 'disable'].includes(args[0])), false);
});

test('autostart has no implicit command or truthy argument fallback', async () => {
  for (const value of [undefined, null, 'enable', 'false', 1, {}]) {
    const f = autostartFixture();
    await assert.rejects(f.autostart.set(value), { code: 'AUTOSTART_UNAVAILABLE' });
    assert.equal(f.calls.length, 0);
  }
});
