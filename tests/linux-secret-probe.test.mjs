import assert from 'node:assert/strict';
import { test } from 'node:test';
import { assertPrivateChild, main, secretProbeEnvironment } from '../scripts/linux-secret-probe.mjs';

const root = '/tmp/fin3000-secret-probe-Ab1234';
test('secret probe only accepts a private fixed-prefix temporary path', () => {
  for (const path of ['/', '/tmp', '/home/synthetic-user', `${root}/..`, `${root}\n`, `${root} x`]) {
    assert.throws(() => secretProbeEnvironment(path));
  }
});
test('secret probe child environment never inherits real desktop credentials/bus', () => {
  const env = secretProbeEnvironment(root);
  assert.deepEqual(Object.keys(env).sort(), ['PATH', 'LANG', 'LC_ALL', 'XDG_DATA_HOME', 'XDG_CONFIG_HOME',
    'XDG_RUNTIME_DIR', 'TMPDIR', 'FIN3000_SECRET_PROBE_ROOT'].sort());
  assert.equal(env.XDG_DATA_HOME, `${root}/data`);
  assert.throws(() => assertPrivateChild(root, env));
  const privateEnv = { ...env, DBUS_SESSION_BUS_ADDRESS: `unix:path=${root}/runtime/bus,guid=fixture` };
  assert.doesNotThrow(() => assertPrivateChild(root, privateEnv));
  for (const delta of [{ DISPLAY: ':0' }, { WAYLAND_DISPLAY: 'wayland-0' }, { XDG_DATA_HOME: '/real/data' },
    { GNOME_KEYRING_CONTROL: '/real/control' }, { DBUS_STARTER_ADDRESS: 'unix:path=/run/user/1000/bus' },
    { DBUS_SESSION_BUS_ADDRESS: 'unix:path=/run/user/1000/bus' }]) {
    assert.throws(() => assertPrivateChild(root, { ...privateEnv, ...delta }));
  }
});
test('help and invalid CLI never start a keyring or accept a real secret', async () => {
  const io = { stdout: { write() {} }, stderr: { write() {} } };
  const forbidden = () => { throw new Error('must not run'); };
  assert.equal(await main(['--help'], io, forbidden), 0);
  for (const args of [[], ['--private-child'], ['--run-synthetic', 'real-secret'], ['--password', 'value']]) {
    assert.equal(await main(args, io, forbidden), 2);
  }
});
test('native probe failure is not converted into a passed gate', async () => {
  let output = '';
  const io = { stdout: { write: text => { output += text; } }, stderr: { write() {} } };
  const report = { status: 'PASS', productReady: false, gateStatus: 'BLOCKED' };
  assert.equal(await main(['--run-synthetic'], io, async () => report), 0);
  assert.deepEqual(JSON.parse(output), report);
  assert.equal(await main(['--run-synthetic'], io, async () => { throw new Error('locked'); }), 1);
});

test('product mode is explicit, fixed and does not accept an arbitrary helper path', async () => {
  const io = { stdout: { write() {} }, stderr: { write() {} } };
  let product;
  assert.equal(await main(['--run-synthetic', '--product'], io, async value => { product = value; return {}; }), 0);
  assert.equal(product, true);
  assert.equal(await main(['--run-synthetic', '--product', '/arbitrary.js'], io, async () => { throw new Error('must not run'); }), 2);
});
