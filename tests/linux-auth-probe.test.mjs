import assert from 'node:assert/strict';
import { test } from 'node:test';
import { BASE_IMAGES, containerArguments, main } from '../scripts/linux-auth-probe.mjs';

const name = 'fin3000-g0-auth-01234567-1234-1234-1234-012345678901';
const image = `sha256:${'a'.repeat(64)}`;
test('container isolation has no mounts, ports, host namespace or broad privileges', () => {
  const args = containerArguments(name, image);
  for (const [key, value] of [['--context', 'default'], ['--network', 'none'], ['--cap-drop', 'ALL'],
    ['--memory', '256m'], ['--pids-limit', '64'], ['--security-opt', 'no-new-privileges']]) {
    assert.equal(args[args.indexOf(key) + 1], value);
  }
  assert.ok(args.includes('--read-only'));
  assert.ok(args.includes('--rm'));
  assert.ok(args.includes(`com.fin3000.synthetic-probe=${name}`));
  for (const forbidden of ['--privileged', '--mount', '-v', '--volume', '-p', '--publish', '--pid', '--userns', '--device', 'SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE']) {
    assert.ok(!args.includes(forbidden));
  }
  assert.equal(args.at(-1), image);
});
test('container targets and public Ubuntu bases are digest-pinned', () => {
  for (const value of Object.values(BASE_IMAGES)) assert.match(value, /^ubuntu@sha256:[a-f0-9]{64}$/);
  for (const badName of ['prod', name + ' x', name + '/..', '*']) assert.throws(() => containerArguments(badName, image));
  for (const badImage of ['ubuntu:latest', '--privileged', 'registry.example/prod']) assert.throws(() => containerArguments(name, badImage));
});
test('CLI help or ambiguous requests cannot trigger builds or containers', async () => {
  const io = { stdout: { write() {} }, stderr: { write() {} } };
  const forbidden = () => { throw new Error('must not run'); };
  assert.equal(await main(['--help'], io, forbidden), 0);
  for (const args of [[], ['--run-synthetic'], ['--run-synthetic', '24.04'], ['--run-synthetic', '--ubuntu=22.04'],
    ['--run-synthetic', '--ubuntu=24.04', 'invoice.pdf']]) assert.equal(await main(args, io, forbidden), 2);
});
test('a container success is explicitly not native desktop or release approval', async () => {
  let output = '';
  const io = { stdout: { write: text => { output += text; } }, stderr: { write() {} } };
  const report = { status: 'PASS', productReady: false, gateStatus: 'BLOCKED' };
  assert.equal(await main(['--run-synthetic', '--ubuntu=24.04'], io, async ubuntu => {
    assert.equal(ubuntu, '24.04'); return report;
  }), 0);
  assert.deepEqual(JSON.parse(output), report);
  assert.equal(await main(['--run-synthetic', '--ubuntu=26.04'], io, async () => { throw new Error('failed'); }), 1);
});
