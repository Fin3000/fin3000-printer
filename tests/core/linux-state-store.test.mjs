import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { chmod, link, mkdir, mkdtemp, readFile, readdir, rename, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { execFileSync } from 'node:child_process';
import { LinuxStateStore } from '../../platforms/linux/state-store.ts';
import { MAX_STATE_BYTES, stateReleaseFromManifest, validateSnapshot, validateStateRelease } from '../../core/state-store.ts';
import { Coordinator } from '../../core/coordinator.ts';

const release = { package: 'fin3000-printer-qa', version: '0.1.0~qa1', sourceCommit: 'a'.repeat(40), stateSchemaVersion: 1, protocolVersion: 2 };
const nextRelease = { ...release, version: '0.2.0~qa1', sourceCommit: 'b'.repeat(40) };

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'fin3000-state-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state');
  const store = await LinuxStateStore.acquire(path, release);
  t.after(() => store.close());
  return { path, store, directory };
}

test('atomic metadata round trip is private and retained across lease release', async t => {
  const f = await fixture(t);
  assert.deepEqual(await f.store.load(), { version: 1, jobs: [] });
  await f.store.save({ version: 1, jobs: [] });
  assert.deepEqual(await f.store.load(), { version: 1, jobs: [] });
  assert.equal((await stat(join(f.path, 'state.json'))).mode & 0o777, 0o600);
  await f.store.close();
  const restarted = await LinuxStateStore.acquire(f.path, release);
  t.after(() => restarted.close());
  assert.deepEqual(await restarted.load(), { version: 1, jobs: [] });
});

test('flock lease survives the helper process and rejects another coordinator', async t => {
  const f = await fixture(t);
  await assert.rejects(LinuxStateStore.acquire(f.path, release), { code: 'INSTANCE_ALREADY_RUNNING' });
  await f.store.save({ version: 1, jobs: [] });
});

test('symlink directory and file, group readable state and hardlinks fail closed', async t => {
  const f = await fixture(t);
  const alias = join(f.directory, 'alias');
  await symlink(f.path, alias);
  await assert.rejects(LinuxStateStore.acquire(alias, release), { code: 'STATE_PATH_INVALID' });
  const foreign = join(f.directory, 'unrelated');
  await writeFile(foreign, 'Do not overwrite', { mode: 0o600 });
  await rm(join(f.path, 'state.json'));
  await symlink(foreign, join(f.path, 'state.json'));
  await assert.rejects(f.store.load());
  await assert.rejects(f.store.save({ version: 1, jobs: [] }));
  assert.equal(await readFile(foreign, 'utf8'), 'Do not overwrite');
  await rm(join(f.path, 'state.json'));
  await link(foreign, join(f.path, 'state.json'));
  await assert.rejects(f.store.load());
  await assert.rejects(f.store.save({ version: 1, jobs: [] }));
  await rm(join(f.path, 'state.json'));
  await writeFile(join(f.path, 'state.json'), '{"version":1,"jobs":[]}', { mode: 0o600 });
  await chmod(join(f.path, 'state.json'), 0o644);
  await assert.rejects(f.store.load());
});

test('directory inode is pinned: replacing pathname cannot redirect state writes', async t => {
  const f = await fixture(t);
  await rename(f.path, join(f.directory, 'original'));
  await mkdir(f.path, { mode: 0o700 });
  await writeFile(join(f.path, 'state.json'), 'unrelated replacement');
  await f.store.save({ version: 1, jobs: [] });
  assert.equal(await readFile(join(f.path, 'state.json'), 'utf8'), 'unrelated replacement');
  assert.deepEqual(JSON.parse(await readFile(join(f.directory, 'original', 'state.json'), 'utf8')), { version: 1, jobs: [] });
});

test('malformed and oversized state never starts empty as a fallback', async t => {
  const f = await fixture(t);
  for (const data of ['not-json', '{"version":2,"jobs":[]}', 'x'.repeat(MAX_STATE_BYTES + 1)]) {
    await writeFile(join(f.path, 'state.json'), data, { mode: 0o600 });
    await assert.rejects(f.store.load());
  }
});

test('state schema rejects secrets and unexpected data instead of serializing them', () => {
  assert.throws(() => validateSnapshot({ version: 1, jobs: [], accessToken: 'never-save' }), { code: 'STATE_INVALID' });
  assert.throws(() => validateSnapshot({ version: 1, jobs: [null] }), { code: 'STATE_INVALID' });
});

test('drained coordinator releases its real Linux lease with recovery durable and no late writes', async t => {
  const f = await fixture(t);
  let finishNetwork, sends = 0, signal;
  const network = new Promise(resolve => { finishNetwork = resolve; });
  const account = { issuer: 'https://api.fin3000.test', audience: 'fin3000-printer:qa',
    clientId: 'fin3000-system-print-qa', subject: `sp_${'b'.repeat(32)}`, target: { id: null, name: 'Synthetic account' } };
  const ports = { clock: { now: () => 1_000_000 }, random: () => 0.5,
    verifier: { verify() { return 'accepted'; } },
    transfer: { send(_row, _bytes, current) { sends++; signal = current; return network; },
      async reconcile() { throw new Error('must not send during restart'); } } };
  const agent = new Coordinator({ store: f.store, ...ports });
  await agent.start(); await agent.connect(account);
  const job = await agent.admit({ generation: randomUUID(), nativeJobUuid: randomUUID() },
    'Synthetic', Buffer.from('%PDF-synthetic'));
  t.after(async () => { finishNetwork('accepted'); await agent.drain(); });
  // The real fsync path need not finish in one event-loop turn.
  for (let step = 0; step < 100 && !signal; step++) await new Promise(resolve => setTimeout(resolve, 10));
  assert.ok(signal, 'the transfer must have reached the network boundary');
  await assert.rejects(LinuxStateStore.acquire(f.path, release), { code: 'INSTANCE_ALREADY_RUNNING' });
  await agent.drain();
  assert.equal(signal.aborted, true);
  const before = await readFile(join(f.path, 'state.json'), 'utf8');
  const saved = JSON.parse(before);
  assert.equal(saved.jobs[0].operationId, job.operationId);
  assert.equal(saved.jobs[0].outcome, 'uncertain');
  assert.equal(saved.jobs[0].delivery, 'possibly_delivered');
  await f.store.close();
  const nextStore = await LinuxStateStore.acquire(f.path, nextRelease);
  t.after(() => nextStore.close());
  const activation = JSON.parse(await readFile(join(f.path, 'activation.json'), 'utf8'));
  const checkpoint = JSON.parse(await readFile(join(f.path, activation.backup.file), 'utf8'));
  assert.deepEqual(checkpoint.state, saved);
  finishNetwork('accepted'); await new Promise(resolve => setImmediate(resolve));
  assert.equal(await readFile(join(f.path, 'state.json'), 'utf8'), before);
  const restarted = new Coordinator({ store: nextStore, ...ports });
  await restarted.start();
  assert.equal(restarted.snapshot()[0].operationId, job.operationId);
  assert.equal(restarted.snapshot()[0].outcome, 'uncertain');
  assert.equal(sends, 1, 'restart must never repeat an unresolved upload');
  await restarted.drain();
});

test('release identity rejects unsupported schemas, environments and invalid versions before disk access', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'fin3000-release-invalid-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'must-not-create');
  for (const changed of [null, {}, { ...release, stateSchemaVersion: 2 }, { ...release, protocolVersion: 3 },
    { ...release, sourceCommit: '0'.repeat(40) }, { ...release, version: '0.1.0; command' },
    { ...release, version: '00.1.0~qa1' }, { ...release, version: '0.1.0' },
    { ...release, package: 'another-app' }, { ...release, accessToken: 'never-save' }]) {
    await assert.rejects(LinuxStateStore.acquire(path, changed), { code: 'STATE_VERSION_UNSUPPORTED' });
  }
  assert.deepEqual(await readdir(directory), []);
  assert.deepEqual(stateReleaseFromManifest({ ...release, sourceFiles: {} }, 'qa'), release);
  assert.throws(() => stateReleaseFromManifest(release, 'production'), { code: 'BUILD_CONFIG_INVALID' });
  const product = { ...release, package: 'fin3000-printer', version: '0.1.0' };
  assert.deepEqual(stateReleaseFromManifest(product, 'production'), product);
  assert.throws(() => stateReleaseFromManifest(product, 'qa'), { code: 'BUILD_CONFIG_INVALID' });
  assert.throws(() => validateStateRelease({ ...product, version: '0.1.0~qa1' }), { code: 'STATE_VERSION_UNSUPPORTED' });
});

test('same release startup is idempotent; a different build creates a private checkpoint before activation', async t => {
  const f = await fixture(t);
  const initial = JSON.parse(await readFile(join(f.path, 'activation.json'), 'utf8'));
  assert.deepEqual(initial, { version: 1, release, backup: null });
  assert.equal((await stat(join(f.path, 'activation.json'))).mode & 0o777, 0o600);
  await f.store.close();
  const same = await LinuxStateStore.acquire(f.path, release); await same.close();
  assert.deepEqual((await readdir(f.path)).sort(), ['.agent.lock', 'activation.json', 'state.json']);
  const original = await readFile(join(f.path, 'state.json'), 'utf8');
  // QA builds can have the same package version but different immutable sources.
  const changed = { ...release, sourceCommit: nextRelease.sourceCommit };
  const next = await LinuxStateStore.acquire(f.path, changed); t.after(() => next.close());
  const active = JSON.parse(await readFile(join(f.path, 'activation.json'), 'utf8'));
  assert.deepEqual(active.release, changed);
  const backup = join(f.path, active.backup.file);
  assert.equal((await stat(backup)).mode & 0o777, 0o600);
  assert.deepEqual(JSON.parse(await readFile(backup, 'utf8')),
    { version: 1, from: release, to: changed, state: JSON.parse(original) });
  assert.equal(await readFile(join(f.path, 'state.json'), 'utf8'), original);
});

test('first known build checkpoints existing v1 state, never an empty fallback for corrupt state', async t => {
  const f = await fixture(t); await f.store.close();
  await rm(join(f.path, 'activation.json'));
  const before = await readFile(join(f.path, 'state.json'), 'utf8');
  const resumed = await LinuxStateStore.acquire(f.path, nextRelease); t.after(() => resumed.close());
  const active = JSON.parse(await readFile(join(f.path, 'activation.json'), 'utf8'));
  const backup = JSON.parse(await readFile(join(f.path, active.backup.file), 'utf8'));
  assert.equal(backup.from, null); assert.deepEqual(backup.state, JSON.parse(before));
});

test('missing, malformed or unsupported existing state refuses activation without changing any bytes', async t => {
  const f = await fixture(t); await f.store.close();
  const activation = await readFile(join(f.path, 'activation.json'), 'utf8');
  await rm(join(f.path, 'state.json'));
  await assert.rejects(LinuxStateStore.acquire(f.path, nextRelease), { code: 'STATE_INVALID' });
  for (const raw of ['not-json', '{"version":2,"jobs":[]}', '{"version":1,"jobs":[],"accessToken":"never-save"}']) {
    await writeFile(join(f.path, 'state.json'), raw, { mode: 0o600 });
    await assert.rejects(LinuxStateStore.acquire(f.path, nextRelease), { code: 'STATE_INVALID' });
    assert.equal(await readFile(join(f.path, 'state.json'), 'utf8'), raw);
    assert.equal(await readFile(join(f.path, 'activation.json'), 'utf8'), activation);
  }
  assert.deepEqual((await readdir(f.path)).sort(), ['.agent.lock', 'activation.json', 'state.json']);
});

test('activation failure retains old state and checkpoint; retry never overwrites or auto-restores backups', async t => {
  const f = await fixture(t); await f.store.close();
  const state = await readFile(join(f.path, 'state.json'), 'utf8');
  const activation = await readFile(join(f.path, 'activation.json'), 'utf8');
  const original = LinuxStateStore.prototype.writeAtomic;
  const mocked = t.mock.method(LinuxStateStore.prototype, 'writeAtomic', async function (name, bytes) {
    if (name === 'activation.json') throw new Error('synthetic activation I/O failure');
    return original.call(this, name, bytes);
  });
  await assert.rejects(LinuxStateStore.acquire(f.path, nextRelease), /synthetic activation I\/O failure/);
  mocked.mock.restore();
  assert.equal(await readFile(join(f.path, 'state.json'), 'utf8'), state);
  assert.equal(await readFile(join(f.path, 'activation.json'), 'utf8'), activation);
  const before = (await readdir(f.path)).filter(name => name.startsWith('state-before-'));
  assert.equal(before.length, 1);
  const checkpoint = await readFile(join(f.path, before[0]), 'utf8');
  const retried = await LinuxStateStore.acquire(f.path, nextRelease); t.after(() => retried.close());
  assert.equal(await readFile(join(f.path, before[0]), 'utf8'), checkpoint);
  assert.equal((await readdir(f.path)).filter(name => name.startsWith('state-before-')).length, 2);
});

test('unsafe activation and checkpoint paths are never followed or overwritten', async t => {
  const f = await fixture(t); await f.store.close();
  const foreign = join(f.directory, 'unrelated');
  await writeFile(foreign, 'Do not modify', { mode: 0o600 });
  await rm(join(f.path, 'activation.json'));
  await symlink(foreign, join(f.path, 'activation.json'));
  await assert.rejects(LinuxStateStore.acquire(f.path, nextRelease), { code: 'STATE_INVALID' });
  assert.equal(await readFile(foreign, 'utf8'), 'Do not modify');
  await rm(join(f.path, 'activation.json'));
  await writeFile(join(f.path, 'activation.json'), JSON.stringify({ version: 1, release,
    backup: { file: '../unrelated', sha256: 'a'.repeat(64) } }), { mode: 0o600 });
  await assert.rejects(LinuxStateStore.acquire(f.path, nextRelease), { code: 'STATE_INVALID' });
  assert.equal(await readFile(foreign, 'utf8'), 'Do not modify');
});

test('damaged checkpoint stops before activating another build and never replaces current state', async t => {
  const f = await fixture(t); await f.store.close();
  const next = await LinuxStateStore.acquire(f.path, nextRelease); await next.close();
  const active = await readFile(join(f.path, 'activation.json'), 'utf8');
  const state = await readFile(join(f.path, 'state.json'), 'utf8');
  const backup = JSON.parse(active).backup.file;
  await writeFile(join(f.path, backup), '{}', { mode: 0o600 });
  await assert.rejects(LinuxStateStore.acquire(f.path, release), { code: 'STATE_INVALID' });
  assert.equal(await readFile(join(f.path, 'state.json'), 'utf8'), state);
  assert.equal(await readFile(join(f.path, 'activation.json'), 'utf8'), active);
});

test('a compatible older build reads the latest state rather than its earlier checkpoint', async t => {
  const f = await fixture(t);
  const account = { issuer: 'https://api.fin3000.test', audience: 'fin3000-printer:qa',
    clientId: 'fin3000-system-print-qa', subject: `sp_${'b'.repeat(32)}`, target: { id: null, name: 'Synthetic' } };
  await f.store.close();
  const next = await LinuxStateStore.acquire(f.path, nextRelease);
  const agent = new Coordinator({ store: next, clock: { now: () => 1_000_000 },
    verifier: { verify() { return 'accepted'; } },
    transfer: { async send() { return 'accepted'; }, async reconcile() { return 'accepted'; } } });
  await agent.start(); await agent.connect(account);
  const job = await agent.admit({ generation: randomUUID(), nativeJobUuid: randomUUID() }, 'Synthetic', Buffer.from('%PDF-synthetic'));
  await agent.confirm(job.operationId); await agent.drain(); await next.close();
  const rollback = await LinuxStateStore.acquire(f.path, release); t.after(() => rollback.close());
  const latest = await rollback.load();
  assert.equal(latest.jobs[0].operationId, job.operationId); assert.equal(latest.jobs[0].outcome, 'accepted');
  assert.equal(latest.jobs[0].receipt, 'accepted');
  const active = JSON.parse(await readFile(join(f.path, 'activation.json'), 'utf8'));
  assert.deepEqual(JSON.parse(await readFile(join(f.path, active.backup.file), 'utf8')).state, latest);
});

test('state or activation FIFO fails promptly without waiting for a writer', async t => {
  for (const name of ['state.json', 'activation.json']) {
    const f = await fixture(t); await f.store.close();
    await rm(join(f.path, name));
    execFileSync('/usr/bin/mkfifo', ['--mode=600', join(f.path, name)], { timeout: 5000 });
    await assert.rejects(LinuxStateStore.acquire(f.path, nextRelease), { code: 'STATE_INVALID' });
  }
});

test('activation cannot cross the isolated QA and production identities', async t => {
  const f = await fixture(t); await f.store.close();
  const before = await readFile(join(f.path, 'activation.json'), 'utf8');
  const product = { ...nextRelease, package: 'fin3000-printer', version: '0.2.0' };
  await assert.rejects(LinuxStateStore.acquire(f.path, product), { code: 'STATE_INVALID' });
  assert.equal(await readFile(join(f.path, 'activation.json'), 'utf8'), before);
});

test('checkpoint readback verification fails before replacing the activation identity', async t => {
  const f = await fixture(t); await f.store.close();
  const before = await readFile(join(f.path, 'activation.json'), 'utf8');
  const original = LinuxStateStore.prototype.readPrivate;
  t.mock.method(LinuxStateStore.prototype, 'readPrivate', async function (name, limit) {
    if (name.startsWith('state-before-')) return Buffer.from('synthetic readback corruption');
    return original.call(this, name, limit);
  });
  await assert.rejects(LinuxStateStore.acquire(f.path, nextRelease), { code: 'STATE_INVALID' });
  assert.equal(await readFile(join(f.path, 'activation.json'), 'utf8'), before);
});
