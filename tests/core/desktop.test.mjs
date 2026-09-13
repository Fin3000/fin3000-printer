import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import test from 'node:test';
import { DesktopController } from '../../core/desktop.ts';
import { Coordinator } from '../../core/coordinator.ts';
import { PrinterError } from '../../core/protocol.ts';
import { PinnedReceiptVerifier } from '../../core/receipts.ts';

const identity = () => ({ generation: randomUUID(), nativeJobUuid: randomUUID() });
const pdf = Buffer.from('%PDF-synthetic');
const binding = () => ({ issuer: 'https://api.fin3000.test', audience: 'fin3000-printer:qa', clientId: 'fin3000-system-print-qa',
  subject: `sp_${'c'.repeat(32)}`, target: { id: randomUUID(), name: 'Synthetic company' } });
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };

async function fixture(overrides = {}) {
  const account = binding(), snapshots = [], calls = [], opens = [], exports = [];
  const clock = { now: () => 1_000_000 };
  const transfer = { async send() { calls.push('send'); return 'accepted'; }, async reconcile() { calls.push('reconcile'); return 'accepted'; }, ...overrides.transfer };
  const agent = new Coordinator({ store: { async load() { return null; }, async save() {} }, transfer,
    verifier: overrides.verifier ?? { verify(token) { if (token !== 'accepted') throw new PrinterError('RECEIPT_INVALID'); return 'accepted'; } }, clock });
  const auth = { async restore() { calls.push('restore'); return account; }, async authorize() { calls.push('authorize'); return account; },
    async disconnect() { calls.push('revoke'); },
    lock() { calls.push('lock'); }, ...overrides.auth };
  const native = { async start() { calls.push('native_start'); }, async stop() { calls.push('native_stop'); }, async setup(action) { calls.push(action); }, ...overrides.native };
  const desktop = new DesktopController({ agent, auth, native, now: clock.now, emit: value => snapshots.push(value), open: async where => opens.push(where),
    exportRecovery: (operationId, content) => exports.push({operationId, content}) });
  await desktop.start();
  return { desktop, agent, snapshots, calls, opens, exports, account, auth, native, last: () => snapshots.at(-1),
    async unlock() { await desktop.command({ action: 'session', locked: false }); await desktop.idle(); } };
}

test('no desktop-unlock evidence means no login or document admission', async () => {
  const f = await fixture();
  await f.desktop.command({ action: 'connect' });
  assert.equal(f.last().code, 'SESSION_LOCKED');
  assert.equal(f.calls.includes('authorize'), false);
  await assert.rejects(f.desktop.admit(identity(), 'synthetic', pdf), { code: 'CONNECT_AND_REPRINT' });
});

test('ready only after native start, secure restore and fresh principal binding', async () => {
  const f = await fixture(); await f.unlock();
  assert.equal(f.last().connected, true);
  assert.equal(f.last().target, f.account.target.name);
  const job = await f.desktop.admit(identity(), 'synthetic', pdf);
  assert.equal(f.last().jobs[0].canSend, true);
  assert.equal(f.calls.includes('send'), false);
  await f.desktop.command({ action: 'confirm', operationId: job.operationId });
  await f.desktop.idle();
  assert.equal(f.last().jobs[0].outcome, 'accepted');
  assert.equal(f.calls.filter(call => call === 'send').length, 1);
  const text = JSON.stringify(f.last());
  for (const secret of ['receipt', 'requestFingerprint', 'pdfSha256', 'callbackNonce', f.account.subject, '%PDF']) assert.equal(text.includes(secret), false);
});

test('unassigned account remains connected and presents a localizable null destination', async () => {
  const f = await fixture(); f.account.target.id = null;
  await f.unlock();
  assert.equal(f.last().connected, true); assert.equal(f.last().target, null);
  const job = await f.desktop.admit(identity(), 'synthetic', pdf);
  assert.equal(f.last().jobs[0].target, null); assert.equal(f.last().jobs[0].canSend, true);
  await f.desktop.command({ action: 'confirm', operationId: job.operationId });
  await f.desktop.idle(); assert.ok(f.calls.includes('send'));
});

test('installation failure stays setup-required and never opens login', async () => {
  const f = await fixture({ native: { async start() { throw new Error('missing package'); } } });
  await f.unlock();
  assert.equal(f.last().queueReady, false);
  assert.equal(f.last().code, 'SETUP_REQUIRED');
  await f.desktop.command({ action: 'connect' });
  assert.equal(f.calls.includes('authorize'), false);
});

test('setup is a separate explicit action; interrupted setup does not mean connected', async () => {
  const f = await fixture({ auth: { async restore() { throw new PrinterError('LOGIN_REQUIRED'); } } });
  await f.unlock();
  await f.desktop.command({ action: 'configure' }); await f.desktop.idle();
  assert.equal(f.calls.includes('configure'), true);
  assert.equal(f.last().queueReady, true); assert.equal(f.last().connected, false);
  assert.equal(f.calls.includes('authorize'), false);
});

test('repairing an existing queue clears admission until a fresh account check', async () => {
  const f = await fixture(); await f.unlock();
  assert.equal(f.last().connected, true);
  await f.desktop.command({ action: 'configure' }); await f.desktop.idle();
  assert.equal(f.last().connected, false);
  await assert.rejects(f.desktop.admit(identity(), 'synthetic', pdf), { code: 'CONNECT_AND_REPRINT' });
});

test('login can be cancelled while it is pending; late result never connects', async () => {
  const pending = deferred();
  const f = await fixture({ auth: { async restore() { throw new PrinterError('LOGIN_REQUIRED'); }, authorize() { return pending.promise; } } });
  await f.unlock();
  await f.desktop.command({ action: 'connect' });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.last().busy, 'login');
  await f.desktop.command({ action: 'cancelLogin' });
  pending.resolve(f.account); await f.desktop.idle();
  assert.equal(f.last().connected, false);
});

test('locking cancels confirmation and a late authentication cannot reconnect', async () => {
  const f = await fixture(); await f.unlock();
  await f.desktop.admit(identity(), 'synthetic', pdf);
  await f.desktop.command({ action: 'session', locked: true });
  assert.equal(f.last().jobs[0].outcome, 'cancelled');
  assert.equal(f.last().connected, false); assert.equal(f.last().locked, true);
  await f.desktop.command({ action: 'connect' });
  assert.equal(f.calls.includes('authorize'), false);
});

test('original action cancels the local copy BEFORE opening the existing upload', async () => {
  const f = await fixture(); await f.unlock();
  const job = await f.desktop.admit(identity(), 'synthetic', pdf);
  await f.desktop.command({ action: 'original', operationId: job.operationId });
  assert.equal(f.last().jobs[0].outcome, 'cancelled');
  assert.deepEqual(f.opens, ['original']); assert.equal(f.calls.includes('send'), false);
});

test('cancel remains responsive during transfer and uncertain state cannot open original upload', async () => {
  const pending = deferred();
  const f = await fixture({ transfer: { send() { return pending.promise; } } }); await f.unlock();
  const job = await f.desktop.admit(identity(), 'synthetic', pdf);
  await f.desktop.command({ action: 'confirm', operationId: job.operationId });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.last().busy, 'transfer');
  await f.desktop.command({ action: 'cancel', operationId: job.operationId }); await f.desktop.idle();
  assert.equal(f.last().jobs[0].outcome, 'uncertain');
  await f.desktop.command({ action: 'original', operationId: job.operationId });
  assert.equal(f.last().code, 'ORIGINAL_NOT_AVAILABLE'); assert.deepEqual(f.opens, []);
  pending.reject(new Error('synthetic aborted network'));
});

test('remove requires prior explicit drain and never clears saved recovery metadata', async () => {
  const f = await fixture(); await f.unlock();
  await f.desktop.command({ action: 'remove' });
  assert.equal(f.last().code, 'DRAIN_REQUIRED');
  await f.desktop.admit(identity(), 'synthetic', pdf);
  await f.desktop.command({ action: 'prepareRemoval' }); await f.desktop.idle();
  assert.equal(f.last().draining, true); assert.equal(f.last().queueReady, false);
  assert.equal(f.last().jobs[0].outcome, 'cancelled');
  await f.desktop.command({ action: 'remove' }); await f.desktop.idle();
  assert.equal(f.calls.includes('remove'), true);
  assert.ok(f.calls.indexOf('revoke') < f.calls.indexOf('remove'));
  assert.equal(f.last().removed, true);
  assert.equal(f.last().jobs[0].outcome, 'cancelled');
  await f.desktop.command({ action: 'configure' }); await f.desktop.idle();
  assert.equal(f.last().code, 'REMOVED_RESTART_REQUIRED');
  assert.equal(f.calls.includes('configure'), false);
});

test('failed queue removal never reports removed and can be retried after the pending job is resolved', async () => {
  const f = await fixture({ native: { async setup() { throw new PrinterError('PRINT_JOBS_PENDING'); } } });
  await f.unlock(); await f.desktop.command({ action: 'prepareRemoval' }); await f.desktop.idle();
  await f.desktop.command({ action: 'remove' }); await f.desktop.idle();
  assert.equal(f.last().removed, false); assert.equal(f.last().code, 'PRINT_JOBS_PENDING');
  assert.equal(f.last().removalReady, true);
  f.native.setup = async () => {};
  await f.desktop.command({ action: 'remove' }); await f.desktop.idle();
  assert.equal(f.last().removed, true); assert.equal(f.last().connected, false);
});

test('native startup preserves a bounded diagnostic code instead of misreporting missing setup', async () => {
  const f = await fixture({ native: { async start() { throw new PrinterError('INSTALLATION_DRIFT'); } } });
  assert.equal(f.last().queueReady, false);
  assert.equal(f.last().code, 'INSTALLATION_DRIFT');
});

test('failed revocation keeps removal paused and offers a safe retry without losing job state', async () => {
  const f = await fixture({ auth: { async disconnect() { throw new PrinterError('REVOCATION_PENDING'); } } });
  await f.unlock(); await f.desktop.admit(identity(), 'synthetic', pdf);
  await f.desktop.command({ action: 'prepareRemoval' }); await f.desktop.idle();
  assert.equal(f.last().removalReady, false); assert.equal(f.last().draining, true);
  await f.desktop.command({ action: 'remove' }); await f.desktop.idle();
  assert.equal(f.calls.includes('remove'), false);
  assert.equal(f.last().jobs[0].outcome, 'cancelled');
  f.auth.disconnect = async () => {};
  await f.desktop.command({ action: 'prepareRemoval' }); await f.desktop.idle();
  assert.equal(f.last().removalReady, true);
});

test('expired credentials reveal reconnection instead of leaving a falsely connected status', async () => {
  const f = await fixture({ transfer: { async send() { throw new PrinterError('LOGIN_REQUIRED'); } } }); await f.unlock();
  const job = await f.desktop.admit(identity(), 'synthetic', pdf);
  await f.desktop.command({ action: 'confirm', operationId: job.operationId }); await f.desktop.idle();
  assert.equal(f.last().jobs[0].outcome, 'uncertain'); assert.equal(f.last().connected, false);
  await f.desktop.command({ action: 'connect' }); await f.desktop.idle();
  assert.equal(f.last().connected, true);
  assert.equal(f.last().jobs[0].operationId, job.operationId);
});

test('explicit recovery export survives disconnect and drain without exposing document metadata or sending again', async () => {
  const f = await fixture({transfer: {async send() { throw new PrinterError('LOGIN_REQUIRED'); }}}); await f.unlock();
  const job = await f.desktop.admit(identity(), 'PRIVATE-INVOICE-TITLE', pdf);
  await f.desktop.command({action: 'exportRecovery', operationId: job.operationId});
  assert.equal(f.last().code, 'RECOVERY_NOT_AVAILABLE'); assert.equal(f.exports.length, 0);
  await f.desktop.command({action: 'confirm', operationId: job.operationId}); await f.desktop.idle();
  await f.desktop.command({action: 'prepareRemoval'}); await f.desktop.idle();
  const before = f.agent.snapshot();
  await f.desktop.command({action: 'exportRecovery', operationId: job.operationId});
  assert.equal(f.exports.length, 1); assert.equal(f.exports[0].operationId, job.operationId);
  const data = JSON.parse(f.exports[0].content);
  assert.equal(data.clientId, f.account.clientId); assert.equal(data.targetId, f.account.target.id);
  assert.equal(f.exports[0].content.includes('PRIVATE-INVOICE-TITLE'), false);
  assert.equal(f.exports[0].content.includes(f.account.target.name), false);
  assert.deepEqual(f.agent.snapshot(), before); assert.equal(f.last().connected, false);
  assert.deepEqual(f.opens, []); assert.equal(f.calls.includes('reconcile'), false);
  await f.desktop.command({action: 'session', locked: true});
  await f.desktop.command({action: 'exportRecovery', operationId: job.operationId});
  assert.equal(f.exports.length, 1); assert.equal(f.last().code, 'SESSION_LOCKED');
});

test('desktop receipt import verifies real signatures and exact binding while disconnected, without uploading', async () => {
  const {privateKey, publicKey} = generateKeyPairSync('ed25519');
  const verifier = new PinnedReceiptVerifier({test: publicKey.export({format: 'pem', type: 'spki'}).toString()}, {now: () => 1_000_000});
  const f = await fixture({verifier, transfer: {async send() { throw new PrinterError('LOGIN_REQUIRED'); }}}); await f.unlock();
  const job = await f.desktop.admit(identity(), 'synthetic', pdf);
  await f.desktop.command({action: 'confirm', operationId: job.operationId}); await f.desktop.idle();
  const row = f.agent.snapshot()[0];
  const claims = {iss: row.binding.issuer, aud: row.binding.audience, sub: row.binding.subject, client_id: row.binding.clientId,
    target_id: row.binding.target.id, operation_id: row.operationId, client_batch_id: row.clientBatchId,
    client_item_id: row.clientItemId, request_fingerprint: row.requestFingerprint, nonce: row.callbackNonce,
    protocol_version: 2, generation: 1, jti: randomUUID(), iat: 1000, nbf: 1000, exp: 1120, outcome: 'accepted'};
  const token = change => {
    const head = Buffer.from(JSON.stringify({alg: 'EdDSA', typ: 'fin3000-print-receipt+jwt', kid: 'test'})).toString('base64url');
    const payload = Buffer.from(JSON.stringify({...claims, ...change})).toString('base64url');
    return `${head}.${payload}.${sign(null, Buffer.from(`${head}.${payload}`), privateKey).toString('base64url')}`;
  };
  await f.desktop.command({action: 'importReceipt', operationId: job.operationId, receipt: token({target_id: randomUUID()})}); await f.desktop.idle();
  assert.equal(f.last().jobs[0].outcome, 'uncertain'); assert.equal(f.last().code, 'RECEIPT_INVALID');
  await f.desktop.command({action: 'importReceipt', operationId: job.operationId, receipt: token({})}); await f.desktop.idle();
  assert.equal(f.last().jobs[0].outcome, 'accepted'); assert.equal(f.last().connected, false); assert.equal(f.last().code, null);
  assert.equal(f.calls.includes('reconcile'), false); assert.deepEqual(f.opens, []);
  await f.desktop.command({action: 'importReceipt', operationId: job.operationId, receipt: token({})}); await f.desktop.idle();
  assert.equal(f.last().code, 'RECEIPT_NOT_EXPECTED'); assert.equal(f.last().jobs[0].outcome, 'accepted');
});

test('desktop shutdown joins an upload, retains recovery and never revokes the saved connection', async () => {
  const network = deferred(); let signal;
  const f = await fixture({ transfer: { send(_row, _bytes, current) { signal = current; return network.promise; } } });
  await f.unlock();
  const job = await f.desktop.admit(identity(), 'Synthetic', pdf);
  await f.desktop.command({ action: 'confirm', operationId: job.operationId });
  await new Promise(resolve => setImmediate(resolve));
  try {
    await f.desktop.stop();
    assert.equal(signal.aborted, true);
    assert.equal(f.last().busy, null);
    assert.equal(f.last().connected, false); assert.equal(f.last().queueReady, false);
    assert.equal(f.last().jobs[0].outcome, 'uncertain');
    assert.equal(f.last().jobs[0].operationId, job.operationId);
    assert.equal(f.calls.includes('revoke'), false);
    const before = f.agent.snapshot();
    network.resolve('accepted'); await f.desktop.idle();
    assert.deepEqual(f.agent.snapshot(), before);
  } finally { network.resolve('accepted'); await f.desktop.idle(); }
});

test('setup finishing during shutdown cannot restart ingress after the stop barrier', async () => {
  const setup = deferred(); let stopped = false;
  const f = await fixture({ native: { setup() { return setup.promise; } } });
  await f.unlock();
  await f.desktop.command({ action: 'configure' });
  await new Promise(resolve => setImmediate(resolve));
  const stop = f.desktop.stop().then(() => { stopped = true; });
  try {
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(stopped, false, 'shutdown must join the existing setup action');
    setup.resolve(); await stop;
    assert.equal(f.calls.filter(call => call === 'native_start').length, 1);
    assert.equal(f.last().queueReady, false); assert.equal(f.last().connected, false);
    assert.equal(f.last().busy, null);
    await assert.rejects(f.desktop.admit(identity(), 'Synthetic', pdf), { code: 'CONNECT_AND_REPRINT' });
  } finally { setup.resolve(); await stop; await f.desktop.idle(); }
});

test('ingress startup already entered by setup finishes before the final native stop', async () => {
  const startup = deferred();
  const f = await fixture(); await f.unlock();
  f.native.start = async () => {
    f.calls.push('native_start_enter'); await startup.promise; f.calls.push('native_start_finished');
  };
  await f.desktop.command({ action: 'configure' });
  await new Promise(resolve => setImmediate(resolve));
  assert.ok(f.calls.includes('native_start_enter'));
  const stop = f.desktop.stop();
  startup.resolve(); await stop;
  assert.ok(f.calls.lastIndexOf('native_stop') > f.calls.indexOf('native_start_finished'));
  assert.equal(f.last().queueReady, false); assert.equal(f.last().connected, false);
  assert.equal(f.last().busy, null);
});
