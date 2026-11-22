import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';

import { DesktopController } from '../../core/desktop.ts';
import { Coordinator } from '../../core/coordinator.ts';
import { PrinterError } from '../../core/protocol.ts';

const identity = () => ({ generation: randomUUID(), nativeJobUuid: randomUUID() });
const pdf = Buffer.from('%PDF-synthetic');
const binding = () => ({ issuer: 'https://api.fin3000.test', audience: 'fin3000-printer:qa', clientId: 'fin3000-system-print-qa',
  subject: `sp_${'c'.repeat(32)}`, accountName: 'Synthetic account', target: { id: randomUUID(), name: 'Synthetic company' } });
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };

async function waitFor(check) {
  for (let index = 0; index < 100; index++) {
    if (check()) return;
    await new Promise(resolve => setImmediate(resolve));
  }
  assert.fail('condition was not reached');
}

async function fixture(overrides = {}) {
  const account = binding(), snapshots = [], calls = [], opens = [], exports = [];
  const clock = { now: () => 1_000_000 };
  const transfer = { async send() { calls.push('send'); return 'accepted'; }, async reconcile() { calls.push('reconcile'); return 'accepted'; }, ...overrides.transfer };
  const agent = new Coordinator({ store: { async load() { return null; }, async save() {} }, transfer,
    verifier: { verify(token) { if (!['accepted', 'never_accepted'].includes(token)) throw new PrinterError('RECEIPT_INVALID'); return token; } }, clock });
  const auth = { async restore() { calls.push('restore'); return account; }, async authorize() { calls.push('authorize'); return account; },
    async disconnect() { calls.push('revoke'); }, lock() { calls.push('lock'); }, ...overrides.auth };
  const native = { async start() { calls.push('native_start'); }, async stop() { calls.push('native_stop'); }, async setup(action) { calls.push(action); }, ...overrides.native };
  const desktop = new DesktopController({ agent, auth, native, now: clock.now, emit: value => snapshots.push(value), open: async where => opens.push(where),
    exportRecovery: (operationId, content) => exports.push({ operationId, content }) });
  await desktop.start();
  return { desktop, agent, snapshots, calls, opens, exports, account, auth, native, last: () => snapshots.at(-1),
    async unlock() { await desktop.command({ action: 'session', locked: false }); await desktop.idle(); } };
}

test('no desktop-unlock evidence means no login or admission', async () => {
  const f = await fixture();
  await f.desktop.command({ action: 'connect' });
  assert.equal(f.last().code, 'SESSION_LOCKED');
  assert.equal(f.calls.includes('authorize'), false);
  await assert.rejects(f.desktop.admit(identity(), 'synthetic', pdf), { code: 'CONNECT_AND_REPRINT' });
});

test('one print automatically transfers after durable desktop admission', async () => {
  const f = await fixture(); await f.unlock();
  const job = await f.desktop.admit(identity(), 'synthetic', pdf);
  await waitFor(() => f.agent.snapshot()[0]?.outcome === 'accepted');
  await f.desktop.tick();
  assert.equal(f.last().connected, true);
  assert.equal(f.last().accountName, 'Synthetic account');
  assert.equal(f.last().target, 'Synthetic company');
  assert.equal(f.last().jobs[0].operationId, job.operationId);
  assert.equal(f.last().jobs[0].outcome, 'accepted');
  assert.equal(f.calls.filter(call => call === 'send').length, 1);
  const text = JSON.stringify(f.last());
  for (const secret of ['receipt', 'requestFingerprint', 'pdfSha256', 'callbackNonce', f.account.subject, '%PDF']) assert.equal(text.includes(secret), false);
});

test('unassigned account remains connected and sends without a second action', async () => {
  const f = await fixture(); f.account.target.id = null;
  await f.unlock();
  await f.desktop.admit(identity(), 'synthetic', pdf);
  await waitFor(() => f.agent.snapshot()[0]?.outcome === 'accepted');
  await f.desktop.tick();
  assert.equal(f.last().target, null);
  assert.equal(f.last().jobs[0].target, null);
  assert.equal(f.calls.filter(call => call === 'send').length, 1);
});

test('installation failure stays setup-required and never opens login', async () => {
  const f = await fixture({ native: { async start() { throw new Error('missing package'); } } });
  await f.unlock();
  assert.equal(f.last().queueReady, false);
  assert.equal(f.last().code, 'SETUP_REQUIRED');
  await f.desktop.command({ action: 'connect' });
  assert.equal(f.calls.includes('authorize'), false);
});

test('setup remains an explicit action and requires a fresh account check', async () => {
  const f = await fixture(); await f.unlock();
  await f.desktop.command({ action: 'configure' }); await f.desktop.idle();
  assert.equal(f.calls.includes('configure'), true);
  assert.equal(f.last().queueReady, true);
  assert.equal(f.last().connected, false);
  await assert.rejects(f.desktop.admit(identity(), 'synthetic', pdf), { code: 'CONNECT_AND_REPRINT' });
});

test('login can be cancelled while pending and a late result never connects', async () => {
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

test('locking aborts an active transfer and exposes uncertainty without cancel UI semantics', async () => {
  const pending = deferred();
  const f = await fixture({ transfer: { send(_row, _bytes, signal) {
    signal.addEventListener('abort', () => pending.reject(new Error('locked')), { once: true });
    return pending.promise;
  } } });
  await f.unlock();
  await f.desktop.admit(identity(), 'synthetic', pdf);
  await waitFor(() => f.agent.snapshot()[0]?.outcome === 'transferring');
  await f.desktop.command({ action: 'session', locked: true });
  await waitFor(() => f.agent.snapshot()[0]?.outcome === 'uncertain');
  await f.desktop.tick();
  assert.equal(f.last().jobs[0].outcome, 'uncertain');
  assert.equal(f.last().connected, false);
});

test('expired credentials expose reconnect while preserving the operation', async () => {
  const f = await fixture({ transfer: { async send() { throw new PrinterError('LOGIN_REQUIRED'); } } });
  await f.unlock();
  const job = await f.desktop.admit(identity(), 'synthetic', pdf);
  await waitFor(() => f.agent.snapshot()[0]?.outcome === 'uncertain');
  await f.desktop.tick();
  assert.equal(f.last().connected, false);
  await f.desktop.command({ action: 'connect' }); await f.desktop.idle();
  assert.equal(f.last().connected, true);
  assert.equal(f.last().jobs[0].operationId, job.operationId);
});

test('removal drains transport before revocation and package removal', async () => {
  const f = await fixture(); await f.unlock();
  await f.desktop.command({ action: 'prepareRemoval' }); await f.desktop.idle();
  assert.equal(f.last().draining, true);
  assert.equal(f.last().queueReady, false);
  await f.desktop.command({ action: 'remove' }); await f.desktop.idle();
  assert.equal(f.calls.includes('remove'), true);
  assert.ok(f.calls.indexOf('revoke') < f.calls.indexOf('remove'));
  assert.equal(f.last().removed, true);
});

test('desktop shutdown joins an upload and retains recovery state', async () => {
  const pending = deferred(); let signal;
  const f = await fixture({ transfer: { send(_row, _bytes, current) { signal = current; return pending.promise; } } });
  await f.unlock();
  const job = await f.desktop.admit(identity(), 'Synthetic', pdf);
  await waitFor(() => signal);
  await f.desktop.stop();
  assert.equal(signal.aborted, true);
  assert.equal(f.last().jobs[0].outcome, 'uncertain');
  assert.equal(f.last().jobs[0].operationId, job.operationId);
  assert.equal(f.calls.includes('revoke'), false);
  pending.resolve('accepted');
});
