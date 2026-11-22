import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';

import { Coordinator } from '../../core/coordinator.ts';
import { manifestFingerprint, PrinterError } from '../../core/protocol.ts';

const pdf = Buffer.from('%PDF-1.7\nSynthetic, not a real invoice.\n%%EOF');
const identity = () => ({ generation: randomUUID(), nativeJobUuid: randomUUID() });
const binding = () => ({ issuer: 'https://api.fin3000.test', audience: 'fin3000-printer:qa', clientId: 'fin3000-system-print-qa', subject: `sp_${'a'.repeat(32)}`, target: { id: randomUUID(), name: 'Testunternehmen' } });
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };

async function waitFor(check) {
  for (let index = 0; index < 100; index++) {
    if (check()) return;
    await new Promise(resolve => setImmediate(resolve));
  }
  assert.fail('condition was not reached');
}

async function fixture(options = {}) {
  let state = options.state ?? null;
  const saves = [];
  const clock = { time: 1_000_000, now() { return this.time; } };
  const store = { async load() { return state; }, async save(value) { state = structuredClone(value); saves.push(state); } };
  const calls = [];
  const transfer = {
    async send(record, bytes, signal) { calls.push({ record, bytes: Buffer.from(bytes), signal }); return 'accepted'; },
    async reconcile(record) { calls.push({ reconcile: record }); return 'accepted'; },
    ...options.transfer,
  };
  const verifier = { verify(token) { if (!['accepted', 'never_accepted'].includes(token)) throw new PrinterError('RECEIPT_INVALID'); return token; } };
  const agent = new Coordinator({ store, transfer, verifier, clock, random: () => 0.5 });
  await agent.start();
  const account = options.binding ?? binding();
  if (options.connected !== false) await agent.connect(account);
  return { agent, store, clock, calls, saves, account, state: () => state };
}

test('no connection rejects before saving or sending', async () => {
  const f = await fixture({ connected: false });
  await assert.rejects(f.agent.admit(identity(), 'Rechnung', pdf), { code: 'CONNECT_AND_REPRINT' });
  assert.equal(f.calls.length, 0);
  assert.equal(f.saves.length, 0);
});

test('one OS print durably queues and automatically dispatches exactly once', async () => {
  const gate = deferred();
  const f = await fixture({ transfer: { async send(record, bytes) {
    assert.equal(f.saves[0].jobs[0].outcome, 'waiting', 'admission must be durable first');
    assert.equal(f.state().jobs[0].delivery, 'possibly_delivered');
    assert.deepEqual(bytes, pdf);
    f.calls.push(record.operationId);
    return gate.promise;
  } } });
  const job = await f.agent.admit(identity(), '../Änderung\u0000.pdf', pdf);
  await waitFor(() => f.calls.length === 1);
  assert.equal(f.agent.snapshot()[0].name, 'Änderung.pdf');
  gate.resolve('accepted');
  await waitFor(() => f.state().jobs[0].outcome === 'accepted');
  assert.equal(f.state().jobs[0].operationId, job.operationId);
  assert.equal(f.state().jobs[0].receipt, 'accepted');
  assert.equal(JSON.stringify(f.state()).includes('%PDF'), false);
});

test('queue dispatches serially and rejects a fourth open job', async () => {
  const gates = [deferred(), deferred(), deferred()];
  const f = await fixture({ transfer: { send(record) {
    const index = f.calls.length;
    f.calls.push(record.operationId);
    return gates[index].promise;
  } } });
  const jobs = [];
  for (let index = 0; index < 3; index++) jobs.push(await f.agent.admit(identity(), `Job ${index}`, pdf));
  await waitFor(() => f.calls.length === 1);
  assert.deepEqual(f.agent.snapshot().map(row => row.outcome), ['transferring', 'waiting', 'waiting']);
  await assert.rejects(f.agent.admit(identity(), 'Vierter Job', pdf), { code: 'QUEUE_FULL' });
  gates[0].resolve('accepted'); await waitFor(() => f.calls.length === 2);
  gates[1].resolve('accepted'); await waitFor(() => f.calls.length === 3);
  gates[2].resolve('accepted'); await waitFor(() => f.agent.snapshot().every(row => row.outcome === 'accepted'));
  assert.deepEqual(f.calls, jobs.map(job => job.operationId));
});

test('native replay reuses the operation and changed bytes fail closed', async () => {
  const gate = deferred();
  const f = await fixture({ transfer: { send() { return gate.promise; } } });
  const id = identity();
  const first = await f.agent.admit(id, 'Rechnung', pdf);
  const replay = await f.agent.admit(id, 'Rechnung', pdf);
  assert.equal(replay.operationId, first.operationId);
  assert.equal(replay.replay, true);
  await assert.rejects(f.agent.admit(id, 'Rechnung', Buffer.concat([pdf, Buffer.from('changed')])), { code: 'NATIVE_IDENTITY_CONFLICT' });
  gate.resolve('accepted');
});

test('cancel applies only before dispatch and never implies a negative result in flight', async () => {
  const gate = deferred();
  const f = await fixture({ transfer: { send() { return gate.promise; } } });
  const active = await f.agent.admit(identity(), 'One', pdf);
  const queued = await f.agent.admit(identity(), 'Two', pdf);
  await waitFor(() => f.agent.snapshot()[0].outcome === 'transferring');
  await f.agent.cancel(active.operationId);
  assert.equal(f.agent.snapshot()[0].outcome, 'transferring');
  await f.agent.cancel(queued.operationId);
  assert.equal(f.agent.snapshot()[1].outcome, 'cancelled');
  gate.reject(new Error('network lost'));
  await waitFor(() => f.agent.snapshot()[0].outcome === 'uncertain');
});

test('uncertain delivery cancels queued PDFs and recovery never uploads again', async () => {
  let sends = 0, reconciles = 0;
  const f = await fixture({ transfer: {
    async send() { sends++; throw new Error('connection lost'); },
    async reconcile() { reconciles++; return 'never_accepted'; },
  } });
  const first = await f.agent.admit(identity(), 'One', pdf);
  await f.agent.admit(identity(), 'Two', pdf);
  await waitFor(() => f.agent.snapshot()[0].outcome === 'uncertain');
  assert.deepEqual(f.agent.snapshot().map(row => row.outcome), ['uncertain', 'cancelled']);
  await assert.rejects(f.agent.admit(identity(), 'Three', pdf), { code: 'RECONCILE_REQUIRED' });
  await f.agent.reconcile(first.operationId);
  assert.equal(f.agent.snapshot()[0].outcome, 'never_accepted');
  assert.equal(sends, 1);
  assert.equal(reconciles, 1);
});

test('restart cancels undispatched bytes and turns an in-flight record into recovery', async () => {
  const account = binding();
  const waiting = record(account, { outcome: 'waiting', delivery: 'not_dispatched' });
  const active = record(account, { outcome: 'transferring', delivery: 'possibly_delivered' });
  const f = await fixture({ state: { version: 1, jobs: [waiting, active] }, binding: account });
  assert.deepEqual(f.agent.snapshot().map(row => row.outcome), ['cancelled', 'uncertain']);
  assert.equal(f.agent.snapshot()[0].code, 'REPRINT_AFTER_RESTART');
  assert.equal(f.calls.length, 0);
});

test('locking stops the queue and leaves an active transfer unresolved', async () => {
  const gate = deferred();
  const f = await fixture({ transfer: { send(_row, _bytes, signal) {
    signal.addEventListener('abort', () => gate.reject(new Error('locked')), { once: true });
    return gate.promise;
  } } });
  await f.agent.admit(identity(), 'One', pdf);
  await f.agent.admit(identity(), 'Two', pdf);
  await f.agent.sessionLocked();
  await waitFor(() => f.agent.snapshot()[0].outcome === 'uncertain');
  assert.equal(f.agent.snapshot()[1].outcome, 'cancelled');
  assert.equal(f.agent.snapshot()[1].code, 'SESSION_LOCKED');
});

test('store failure rejects handoff before any network request', async () => {
  const f = await fixture();
  f.store.save = async () => { throw new Error('disk full'); };
  await assert.rejects(f.agent.admit(identity(), 'One', pdf), { code: 'STATE_STORE_UNAVAILABLE' });
  assert.equal(f.calls.length, 0);
});

test('terminal history is bounded while unresolved recovery is never pruned', async () => {
  const account = binding();
  const jobs = Array.from({ length: 102 }, (_, index) => record(account, {
    outcome: 'accepted', delivery: 'settled', receivedAt: 900_000 + index, receipt: 'accepted',
  }));
  jobs.push(record(account, { outcome: 'uncertain', delivery: 'possibly_delivered', receivedAt: 1 }));
  const f = await fixture({ state: { version: 1, jobs }, binding: account });
  assert.equal(f.agent.snapshot().filter(row => row.outcome === 'accepted').length, 100);
  assert.equal(f.agent.snapshot().filter(row => row.outcome === 'uncertain').length, 1);
});

test('drain aborts an in-flight upload and waits for durable uncertainty', async () => {
  const gate = deferred(); let signal;
  const f = await fixture({ transfer: { send(_row, _bytes, current) { signal = current; return gate.promise; } } });
  await f.agent.admit(identity(), 'One', pdf);
  await waitFor(() => signal);
  await f.agent.drain();
  assert.equal(signal.aborted, true);
  assert.equal(f.agent.snapshot()[0].outcome, 'uncertain');
  gate.resolve('accepted');
});

test('manifest digest is deterministic and Python-compatible', () => {
  assert.equal(manifestFingerprint('00000000-0000-0000-0000-000000000001', 'Änderung.pdf', 1024),
    'da5728cfacd2bd1ace357219a537b92139ac6f977522dc647b9695d5a3064a24');
});

function record(account, overrides = {}) {
  const clientItemId = randomUUID();
  const name = 'Synthetic.pdf';
  return {
    operationId: randomUUID(), clientBatchId: randomUUID(), clientItemId,
    identity: identity(), binding: structuredClone(account), name, size: pdf.length,
    requestFingerprint: manifestFingerprint(clientItemId, name, pdf.length),
    pdfSha256: 'a'.repeat(64), callbackNonce: 'a'.repeat(43),
    outcome: 'waiting', delivery: 'not_dispatched', receivedAt: 1_000_000,
    extended: false, ...overrides,
  };
}
