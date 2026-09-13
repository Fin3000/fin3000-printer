import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { Coordinator } from '../../core/coordinator.ts';
import { manifestFingerprint, PrinterError } from '../../core/protocol.ts';
import { HttpFailure } from '../../core/http.ts';

const pdf = Buffer.from('%PDF-1.7\nSynthetic, not a real invoice.\n%%EOF');
const identity = () => ({ generation: randomUUID(), nativeJobUuid: randomUUID() });
const binding = () => ({ issuer: 'https://api.fin3000.test', audience: 'fin3000-printer:qa', clientId: 'fin3000-system-print-qa', subject: `sp_${'a'.repeat(32)}`, target: { id: randomUUID(), name: 'Testunternehmen' } });
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };

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
  const verifier = { verify(token) { if (token !== 'accepted' && token !== 'never_accepted') throw new PrinterError('RECEIPT_INVALID'); return token; } };
  const agent = new Coordinator({ store, transfer, verifier, clock, random: () => 0.5 });
  await agent.start();
  const account = options.binding ?? binding();
  if (options.connected !== false) await agent.connect(account);
  return { agent, store, transfer, verifier, clock, calls, saves, account, state: () => state };
}

test('no connection: reject before saving or sending, never hold for a later login', async () => {
  const f = await fixture({ connected: false });
  await assert.rejects(f.agent.admit(identity(), 'Rechnung', pdf), { code: 'CONNECT_AND_REPRINT' });
  assert.equal(f.calls.length, 0); assert.equal(f.saves.length, 0);
});

test('one confirmation and two waiting jobs; fourth is visibly rejected', async () => {
  const f = await fixture();
  for (let index = 0; index < 3; index++) await f.agent.admit(identity(), 'Rechnung', pdf);
  assert.deepEqual(f.agent.snapshot().map(row => row.outcome), ['confirming', 'waiting', 'waiting']);
  await assert.rejects(f.agent.admit(identity(), 'Vierter Job', pdf), { code: 'QUEUE_FULL' });
  assert.equal(f.calls.length, 0);
});

test('operation identity is durable before handoff and dispatch before network', async () => {
  const f = await fixture();
  const job = await f.agent.admit(identity(), '../Änderung\u0000.pdf', pdf);
  assert.equal(f.state().jobs[0].operationId, job.operationId);
  assert.equal(f.state().jobs[0].name, 'Änderung.pdf');
  assert.equal(f.state().jobs[0].delivery, 'not_dispatched');
  f.transfer.send = async (record, bytes) => {
    assert.equal(f.state().jobs[0].delivery, 'possibly_delivered');
    assert.equal(f.state().jobs[0].operationId, record.operationId);
    assert.deepEqual(bytes, pdf);
    return 'accepted';
  };
  await f.agent.confirm(job.operationId);
  assert.equal(f.state().jobs[0].delivery, 'settled');
  assert.equal(f.state().jobs[0].receipt, 'accepted');
  assert.equal(JSON.stringify(f.state()).includes('%PDF'), false);
});

test('re-delivered native identity reuses operation; changed contents fail closed', async () => {
  const f = await fixture(); const id = identity();
  const first = await f.agent.admit(id, 'Rechnung', pdf);
  const second = await f.agent.admit(id, 'Rechnung', pdf);
  assert.equal(second.operationId, first.operationId); assert.equal(second.replay, true);
  await assert.rejects(f.agent.admit(id, 'Rechnung', Buffer.concat([pdf, Buffer.from('changed')])), { code: 'NATIVE_IDENTITY_CONFLICT' });
  assert.equal(f.agent.snapshot().length, 1);
});

test('cancel before dispatch is terminal locally and promotes the next confirmation', async () => {
  const f = await fixture();
  const first = await f.agent.admit(identity(), 'One', pdf);
  await f.agent.admit(identity(), 'Two', pdf);
  await f.agent.cancel(first.operationId);
  assert.deepEqual(f.agent.snapshot().map(row => row.outcome), ['cancelled', 'confirming']);
  assert.equal(f.calls.length, 0);
});

test('confirmation expires at 120 seconds and only one explicit extension is possible', async () => {
  const f = await fixture(); const job = await f.agent.admit(identity(), 'Rechnung', pdf);
  f.clock.time += 90_000;
  await f.agent.extendConfirmation(job.operationId);
  await assert.rejects(f.agent.extendConfirmation(job.operationId), { code: 'CONFIRMATION_EXTENSION_UNAVAILABLE' });
  f.clock.time += 149_999; await f.agent.tick();
  assert.equal(f.agent.snapshot()[0].outcome, 'confirming');
  f.clock.time += 1; await f.agent.tick();
  assert.equal(f.agent.snapshot()[0].outcome, 'cancelled');
  assert.equal(f.calls.length, 0);
});

test('uncertain receipt blocks new work and cancels waiting PDF jobs', async () => {
  const f = await fixture({ transfer: { async send() { throw new PrinterError('HTTP_404'); } } });
  const first = await f.agent.admit(identity(), 'One', pdf);
  await f.agent.admit(identity(), 'Two', pdf);
  await f.agent.confirm(first.operationId);
  assert.deepEqual(f.agent.snapshot().map(row => row.outcome), ['uncertain', 'cancelled']);
  assert.equal(f.state().jobs[0].delivery, 'possibly_delivered');
  await assert.rejects(f.agent.admit(identity(), 'Three', pdf), { code: 'RECONCILE_REQUIRED' });
});

test('valid receipt recovery uses same operation without another upload', async () => {
  let sends = 0, reconciles = 0;
  const f = await fixture({ transfer: {
    async send() { sends++; return 'forged'; },
    async reconcile(record) { reconciles++; assert.ok(record.operationId); return 'never_accepted'; },
  } });
  const job = await f.agent.admit(identity(), 'One', pdf);
  await f.agent.confirm(job.operationId);
  assert.equal(f.state().jobs[0].outcome, 'uncertain');
  await f.agent.reconcile(job.operationId);
  assert.equal(f.state().jobs[0].outcome, 'never_accepted');
  assert.equal(sends, 1); assert.equal(reconciles, 1);
});

test('restart never auto-uploads and preserves possibly delivered records indefinitely', async () => {
  const gate = deferred();
  const f = await fixture({ transfer: { send() { return gate.promise; } } });
  const first = await f.agent.admit(identity(), 'One', pdf);
  const running = f.agent.confirm(first.operationId);
  await new Promise(resolve => setImmediate(resolve));
  const restored = await fixture({ state: f.state(), binding: f.account });
  assert.equal(restored.agent.snapshot()[0].outcome, 'uncertain');
  assert.equal(restored.calls.length, 0);
  await assert.rejects(restored.agent.connect({ ...f.account, target: { ...f.account.target, id: randomUUID() } }), { code: 'ORIGINAL_ACCOUNT_REQUIRED' });
  gate.reject(new Error('crash')); await running;
});

test('store failure forbids handoff and any network request', async () => {
  const f = await fixture(); f.store.save = async () => { throw new Error('disk full'); };
  await assert.rejects(f.agent.admit(identity(), 'One', pdf), { code: 'STATE_STORE_UNAVAILABLE' });
  assert.equal(f.calls.length, 0);
  await assert.rejects(f.agent.admit(identity(), 'Two', pdf), { code: 'STATE_STORE_UNAVAILABLE' });
});

test('concurrent confirmations launch exactly one transfer; cancel after send is not a negative proof', async () => {
  const gate = deferred(); let sends = 0;
  const f = await fixture({ transfer: { async send(_record, _bytes, signal) {
    sends++; signal.addEventListener('abort', () => gate.reject(new Error('cancelled')), { once: true }); return gate.promise;
  } } });
  const job = await f.agent.admit(identity(), 'One', pdf);
  const running = f.agent.confirm(job.operationId);
  await new Promise(resolve => setImmediate(resolve));
  await assert.rejects(f.agent.confirm(job.operationId), { code: 'CONFIRMATION_NOT_AVAILABLE' });
  await f.agent.cancel(job.operationId); await running;
  assert.equal(sends, 1); assert.equal(f.state().jobs[0].outcome, 'uncertain');
});

test('session lock cancels unconfirmed jobs and disconnects admission', async () => {
  const f = await fixture(); await f.agent.admit(identity(), 'One', pdf);
  await f.agent.sessionLocked();
  assert.equal(f.state().jobs[0].outcome, 'cancelled');
  await assert.rejects(f.agent.admit(identity(), 'Two', pdf), { code: 'CONNECT_AND_REPRINT' });
});

test('manifest digest is deterministic and includes Unicode in Python-compatible encoding', () => {
  assert.equal(manifestFingerprint('00000000-0000-0000-0000-000000000001', 'Änderung.pdf', 1024),
    'da5728cfacd2bd1ace357219a537b92139ac6f977522dc647b9695d5a3064a24');
});

test('background recovery reserves its attempt durably and never repeats the PDF upload', async () => {
  let sends = 0, attempts = 0;
  const f = await fixture({ transfer: {
    async send() { sends++; throw new HttpFailure('HTTP_FAILURE', 503, 3600); },
    async reconcile(record) {
      attempts++;
      assert.equal(f.state().jobs[0].recovery.attempt, attempts);
      assert.equal(record.operationId, f.state().jobs[0].operationId);
      throw new HttpFailure('HTTP_FAILURE', 503);
    },
  } });
  const job = await f.agent.admit(identity(), 'Synthetic', pdf); await f.agent.confirm(job.operationId);
  const first = f.state().jobs[0].recovery;
  assert.equal(first.notBefore, f.clock.time + 3600000);
  await assert.rejects(f.agent.reconcile(job.operationId), { code: 'RETRY_LATER' });
  f.clock.time += 3599999; await f.agent.tick(); await new Promise(resolve => setImmediate(resolve));
  assert.equal(attempts, 0);
  f.clock.time++; await f.agent.tick(); await new Promise(resolve => setImmediate(resolve));
  assert.equal(attempts, 1); assert.equal(sends, 1);
  assert.equal(f.state().jobs[0].recovery.nextAttemptAt, f.clock.time + 120000);
  await f.agent.tick(); await new Promise(resolve => setImmediate(resolve));
  assert.equal(attempts, 1);
  const restored = await fixture({ state: f.state(), binding: f.account });
  assert.deepEqual(restored.state().jobs[0].recovery, f.state().jobs[0].recovery);
});

test('lost authentication pauses background recovery until the original binding is revalidated', async () => {
  let attempts = 0;
  const f = await fixture({ transfer: {
    async send() { throw new PrinterError('LOGIN_REQUIRED'); },
    async reconcile() { attempts++; return 'accepted'; },
  } });
  const job = await f.agent.admit(identity(), 'Synthetic', pdf); await f.agent.confirm(job.operationId);
  f.clock.time += 86400000; await f.agent.tick(); await new Promise(resolve => setImmediate(resolve));
  assert.equal(attempts, 0);
  await f.agent.connect(f.account); await f.agent.tick(); await new Promise(resolve => setImmediate(resolve));
  assert.equal(attempts, 1); assert.equal(f.state().jobs[0].outcome, 'accepted');
  assert.equal(f.state().jobs[0].recovery, undefined);
});

test('drain aborts an in-flight upload and waits for durable uncertainty before returning', async () => {
  const network = deferred(), persisted = deferred(); let signal, drained = false;
  const f = await fixture({ transfer: { send(_row, _bytes, current) { signal = current; return network.promise; } } });
  const job = await f.agent.admit(identity(), 'Synthetic', pdf);
  const running = f.agent.confirm(job.operationId);
  await new Promise(resolve => setImmediate(resolve));
  const save = f.store.save;
  f.store.save = async value => {
    if (value.jobs[0].outcome === 'uncertain') await persisted.promise;
    await save(value);
  };
  const drain = f.agent.drain().then(() => { drained = true; });
  try {
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(signal.aborted, true);
    assert.equal(drained, false, 'state lock must remain held until the final save');
    persisted.resolve(); await drain; await running;
    assert.equal(f.state().jobs[0].operationId, job.operationId);
    assert.equal(f.state().jobs[0].outcome, 'uncertain');
    assert.equal(f.state().jobs[0].delivery, 'possibly_delivered');
    const saves = f.saves.length;
    network.resolve('accepted'); await new Promise(resolve => setImmediate(resolve));
    assert.equal(f.saves.length, saves, 'late network result cannot write after drain');
    await assert.rejects(f.agent.connect(f.account), { code: 'DRAINING' });
  } finally { persisted.resolve(); network.resolve('accepted'); await running; await drain; }
});

test('drain also joins background recovery that has no desktop command waiting for it', async () => {
  const network = deferred(); let signal, reconciles = 0;
  const f = await fixture({ transfer: {
    async send() { throw new PrinterError('REQUEST_ABORTED'); },
    reconcile(_row, current) { signal = current; reconciles++; return network.promise; },
  } });
  const job = await f.agent.admit(identity(), 'Synthetic', pdf);
  await f.agent.confirm(job.operationId);
  f.clock.time = f.state().jobs[0].recovery.nextAttemptAt;
  await f.agent.tick(); await new Promise(resolve => setImmediate(resolve));
  try {
    await f.agent.drain();
    assert.equal(signal.aborted, true); assert.equal(reconciles, 1);
    assert.equal(f.state().jobs[0].outcome, 'uncertain');
    const saves = f.saves.length;
    network.resolve('accepted'); await new Promise(resolve => setImmediate(resolve));
    assert.equal(f.saves.length, saves);
    f.clock.time += 86400000; await f.agent.tick();
    assert.equal(reconciles, 1);
  } finally { network.resolve('accepted'); await new Promise(resolve => setImmediate(resolve)); }
});

test('drain wins over a queued confirmation without dispatching or losing the job identity', async () => {
  const f = await fixture();
  const job = await f.agent.admit(identity(), 'Synthetic', pdf);
  const rejected = assert.rejects(f.agent.confirm(job.operationId), { code: 'CONFIRMATION_NOT_AVAILABLE' });
  await f.agent.drain(); await rejected;
  assert.equal(f.calls.length, 0);
  assert.equal(f.state().jobs[0].operationId, job.operationId);
  assert.equal(f.state().jobs[0].delivery, 'not_dispatched');
  assert.equal(f.state().jobs[0].outcome, 'cancelled');
});

test('drain reports a storage failure, aborts transport and retains the last durable recovery identity', async () => {
  const network = deferred(); let signal;
  const f = await fixture({ transfer: { send(_row, _bytes, current) { signal = current; return network.promise; } } });
  const job = await f.agent.admit(identity(), 'Synthetic', pdf);
  const running = f.agent.confirm(job.operationId);
  // Attach the rejection handler before deliberately failing the durable writer.
  const completed = running.then(() => null, error => error);
  await new Promise(resolve => setImmediate(resolve));
  f.store.save = async () => { throw new Error('synthetic disk full'); };
  try {
    await assert.rejects(f.agent.drain(), { code: 'STATE_STORE_UNAVAILABLE' });
    assert.equal(signal.aborted, true);
    assert.equal((await completed).code, 'STATE_STORE_UNAVAILABLE');
    assert.equal(f.state().jobs[0].operationId, job.operationId);
    assert.equal(f.state().jobs[0].delivery, 'possibly_delivered');
  } finally { network.resolve('accepted'); await completed; }
});

test('repeated drain preserves an already verified receipt instead of making acceptance uncertain', async () => {
  const f = await fixture();
  const job = await f.agent.admit(identity(), 'Synthetic', pdf);
  await f.agent.confirm(job.operationId);
  const before = f.state();
  await Promise.all([f.agent.drain(), f.agent.drain()]);
  assert.deepEqual(f.state(), before);
  assert.equal(f.state().jobs[0].receipt, 'accepted');
});
