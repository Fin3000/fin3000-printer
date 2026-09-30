import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import test from 'node:test';
import { HttpFailure } from '../../core/http.ts';
import { manifestFingerprint } from '../../core/protocol.ts';
import { NativeTransfer, operationManifest } from '../../core/transfer.ts';

const signal = () => AbortSignal.timeout(5000);
function fixture() {
  const pdf = Buffer.from('%PDF-synthetic'), itemId = randomUUID();
  const binding = { issuer: 'https://api.fin3000.test', audience: 'fin3000-printer:qa', clientId: 'fin3000-system-print-qa', subject: `sp_${'a'.repeat(32)}`, accountName: 'Synthetic account', target: { id: randomUUID(), name: 'Test' } };
  const record = { operationId: randomUUID(), clientBatchId: randomUUID(), clientItemId: randomUUID(), binding,
    identity: { generation: randomUUID(), nativeJobUuid: randomUUID() }, name: 'Änderung.pdf', size: pdf.length,
    pdfSha256: createHash('sha256').update(pdf).digest('hex'), callbackNonce: 'nonce', delivery: 'possibly_delivered', outcome: 'transferring', receivedAt: Date.now(), extended: false };
  record.requestFingerprint = manifestFingerprint(record.clientItemId, record.name, record.size);
  const operation = { protocolVersion: 2, operationId: record.operationId, clientBatchId: record.clientBatchId, clientItemId: record.clientItemId,
    requestFingerprint: record.requestFingerprint, target: binding.target, outcome: 'pending',
    batch: { source: 'system_print', businessUnit: binding.target.id, clientBatchId: record.clientBatchId,
      items: [{ id: itemId, clientItemId: record.clientItemId, expectedSize: record.size, name: record.name, contentType: 'application/pdf' }] } };
  const intent = { method: 'POST', url: 'https://quarantine.fin3000.test/bucket/', fields: { key: `incoming/system-print/${randomUUID()}/${itemId}/payload`,
    'Content-Type': 'application/pdf', 'x-amz-meta-intake-item': itemId }, minimumBytes: record.size, maximumBytes: record.size, expiresAt: new Date(Date.now() + 600000).toISOString() };
  const calls = [];
  const http = { async api(method, path, body, token) {
    calls.push({ method, path, body, token });
    if (path.endsWith('/receipt/')) return { receipt: 'signed-proof-for-coordinator-to-check' };
    if (path.endsWith('/intent/')) return intent;
    if (path.endsWith('/complete/')) return { ...operation, outcome: 'accepted' };
    return structuredClone(operation);
  }, async upload(value, bytes) { calls.push({ upload: value }); assert.deepEqual(bytes, pdf); }, async token() { throw new Error('UNEXPECTED'); } };
  const tokens = { async access() { return { accessToken: 'synthetic-access-token', binding }; } };
  return { transfer: new NativeTransfer(http, tokens), http, tokens, calls, record, pdf, operation, intent, itemId };
}

test('manifest, intent, PDF, completion and bound receipt use one identity in that order', async () => {
  const f = fixture(); assert.equal(await f.transfer.send(f.record, f.pdf, signal()), 'signed-proof-for-coordinator-to-check');
  assert.equal(f.calls.length, 5); assert.deepEqual(f.calls[0].body, operationManifest(f.record));
  assert.match(f.calls[1].path, new RegExp(`/items/${f.itemId}/intent/$`)); assert.ok(f.calls[2].upload);
  assert.deepEqual(f.calls[3].body, { clientItemId: f.record.clientItemId });
  assert.deepEqual(f.calls[4].body, { callbackNonce: f.record.callbackNonce });
});

test('changed PDF cannot reach manifest admission', async () => {
  const f = fixture(); await assert.rejects(f.transfer.send(f.record, Buffer.from('%PDF-different'), signal()), { code: 'PDF_IDENTITY_CHANGED' }); assert.equal(f.calls.length, 0);
});

test('unassigned transfer preserves explicit null through manifest and batch, never a wildcard', async () => {
  const f = fixture(); f.record.binding.target.id = null; f.operation.batch.businessUnit = null;
  await f.transfer.send(f.record, f.pdf, signal());
  assert.ok(Object.hasOwn(f.calls[0].body, 'targetId')); assert.equal(f.calls[0].body.targetId, null);
  for (const target of [undefined, '', 'null', randomUUID()]) {
    const bad = fixture(); bad.record.binding.target.id = null; bad.operation.batch.businessUnit = target;
    await assert.rejects(bad.transfer.send(bad.record, bad.pdf, signal()), { code: 'OPERATION_RESPONSE_INVALID' });
    assert.equal(bad.calls.length, 1);
  }
});

test('changed account or target prevents every API call', async () => {
  const f = fixture(); f.tokens.access = async () => ({ accessToken: 'synthetic', binding: { ...f.record.binding, target: { id: randomUUID(), name: 'Other' } } });
  await assert.rejects(f.transfer.send(f.record, f.pdf, signal()), { code: 'PRINCIPAL_CHANGED' }); assert.equal(f.calls.length, 0);
});

test('wrong operation, batch, item, digest or BU response never triggers PDF upload', async () => {
  for (const key of ['operationId', 'clientBatchId', 'clientItemId', 'requestFingerprint', 'target']) {
    const f = fixture(); f.operation[key] = key === 'target' ? { id: randomUUID() } : randomUUID();
    await assert.rejects(f.transfer.send(f.record, f.pdf, signal()), { code: 'OPERATION_RESPONSE_INVALID' }); assert.equal(f.calls.length, 1);
  }
});

test('wrong intent item metadata, key or byte size cannot leave the device', async () => {
  for (const mutate of [f => f.intent.fields['x-amz-meta-intake-item'] = randomUUID(), f => f.intent.fields.key = 'other', f => f.intent.maximumBytes++]) {
    const f = fixture(); mutate(f); await assert.rejects(f.transfer.send(f.record, f.pdf, signal()), { code: 'UPLOAD_INTENT_INVALID' }); assert.equal(f.calls.length, 2);
  }
});

test('already accepted manifest replay requests proof, without creating another upload', async () => {
  const f = fixture(); f.operation.outcome = 'accepted';
  await f.transfer.send(f.record, f.pdf, signal()); assert.equal(f.calls.length, 2); assert.match(f.calls[1].path, /\/receipt\/$/);
});

test('recovery uses lookup, atomic settle and receipt only; no file or manifest upload', async () => {
  const f = fixture(), api = f.http.api;
  f.http.api = async (...args) => { const result = await api(...args); return args[1].endsWith('/settle/') ? { ...result, outcome: 'accepted' } : result; };
  await f.transfer.reconcile(f.record, signal()); assert.equal(f.calls.length, 3);
  assert.equal(f.calls[0].method, 'GET'); assert.deepEqual(f.calls[1].body, {}); assert.match(f.calls[2].path, /\/receipt\/$/);
  assert.ok(f.calls.every(call => !call.upload && !call.path.endsWith('/manifest/')));
});

test('404 requires permanent negative claim plus proof, never a local never-accepted result', async () => {
  const f = fixture(), api = f.http.api;
  f.http.api = async (...args) => {
    if (args[0] === 'GET') { f.calls.push({ method: args[0], path: args[1] }); throw new HttpFailure('HTTP_FAILURE', 404); }
    const result = await api(...args); return args[1].endsWith('/settle/') ? { ...result, outcome: 'never_accepted' } : result;
  };
  await f.transfer.reconcile(f.record, signal()); assert.deepEqual(f.calls[1].body, operationManifest(f.record)); assert.match(f.calls[2].path, /\/receipt\/$/);
});

test('server unavailability or still-pending settlement remains uncertain and does not spin', async () => {
  const pending = fixture(); await assert.rejects(pending.transfer.reconcile(pending.record, signal()), { code: 'SETTLEMENT_PENDING' }); assert.equal(pending.calls.length, 2);
  const unavailable = fixture(); unavailable.http.api = async () => { throw new HttpFailure('HTTP_FAILURE', 503, 30); };
  await assert.rejects(unavailable.transfer.reconcile(unavailable.record, signal()), { status: 503 });
});
