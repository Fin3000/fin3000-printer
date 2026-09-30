import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import test from 'node:test';
import { recoveryExport } from '../../core/recovery-export.ts';

function record() {
  return {operationId: randomUUID(), clientBatchId: randomUUID(), clientItemId: randomUUID(),
    identity: {generation: randomUUID(), nativeJobUuid: randomUUID()},
    binding: {issuer: 'https://api.fin3000.test', audience: 'fin3000-printer:qa', clientId: 'fin3000-system-print-qa',
      subject: `sp_${'a'.repeat(32)}`, target: {id: randomUUID(), name: 'PRIVATE-TARGET'}},
    name: 'PRIVATE-DOCUMENT.pdf', size: 93872, requestFingerprint: 'b'.repeat(64), pdfSha256: 'c'.repeat(64),
    callbackNonce: randomBytes(32).toString('base64url'), outcome: 'uncertain', delivery: 'possibly_delivered', receivedAt: 1000000,
    extended: false, code: 'LOGIN_REQUIRED'};
}

test('opaque export has an exact minimal schema and deterministic checksum, without mutating persisted state', () => {
  const row = record(), before = structuredClone(row), text = recoveryExport(row), data = JSON.parse(text);
  assert.deepEqual(Object.keys(data), ['format', 'version', 'issuer', 'audience', 'clientId', 'subject', 'targetId',
    'operationId', 'clientBatchId', 'clientItemId', 'requestFingerprint', 'callbackNonce', 'checksum']);
  assert.equal(text, recoveryExport(row)); assert.deepEqual(row, before); assert.ok(Buffer.byteLength(text) < 4096);
  const {checksum, ...payload} = data;
  assert.equal(checksum, createHash('sha256').update(JSON.stringify(payload)).digest('hex'));
  for (const secret of ['PRIVATE', row.pdfSha256, row.identity.nativeJobUuid, 'receivedAt', 'receipt', 'size', 'accessToken', 'refreshToken']) {
    assert.equal(text.includes(secret), false, secret);
  }
  assert.equal(data.operationId, row.operationId); assert.equal(data.callbackNonce, row.callbackNonce);
});

test('export refuses unsent, accepted or malformed state and cannot silently include new fields', () => {
  const row = record();
  for (const changed of [{outcome: 'cancelled', delivery: 'not_dispatched'}, {outcome: 'waiting', delivery: 'not_dispatched'},
    {outcome: 'accepted', delivery: 'settled', receipt: 'synthetic'}]) {
    assert.throws(() => recoveryExport({...row, ...changed}), {code: 'RECOVERY_NOT_AVAILABLE'});
  }
  for (const changed of [{operationId: '../path'}, {accessToken: 'secret'}, {callbackNonce: 'invalid'}, {requestFingerprint: 'invalid'}]) {
    assert.throws(() => recoveryExport({...row, ...changed}), {code: 'STATE_INVALID'});
  }
});

test('unassigned jobs preserve explicit null in the checksummed recovery export', () => {
  const row = record(); row.binding.target.id = null;
  const { checksum, ...payload } = JSON.parse(recoveryExport(row));
  assert.equal(payload.targetId, null);
  assert.equal(checksum, createHash('sha256').update(JSON.stringify(payload)).digest('hex'));
  delete row.binding.target.id;
  assert.throws(() => recoveryExport(row), { code: 'STATE_INVALID' });
});
