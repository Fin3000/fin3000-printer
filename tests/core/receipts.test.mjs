import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import test from 'node:test';
import { PinnedReceiptVerifier } from '../../core/receipts.ts';

function fixture() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const time = 1_800_000_000;
  const record = {
    operationId: randomUUID(), clientBatchId: randomUUID(), clientItemId: randomUUID(), requestFingerprint: 'a'.repeat(64),
    callbackNonce: randomBytes(32).toString('base64url'),
    binding: { issuer: 'https://api.fin3000.test', audience: 'fin3000-printer:qa', subject: `sp_${'b'.repeat(32)}`, clientId: 'fin3000-system-print-qa', target: { id: randomUUID(), name: 'Test' } },
  };
  const claims = {
    iss: record.binding.issuer, aud: record.binding.audience, sub: record.binding.subject,
    client_id: record.binding.clientId, target_id: record.binding.target.id, operation_id: record.operationId,
    client_batch_id: record.clientBatchId, client_item_id: record.clientItemId,
    request_fingerprint: record.requestFingerprint, nonce: record.callbackNonce, protocol_version: 2,
    generation: 2, jti: randomUUID(), iat: time, nbf: time, exp: time + 120, outcome: 'accepted',
  };
  const clock = { time: time * 1000, now() { return this.time; } };
  const verifier = new PinnedReceiptVerifier({ test: publicKey.export({ format: 'pem', type: 'spki' }).toString() }, clock);
  function token(changed = {}, header = {}, key = privateKey) {
    const h = Buffer.from(JSON.stringify({ alg: 'EdDSA', kid: 'test', typ: 'fin3000-print-receipt+jwt', ...header })).toString('base64url');
    const p = Buffer.from(JSON.stringify({ ...claims, ...changed })).toString('base64url');
    return `${h}.${p}.${sign(null, Buffer.from(`${h}.${p}`), key).toString('base64url')}`;
  }
  return { record, claims, verifier, clock, token };
}

test('pinned asymmetric receipt accepts exactly bound terminal outcomes', () => {
  const f = fixture();
  assert.equal(f.verifier.verify(f.token(), f.record), 'accepted');
  assert.equal(f.verifier.verify(f.token({ outcome: 'never_accepted' }), f.record), 'never_accepted');
});

test('wrong owner, client, target, IDs, manifest, nonce and environment fail even when signed', () => {
  const f = fixture();
  for (const field of ['iss', 'aud', 'sub', 'client_id', 'target_id', 'operation_id', 'client_batch_id', 'client_item_id', 'request_fingerprint', 'nonce', 'outcome']) {
    assert.throws(() => f.verifier.verify(f.token({ [field]: 'changed' }), f.record), { code: 'RECEIPT_INVALID' }, field);
  }
});

test('null BU receipts remain exact owner-bound proofs, not wildcard targets', () => {
  const f = fixture(); f.record.binding.target.id = null;
  assert.equal(f.verifier.verify(f.token({ target_id: null }), f.record), 'accepted');
  for (const target_id of [undefined, '', 'null', randomUUID()]) {
    assert.throws(() => f.verifier.verify(f.token({ target_id }), f.record), { code: 'RECEIPT_INVALID' });
  }
  assert.throws(() => f.verifier.verify(f.token({ target_id: null, sub: `sp_${'c'.repeat(32)}` }), f.record), { code: 'RECEIPT_INVALID' });
});

test('expired, future, overlong or missing timestamps are not recovery proofs', () => {
  const f = fixture();
  for (const changed of [{ exp: f.claims.iat }, { exp: f.claims.iat + 121 }, { iat: f.claims.iat + 31, nbf: f.claims.iat + 31, exp: f.claims.iat + 151 }, { nbf: null }, { generation: 0 }]) {
    assert.throws(() => f.verifier.verify(f.token(changed), f.record), { code: 'RECEIPT_INVALID' });
  }
  f.clock.time += 120_000;
  assert.throws(() => f.verifier.verify(f.token(), f.record), { code: 'RECEIPT_INVALID' });
});

test('no algorithm downgrade, unknown kid, URL keys or alternate signing key', () => {
  const f = fixture();
  for (const header of [{ alg: 'none' }, { alg: 'HS256' }, { kid: 'elsewhere' }, { jku: 'https://evil.test/key' }, { crit: ['x'] }]) {
    assert.throws(() => f.verifier.verify(f.token({}, header), f.record), { code: 'RECEIPT_INVALID' });
  }
  assert.throws(() => f.verifier.verify(f.token({}, {}, generateKeyPairSync('ed25519').privateKey), f.record), { code: 'RECEIPT_INVALID' });
});

test('padding, whitespace, appended fields and oversized tokens are rejected', () => {
  const f = fixture(); const token = f.token();
  for (const bad of [token + '=', token + '\n', token + '.extra', ` ${token}`, 'x'.repeat(8193)]) {
    assert.throws(() => f.verifier.verify(bad, f.record), { code: 'RECEIPT_INVALID' });
  }
});
