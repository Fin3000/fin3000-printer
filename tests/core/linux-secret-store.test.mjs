import assert from 'node:assert/strict';
import test from 'node:test';
import { LinuxSecretStore } from '../../platforms/linux/secret-store.ts';

test('native keyring bridge has environment-separated exact operations and no file fallback', async () => {
  const calls = []; let stored = null;
  const store = new LinuxSecretStore('qa', async request => {
    calls.push(request);
    if (request.action === 'load') return { value: stored };
    if (request.action === 'save') stored = request.value; else stored = null;
    return { ok: true };
  });
  assert.equal(await store.load(), null); await store.save('synthetic-token'); assert.equal(await store.load(), 'synthetic-token');
  await store.clear(); assert.equal(await store.load(), null);
  assert.deepEqual(calls[1], { action: 'save', environment: 'qa', value: 'synthetic-token' });
});

test('keyring lock, missing collection, ambiguous items and malformed response fail closed', async () => {
  for (const response of [{ error: 'KEYRING_LOCKED' }, { error: 'SECRET_COLLECTION_MISSING' }, { error: 'SECRET_STATE_AMBIGUOUS' },
    { error: 'private raw backend message' }, { value: 'x'.repeat(17000) }, { value: null, password: 'unexpected' }, [], null]) {
    const store = new LinuxSecretStore('production', async () => response);
    await assert.rejects(store.load(), error => { assert.match(error.code, /^(KEYRING_|SECRET_)/); assert.equal(error.message.includes('private'), false); return true; });
  }
  const store = new LinuxSecretStore('qa', async () => ({ ok: false }));
  await assert.rejects(store.save('synthetic'), { code: 'SECRET_RESPONSE_INVALID' });
  await assert.rejects(store.clear(), { code: 'SECRET_RESPONSE_INVALID' });
  await assert.rejects(store.save('Ä'.repeat(9000)), { code: 'SECRET_REQUEST_INVALID' });
});
