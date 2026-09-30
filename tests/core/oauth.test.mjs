import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import test from 'node:test';
import { NativeOAuth } from '../../core/oauth.ts';

const config = { environment: 'qa', apiOrigin: 'https://api.fin3000.test', appOrigin: 'https://app.fin3000.test', quarantineOrigins: ['https://quarantine.fin3000.test'],
  clientId: 'fin3000-system-print-qa', audience: 'fin3000-printer:qa', receiptKeys: { synthetic: 'public-test-fixture' } };
const signal = () => AbortSignal.timeout(5000);
const tokens = (suffix = 'first', expires = 3600) => ({ token_type: 'Bearer', scope: 'intake:write', access_token: `synthetic-access-${suffix}`, refresh_token: `synthetic-refresh-${suffix}`, expires_in: expires });

function fixture(options = {}) {
  let secret = options.secret ?? null;
  const saved = [], calls = [], clock = { time: Date.now(), now() { return this.time; } };
  const target = { id: randomUUID(), name: 'Synthetisches Unternehmen' };
  const principal = { protocolVersion: 2, subject: `sp_${'a'.repeat(32)}`, accountName: 'Synthetic account', target, capabilities: ['operations', 'settlement', 'recovery'] };
  const secrets = { async load() { return secret; }, async save(value) { secret = value; saved.push(JSON.parse(value)); }, async clear() { secret = null; }, ...options.secrets };
  let authorizeUrl;
  const browser = { async open(value) {
    authorizeUrl = new URL(value);
    const callback = new URL(authorizeUrl.searchParams.get('redirect_uri'));
    callback.search = new URLSearchParams({ code: 'synthetic-code-once', state: authorizeUrl.searchParams.get('state'), iss: config.apiOrigin }).toString();
    await options.beforeCallback?.(callback, authorizeUrl);
    const response = await fetch(callback); assert.equal(response.status, 200); await response.text();
  }, ...options.browser };
  const http = {
    async revoke(token, hint) { calls.push({ revoke: token, hint }); },
    async token(fields) { calls.push(fields); return tokens(fields.grant_type === 'refresh_token' ? 'rotated' : 'first', options.expires ?? 3600); },
    async api(method, path, body, token) { calls.push({ method, path, body, token }); return structuredClone(principal); }, ...options.http,
  };
  const agent = new NativeOAuth({ config, http, secrets, browser, clock });
  return { agent, saved, calls, secrets, browser, http, clock, principal, secret: () => secret, url: () => authorizeUrl };
}

test('browser PKCE binds loopback, state, issuer and exact narrow scope before token persistence', async () => {
  const f = fixture(); const binding = await f.agent.authorize(signal());
  assert.equal(binding.target.id, f.principal.target.id);
  assert.equal(binding.accountName, f.principal.accountName);
  assert.equal(f.url().pathname, '/oauth/authorize'); assert.equal(f.url().searchParams.get('scope'), 'intake:write');
  const exchange = f.calls[0]; assert.equal(exchange.client_id, config.clientId); assert.equal(exchange.grant_type, 'authorization_code');
  assert.equal(createHash('sha256').update(exchange.code_verifier).digest('base64url'), f.url().searchParams.get('code_challenge'));
  assert.match(exchange.redirect_uri, /^http:\/\/127\.0\.0\.1:\d+\/fin3000-print\/callback$/);
  assert.equal(f.saved[0].binding, null); assert.equal(f.saved[1].binding.target.id, binding.target.id);
  assert.equal((await f.agent.access(signal())).accessToken, 'synthetic-access-first');
});

test('disconnect revokes only its stored refresh/access credentials before clearing the keyring item', async () => {
  const f = fixture(); await f.agent.authorize(signal());
  await f.agent.disconnect(signal());
  assert.deepEqual(f.calls.filter(row => row.revoke), [
    { revoke: 'synthetic-refresh-first', hint: 'refresh_token' }, { revoke: 'synthetic-access-first', hint: 'access_token' },
  ]);
  assert.equal(f.secret(), null);
  await assert.rejects(f.agent.access(signal()), { code: 'SESSION_LOCKED' });
});

test('account printer preserves explicit null BU through login and restore', async () => {
  const f = fixture(); f.principal.target = { id: null, name: 'No fixed business unit' };
  const binding = await f.agent.authorize(signal());
  assert.equal(binding.target.id, null);
  assert.equal(JSON.parse(f.secret()).binding.target.id, null);
  const restored = fixture({ secret: f.secret() }); restored.principal.target = f.principal.target;
  assert.equal((await restored.agent.restore(signal())).target.id, null);
});

test('missing BU is invalid rather than an implicit account-wide grant', async () => {
  for (const id of [undefined, '', 'null']) {
    const f = fixture(); f.principal.target = { id, name: 'Invalid target' };
    await assert.rejects(f.agent.authorize(signal()), { code: 'PRINCIPAL_INVALID' });
  }
});

test('failed revoke retains secure credentials for retry; uncertain rotation does not falsely sign out', async () => {
  const f = fixture(); await f.agent.authorize(signal()); const original = f.secret();
  f.http.revoke = async () => { throw new Error('synthetic offline'); };
  await assert.rejects(f.agent.disconnect(signal()), { code: 'REVOCATION_PENDING' });
  assert.equal(f.secret(), original);
  const unknown = fixture({ secret: JSON.stringify({ ...JSON.parse(original), refreshPending: true }) });
  await assert.rejects(unknown.agent.disconnect(signal()), { code: 'REVOCATION_NEEDS_ACCOUNT' });
  assert.equal(unknown.calls.length, 0); assert.notEqual(unknown.secret(), null);
});

test('forged state/issuer, repeated query keys, POST, and foreign Origin never consume the valid callback', async () => {
  const f = fixture({ async beforeCallback(valid) {
    const variants = [url => url.searchParams.set('state', 'wrong'), url => url.searchParams.set('iss', 'https://other.test'),
      url => url.searchParams.append('code', 'second'), url => url.pathname = '/other', url => url.searchParams.set('token', 'forged')];
    for (const mutate of variants) { const forged = new URL(valid); mutate(forged); const response = await fetch(forged); assert.equal(response.status, 400); await response.text(); }
    for (const request of [{ method: 'POST' }, { headers: { Origin: 'https://untrusted.test' } }, { headers: { Host: 'localhost' } }]) {
      const response = await fetch(valid, request); assert.equal(response.status, 400); await response.text();
    }
  } });
  await f.agent.authorize(signal()); assert.equal(f.calls.filter(row => row.grant_type).length, 1);
});

test('locked/missing secret service prevents opening browser and has no plaintext fallback', async () => {
  let opened = false;
  const f = fixture({ secrets: { async load() { throw new Error('KEYRING_LOCKED'); } }, browser: { async open() { opened = true; } } });
  await assert.rejects(f.agent.authorize(signal()), /KEYRING_LOCKED/); assert.equal(opened, false); assert.equal(f.saved.length, 0);
});

test('one refresh writer across concurrent transfers and durable pending flag before sending', async () => {
  const f = fixture({ expires: 1 }); await f.agent.authorize(signal());
  let refreshes = 0;
  f.http.token = async fields => {
    assert.equal(fields.grant_type, 'refresh_token'); refreshes++;
    assert.equal(JSON.parse(f.secret()).refreshPending, true);
    await new Promise(resolve => setTimeout(resolve, 5)); return tokens('rotated');
  };
  const access = await Promise.all(Array.from({ length: 12 }, () => f.agent.access(signal())));
  assert.equal(refreshes, 1); assert.ok(access.every(row => row.accessToken === 'synthetic-access-rotated'));
  assert.equal(JSON.parse(f.secret()).refreshPending, false);
});

test('lost rotated-refresh response requires new login after restart, never replays old refresh', async () => {
  const f = fixture({ expires: 1 }); await f.agent.authorize(signal());
  f.http.token = async () => { throw new Error('CONNECTION_LOST'); };
  await assert.rejects(f.agent.access(signal()), /CONNECTION_LOST/); assert.equal(JSON.parse(f.secret()).refreshPending, true);
  const restarted = fixture({ secret: f.secret() });
  await assert.rejects(restarted.agent.restore(signal()), { code: 'LOGIN_REQUIRED' }); assert.equal(restarted.calls.length, 0);
});

test('failed secure save after refresh keeps uncertain token rotation fenced', async () => {
  const f = fixture({ expires: 1 }); await f.agent.authorize(signal());
  const oldSave = f.secrets.save;
  f.secrets.save = async value => { if (!JSON.parse(value).refreshPending) throw new Error('KEYRING_DISCONNECTED'); await oldSave(value); };
  await assert.rejects(f.agent.access(signal()), { code: 'SECRET_STORE_UNAVAILABLE' });
  assert.equal(JSON.parse(f.secret()).refreshPending, true);
  await assert.rejects(f.agent.access(signal()), { code: 'LOGIN_REQUIRED' });
});

test('restore rechecks current principal and refuses a changed owner or target', async () => {
  const original = fixture(); await original.agent.authorize(signal());
  const restarted = fixture({ secret: original.secret() });
  await assert.rejects(restarted.agent.restore(signal()), { code: 'PRINCIPAL_CHANGED' });
  await assert.rejects(restarted.agent.access(signal()), { code: 'LOGIN_REQUIRED' });
  restarted.principal.target = original.principal.target;
  assert.deepEqual(await restarted.agent.restore(signal()), JSON.parse(original.secret()).binding);
});

test('session locking stops access, including a refresh that was already in flight', async () => {
  const f = fixture({ expires: 1 }); await f.agent.authorize(signal());
  f.http.token = async () => { f.agent.lock(); return tokens('rotated'); };
  await assert.rejects(f.agent.access(signal()), { code: 'SESSION_LOCKED' });
  await assert.rejects(f.agent.access(signal()), { code: 'SESSION_LOCKED' });
});

test('scope broadening, oversized tokens and malformed expiry fail before persisting', async () => {
  for (const change of [{ scope: 'intake:write mcp:write' }, { token_type: 'MAC' }, { access_token: 'x'.repeat(5000) }, { expires_in: 3601 }]) {
    const f = fixture({ http: { async token() { return { ...tokens(), ...change }; } } });
    await assert.rejects(f.agent.authorize(signal()), { code: 'AUTH_RESPONSE_INVALID' }); assert.equal(f.saved.length, 0);
  }
});

test('cancelled browser login closes the ephemeral listener and never requests a token', async () => {
  const abort = new AbortController();
  const f = fixture({ browser: { async open() { abort.abort(); } } });
  await assert.rejects(f.agent.authorize(abort.signal), { code: 'LOGIN_CANCELLED' }); assert.equal(f.calls.length, 0);
});
