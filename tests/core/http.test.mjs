import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { PRINT_API, validateBuildConfig } from '../../core/config.ts';
import { NativeHttp } from '../../core/http.ts';

const signal = () => AbortSignal.timeout(5000);
const token = 'synthetic-token-never-live';
async function fixture(t, handler) {
  const server = createServer(handler); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { server.closeAllConnections(); server.close(); });
  const origin = `http://127.0.0.1:${server.address().port}`;
  const config = { environment: 'qa', apiOrigin: origin, appOrigin: origin, quarantineOrigins: [origin],
    clientId: 'fin3000-system-print-qa', audience: 'fin3000-printer:qa', receiptKeys: { synthetic: 'public-test-fixture' } };
  return { config, http: new NativeHttp(config), origin };
}

test('build destinations are immutable; production cannot use QA client, HTTP, aliases or credentials', () => {
  const good = { environment: 'production', apiOrigin: 'https://api.fin3000.com', appOrigin: 'https://app.fin3000.com',
    quarantineOrigins: ['https://quarantine.fin3000.test'], clientId: 'fin3000-system-print', audience: 'fin3000-printer:production', receiptKeys: { key: 'public' } };
  const copy = validateBuildConfig(good); good.quarantineOrigins.push('https://untrusted.test');
  assert.equal(copy.quarantineOrigins.length, 1); assert.ok(Object.isFrozen(copy.receiptKeys));
  for (const change of [{ apiOrigin: 'https://evil.test' }, { appOrigin: 'http://app.fin3000.com' },
    { apiOrigin: 'https://api.fin3000.com/' }, { clientId: 'fin3000-system-print-qa' }, { quarantineOrigins: ['https://u:p@storage.test'] },
    { environment: 'qa', apiOrigin: 'http://localhost:5000' }]) assert.throws(() => validateBuildConfig({ ...good, ...change }), { code: 'BUILD_CONFIG_INVALID' });
});

test('API uses exact bearer and v2 header; token exchange uses form and no bearer', async t => {
  const requests = [];
  const f = await fixture(t, async (req, res) => {
    const parts = []; for await (const part of req) parts.push(part);
    requests.push({ url: req.url, headers: req.headers, body: Buffer.concat(parts).toString() });
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.end('{"ok":true}');
  });
  assert.deepEqual(await f.http.api('POST', `${PRINT_API}manifest/`, { name: 'Änderung' }, token, signal()), { ok: true });
  await f.http.token({ client_id: f.config.clientId, grant_type: 'authorization_code', code: 'synthetic-secret' }, signal());
  assert.equal(requests[0].headers.authorization, `Bearer ${token}`); assert.equal(requests[0].headers['x-fin3000-print-protocol'], '2');
  assert.deepEqual(JSON.parse(requests[0].body), { name: 'Änderung' });
  assert.equal(requests[1].url, '/o/token/'); assert.equal(requests[1].headers.authorization, undefined);
  assert.equal(new URLSearchParams(requests[1].body).get('code'), 'synthetic-secret');
});

test('QA rejects every production destination, including quarantine and app origins', async t => {
  const { config } = await fixture(t, (_req, res) => res.end());
  for (const change of [{ apiOrigin: 'https://api.fin3000.com' }, { appOrigin: 'https://app.fin3000.com' },
    { quarantineOrigins: ['https://s3.production.example'] }]) {
    assert.throws(() => validateBuildConfig({ ...config, ...change }), { code: 'BUILD_CONFIG_INVALID' });
  }
});

test('redirect is refused without disclosing credentials to the new destination', async t => {
  let leaked = 0;
  const target = await fixture(t, (_req, res) => { leaked++; res.end(); });
  const f = await fixture(t, (_req, res) => { res.writeHead(307, { Location: `${target.origin}/stolen` }); res.end(); });
  await assert.rejects(f.http.api('GET', `${PRINT_API}principal/`, undefined, token, signal()), { code: 'REDIRECT_REFUSED', status: 307 });
  assert.equal(leaked, 0);
});

test('revocation uses the fixed OAuth endpoint, scoped client and empty RFC7009 response', async t => {
  let request;
  const f = await fixture(t, async (req, res) => {
    const parts = []; for await (const part of req) parts.push(part);
    request = { url: req.url, headers: req.headers, body: Buffer.concat(parts).toString() };
    res.writeHead(200); res.end();
  });
  await f.http.revoke(token, 'refresh_token', signal());
  assert.equal(request.url, '/o/revoke_token/'); assert.equal(request.headers.authorization, undefined);
  assert.deepEqual(Object.fromEntries(new URLSearchParams(request.body)), { client_id: f.config.clientId, token, token_type_hint: 'refresh_token' });
  await assert.rejects(f.http.revoke(`${token}\nprivate`, 'refresh_token', signal()), { code: 'TOKEN_REQUEST_INVALID' });
});

test('invalid paths, header injection and oversized controls fail before network', async t => {
  let calls = 0; const f = await fixture(t, (_req, res) => { calls++; res.end(); });
  for (const path of ['https://untrusted.test/', '//untrusted.test/', '/api/v1/members/', `${PRINT_API}../members`, `${PRINT_API}%2e%2e/`, `${PRINT_API}%2Fsteal`]) {
    await assert.rejects(f.http.api('GET', path, undefined, token, signal()), { code: 'API_REQUEST_INVALID' });
  }
  await assert.rejects(f.http.api('GET', `${PRINT_API}principal/`, undefined, `${token}\r\nX:secret`, signal()), { code: 'API_REQUEST_INVALID' });
  await assert.rejects(f.http.api('POST', `${PRINT_API}manifest/`, 'x'.repeat(200000), token, signal()), { code: 'API_REQUEST_INVALID' });
  assert.equal(calls, 0);
});

test('HTML, malformed JSON, invalid UTF-8 and excessive responses are rejected', async t => {
  let index = 0;
  const f = await fixture(t, (_req, res) => {
    const cases = [ ['text/html', '<html>secret</html>'], ['application/json', '{'], ['application/json', Buffer.from([255])], ['application/json', 'x'.repeat(270000)] ];
    const [type, body] = cases[index++]; res.writeHead(200, { 'Content-Type': type }); res.end(body);
  });
  for (let attempt = 0; attempt < 4; attempt++) await assert.rejects(f.http.api('GET', `${PRINT_API}principal/`, undefined, token, signal()),
    error => { assert.match(error.code, /^HTTP_RESPONSE_(INVALID|TOO_LARGE)$/); assert.equal(error.message.includes('secret'), false); return true; });
});

test('failure returns bounded Retry-After and never logs a provider response body', async t => {
  const f = await fixture(t, (_req, res) => { res.writeHead(503, { 'Retry-After': '99999' }); res.end('private-provider-details'); });
  await assert.rejects(f.http.api('GET', `${PRINT_API}principal/`, undefined, token, signal()), error => {
    assert.equal(error.status, 503); assert.equal(error.retryAfter, 86400); assert.equal(error.message, 'HTTP_FAILURE'); return true;
  });
});

test('upload uses signed fields and synthetic PDF without bearer, title or API header', async t => {
  let request;
  const f = await fixture(t, async (req, res) => {
    const parts = []; for await (const part of req) parts.push(part);
    request = { headers: req.headers, body: Buffer.concat(parts).toString() }; res.writeHead(204); res.end();
  });
  const pdf = Buffer.from('%PDF-synthetic'), item = randomUUID();
  const intent = { method: 'POST', url: `${f.origin}/bucket/`, fields: { key: `incoming/system-print/${randomUUID()}/${item}/payload`,
    'Content-Type': 'application/pdf', 'x-amz-meta-intake-item': item, policy: 'synthetic-policy' }, expiresAt: new Date(Date.now() + 600000).toISOString(), minimumBytes: pdf.length, maximumBytes: pdf.length };
  await f.http.upload(intent, pdf, signal());
  assert.equal(request.headers.authorization, undefined); assert.equal(request.headers['x-fin3000-print-protocol'], undefined);
  assert.match(request.body, /name="file"; filename="document.pdf"/); assert.match(request.body, /%PDF-synthetic/);
  for (const change of [{ url: 'https://untrusted.test' }, { method: 'PUT' }, { maximumBytes: pdf.length - 1 },
    { expiresAt: 'invalid' }, { fields: { ...intent.fields, file: 'injected' } }, { fields: { ...intent.fields, 'bad\r\nHeader': 'bad' } }]) {
    await assert.rejects(f.http.upload({ ...intent, ...change }, pdf, signal()), { code: 'UPLOAD_INTENT_INVALID' });
  }
});

test('aborting a request closes a stalled network operation promptly', async t => {
  let reached; const requestSeen = new Promise(resolve => { reached = resolve; });
  const f = await fixture(t, () => reached()); const abort = new AbortController();
  const pending = f.http.api('GET', `${PRINT_API}principal/`, undefined, token, abort.signal);
  await requestSeen; abort.abort(); await assert.rejects(pending, { code: 'REQUEST_CANCELLED' });
  await assert.rejects(f.http.api('GET', `${PRINT_API}principal/`, undefined, token, abort.signal), { code: 'REQUEST_CANCELLED' });
});
