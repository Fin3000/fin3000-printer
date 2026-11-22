/** One OAuth writer; OS Secret Service is mandatory, with no file fallback. */
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { PRINT_API, validateBuildConfig } from './config.ts';
import type { BuildConfig } from './config.ts';
import type { HttpPort } from './http.ts';
import { PrinterError, sameBinding, validateBinding } from './protocol.ts';
import type { Binding, Clock } from './protocol.ts';

export interface SecretStore {
  load(): Promise<string | null>;
  save(value: string): Promise<void>;
  clear(): Promise<void>;
}
export interface BrowserPort { open(url: string): Promise<void> }
export interface AuthorizedToken { accessToken: string; binding: Binding }
export interface DisplayedBinding extends Binding { accountName: string }
interface SecretSession {
  version: 1; clientId: string; issuer: string;
  accessToken: string; refreshToken: string; expiresAt: number;
  refreshPending: boolean; binding: Binding | null;
}
const tokenValid = (value: unknown): value is string => typeof value === 'string' && /^[\x21-\x7e]{16,4096}$/.test(value);
const object = (value: unknown): Record<string, unknown> => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new PrinterError('AUTH_RESPONSE_INVALID');
  return value as Record<string, unknown>;
};

export class NativeOAuth {
  private config: Readonly<BuildConfig>;
  private http: HttpPort;
  private secrets: SecretStore;
  private browser: BrowserPort;
  private clock: Clock;
  private current: SecretSession | null = null;
  private tail: Promise<unknown> = Promise.resolve();
  private locked = false;

  constructor(options: { config: BuildConfig; http: HttpPort; secrets: SecretStore; browser: BrowserPort; clock: Clock }) {
    this.config = validateBuildConfig(options.config); this.http = options.http;
    this.secrets = options.secrets; this.browser = options.browser; this.clock = options.clock;
  }

  private exclusive<T>(action: () => Promise<T>): Promise<T> {
    const result = this.tail.then(action); this.tail = result.catch(() => {}); return result;
  }

  authorize(signal: AbortSignal): Promise<DisplayedBinding> {
    return this.exclusive(async () => {
      this.current = null; this.locked = false;
      // Probe the secure adapter before opening a browser. Locked/missing keyring
      // must not result in an apparently connected but non-persistent account.
      await this.secrets.load();
      const callback = await loopbackAuthorization(this.config, this.browser, signal);
      const raw = await this.http.token({ grant_type: 'authorization_code', client_id: this.config.clientId,
        code: callback.code, redirect_uri: callback.redirectUri, code_verifier: callback.verifier }, signal);
      const session = this.parseTokens(raw, null);
      await this.persist(session);
      const principal = await this.principal(session.accessToken, signal);
      const { accountName: _displayOnly, ...binding } = principal;
      session.binding = binding;
      await this.persist(session);
      if (this.locked) throw new PrinterError('SESSION_LOCKED');
      this.current = session;
      return structuredClone(principal);
    });
  }

  restore(signal: AbortSignal): Promise<DisplayedBinding> {
    return this.exclusive(async () => {
      try {
      this.locked = false; this.current = null;
      const saved = await this.secrets.load();
      if (saved === null) throw new PrinterError('LOGIN_REQUIRED');
      const session = this.parseStored(saved);
      if (session.refreshPending) throw new PrinterError('LOGIN_REQUIRED');
      this.current = session;
      await this.fresh(signal);
      const principal = await this.principal(this.current!.accessToken, signal);
      const { accountName: _displayOnly, ...binding } = principal;
      if (session.binding && !sameBinding(binding, session.binding)) {
        this.current = null; throw new PrinterError('PRINCIPAL_CHANGED');
      }
      this.current!.binding = binding;
      await this.persist(this.current!);
      if (this.locked) { this.current = null; throw new PrinterError('SESSION_LOCKED'); }
      return structuredClone(principal);
      } catch (error) { this.current = null; throw error; }
    });
  }

  access(signal: AbortSignal): Promise<AuthorizedToken> {
    return this.exclusive(async () => {
      if (this.locked) throw new PrinterError('SESSION_LOCKED');
      await this.fresh(signal);
      if (this.locked) throw new PrinterError('SESSION_LOCKED');
      if (!this.current?.binding) throw new PrinterError('LOGIN_REQUIRED');
      return { accessToken: this.current.accessToken, binding: structuredClone(this.current.binding) };
    });
  }

  lock(): void { this.locked = true; }

  disconnect(signal: AbortSignal): Promise<void> {
    this.locked = true;
    return this.exclusive(async () => {
      this.current = null;
      const saved = await this.secrets.load();
      if (saved === null) return;
      const session = this.parseStored(saved);
      // A lost rotation may have created an unknown successor. Revoking only
      // its already-rotated predecessor is not proof that the family is gone.
      if (session.refreshPending) throw new PrinterError('REVOCATION_NEEDS_ACCOUNT');
      try {
        await this.http.revoke(session.refreshToken, 'refresh_token', signal);
        await this.http.revoke(session.accessToken, 'access_token', signal);
      } catch { throw new PrinterError('REVOCATION_PENDING'); }
      // Keep the secure record on network failure for a later revoke attempt.
      // Never delete unrelated clients/collections or local recovery metadata.
      await this.secrets.clear();
    });
  }

  private async fresh(signal: AbortSignal): Promise<void> {
    const previous = this.current;
    if (!previous || previous.refreshPending) throw new PrinterError('LOGIN_REQUIRED');
    if (previous.expiresAt > this.clock.now() + 60_000) return;
    // Durable BEFORE sending: a lost response/crash can never replay a rotated
    // refresh token and revoke the replacement family on the next launch.
    previous.refreshPending = true;
    await this.persist(previous);
    try {
      const raw = await this.http.token({ grant_type: 'refresh_token', client_id: this.config.clientId,
        refresh_token: previous.refreshToken }, signal);
      const next = this.parseTokens(raw, previous.binding);
      if (next.refreshToken === previous.refreshToken) throw new PrinterError('AUTH_RESPONSE_INVALID');
      await this.persist(next); this.current = next;
    } catch (error) { this.current = null; throw error; }
  }

  private async persist(session: SecretSession): Promise<void> {
    try { await this.secrets.save(JSON.stringify(session)); }
    catch { this.current = null; throw new PrinterError('SECRET_STORE_UNAVAILABLE'); }
  }

  private parseTokens(input: unknown, binding: Binding | null): SecretSession {
    const raw = object(input);
    if (raw.token_type !== 'Bearer' || raw.scope !== 'intake:write' || !tokenValid(raw.access_token) ||
        !tokenValid(raw.refresh_token) || !Number.isSafeInteger(raw.expires_in) ||
        (raw.expires_in as number) < 1 || (raw.expires_in as number) > 3600) throw new PrinterError('AUTH_RESPONSE_INVALID');
    return { version: 1, clientId: this.config.clientId, issuer: this.config.apiOrigin,
      accessToken: raw.access_token, refreshToken: raw.refresh_token,
      expiresAt: this.clock.now() + (raw.expires_in as number) * 1000, refreshPending: false, binding };
  }

  private parseStored(value: string): SecretSession {
    try {
      if (value.length > 16 * 1024) throw new Error();
      const raw = object(JSON.parse(value));
      if (Object.keys(raw).sort().join(',') !== 'accessToken,binding,clientId,expiresAt,issuer,refreshPending,refreshToken,version' ||
          raw.version !== 1 || raw.clientId !== this.config.clientId || raw.issuer !== this.config.apiOrigin ||
          !tokenValid(raw.accessToken) || !tokenValid(raw.refreshToken) || !Number.isSafeInteger(raw.expiresAt) ||
          typeof raw.refreshPending !== 'boolean') throw new Error();
      if (raw.binding !== null) {
        const binding = raw.binding as Binding; validateBinding(binding);
        if (binding.issuer !== this.config.apiOrigin || binding.clientId !== this.config.clientId || binding.audience !== this.config.audience) throw new Error();
      }
      return raw as unknown as SecretSession;
    } catch { throw new PrinterError('SECRET_STATE_INVALID'); }
  }

  private async principal(token: string, signal: AbortSignal): Promise<DisplayedBinding> {
    const raw = object(await this.http.api('GET', `${PRINT_API}principal/`, undefined, token, signal));
    const capabilities = raw.capabilities;
    if (raw.protocolVersion !== 2 || !Array.isArray(capabilities) ||
        !['operations', 'settlement', 'recovery'].every(value => capabilities.includes(value))) throw new PrinterError('PRINCIPAL_INVALID');
    const target = object(raw.target);
    const binding: DisplayedBinding = { issuer: this.config.apiOrigin, audience: this.config.audience,
      clientId: this.config.clientId, subject: raw.subject as string, accountName: raw.accountName as string,
      target: { id: target.id as string | null, name: target.name as string } };
    try { validateBinding(binding); } catch { throw new PrinterError('PRINCIPAL_INVALID'); }
    return binding;
  }
}

async function loopbackAuthorization(config: Readonly<BuildConfig>, browser: BrowserPort, parent: AbortSignal): Promise<{ code: string; redirectUri: string; verifier: string }> {
  const verifier = randomBytes(32).toString('base64url'), state = randomBytes(32).toString('base64url');
  const signal = AbortSignal.any([parent, AbortSignal.timeout(300_000)]);
  if (signal.aborted) throw new PrinterError('LOGIN_CANCELLED');
  return new Promise((resolve, reject) => {
    let redirectUri = '', expectedHost = '', done = false;
    const server = createServer({ maxHeaderSize: 8192, requestTimeout: 5000, headersTimeout: 5000 }, (request, response) => {
      response.setHeader('Cache-Control', 'no-store'); response.setHeader('Referrer-Policy', 'no-referrer');
      response.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
      response.setHeader('Content-Type', 'text/plain; charset=utf-8');
      try {
        if (done || request.method !== 'GET' || request.headers.host !== expectedHost || !request.url || request.url.length > 8192 ||
            (request.headers.origin !== undefined && request.headers.origin !== config.appOrigin)) throw new Error();
        const url = new URL(request.url, redirectUri), values = url.searchParams;
        if (url.origin !== new URL(redirectUri).origin || url.pathname !== '/fin3000-print/callback' || url.hash ||
            [...values.keys()].some(key => !['code', 'state', 'iss', 'error', 'error_description'].includes(key) || values.getAll(key).length !== 1)) throw new Error();
        const receivedState = values.get('state') ?? '';
        if (receivedState.length !== state.length || !timingSafeEqual(Buffer.from(receivedState), Buffer.from(state)) || values.get('iss') !== config.apiOrigin) throw new Error();
        const code = values.get('code');
        if (values.has('error')) {
          if (code) throw new Error();
          response.writeHead(200); response.end('Anmeldung abgebrochen. Du kannst dieses Fenster schließen.');
          finish(new PrinterError('LOGIN_DENIED')); return;
        }
        if (!code || !/^[\x21-\x7e]{16,4096}$/.test(code)) throw new Error();
        response.writeHead(200); response.end('Anmeldung bestätigt. Kehre zum Fin3000-Drucker zurück.');
        finish(undefined, code);
      } catch { response.writeHead(400); response.end('Diese Anmeldeantwort ist ungültig.'); }
    });
    const finish = (error?: Error, code?: string) => {
      if (done) return; done = true;
      signal.removeEventListener('abort', abort);
      server.close(); server.closeIdleConnections();
      if (error) { server.closeAllConnections(); reject(error); }
      else resolve({ code: code!, redirectUri, verifier });
    };
    const abort = () => finish(new PrinterError('LOGIN_CANCELLED'));
    signal.addEventListener('abort', abort, { once: true });
    server.on('error', () => finish(new PrinterError('LOOPBACK_UNAVAILABLE')));
    server.listen({ host: '127.0.0.1', port: 0, exclusive: true }, () => {
      if (done) { server.close(); return; }
      expectedHost = `127.0.0.1:${(server.address() as AddressInfo).port}`;
      redirectUri = `http://${expectedHost}/fin3000-print/callback`;
      const url = new URL('/oauth/authorize', config.appOrigin);
      url.search = new URLSearchParams({ response_type: 'code', client_id: config.clientId, scope: 'intake:write', redirect_uri: redirectUri,
        state, code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256' }).toString();
      void browser.open(url.toString()).catch(() => finish(new PrinterError('BROWSER_UNAVAILABLE')));
    });
  });
}
