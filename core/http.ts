/** Bounded, redirect-free HTTP. Credentials and PDFs have separate destinations. */
import http from 'node:http';
import https from 'node:https';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { PRINT_API, validateBuildConfig } from './config.ts';
import type { BuildConfig } from './config.ts';
import { MAX_PDF_BYTES, PrinterError } from './protocol.ts';
import { retryAfterSeconds } from './retry.ts';

export interface UploadIntent {
  method: 'POST'; url: string; fields: Record<string, string>;
  expiresAt: string; minimumBytes: number; maximumBytes: number;
}
export interface HttpPort {
  api(method: 'GET' | 'POST', path: string, body: unknown, token: string, signal: AbortSignal): Promise<unknown>;
  token(fields: Record<string, string>, signal: AbortSignal): Promise<unknown>;
  revoke(token: string, hint: 'access_token' | 'refresh_token', signal: AbortSignal): Promise<void>;
  upload(intent: UploadIntent, pdf: Buffer, signal: AbortSignal): Promise<void>;
}
export class HttpFailure extends PrinterError {
  readonly status: number;
  readonly retryAfter?: number;
  constructor(code: string, status = 0, retryAfter?: number) { super(code); this.status = status; this.retryAfter = retryAfter; }
}

export class NativeHttp implements HttpPort {
  private config: Readonly<BuildConfig>;
  constructor(config: BuildConfig) { this.config = validateBuildConfig(config); }

  async api(method: 'GET' | 'POST', path: string, body: unknown, token: string, signal: AbortSignal): Promise<unknown> {
    if (!path.startsWith(PRINT_API) || !/^[a-zA-Z0-9/_?=&%-]+$/.test(path) || path.includes('..') || /%2f|%5c|%2e/i.test(path) ||
        !/^[\x21-\x7e]{16,4096}$/.test(token)) throw new PrinterError('API_REQUEST_INVALID');
    const bytes = body === undefined ? [] : [Buffer.from(JSON.stringify(body))];
    if (bytes[0]?.length > 128 * 1024) throw new PrinterError('API_REQUEST_INVALID');
    return this.json(await this.request(new URL(path, this.config.apiOrigin), method, {
      Authorization: `Bearer ${token}`, 'X-Fin3000-Print-Protocol': '2',
      Accept: 'application/json', 'Content-Type': 'application/json',
    }, bytes, signal, false));
  }

  async token(fields: Record<string, string>, signal: AbortSignal): Promise<unknown> {
    const bytes = Buffer.from(new URLSearchParams(fields).toString());
    if (bytes.length > 32 * 1024 || fields.client_id !== this.config.clientId) throw new PrinterError('TOKEN_REQUEST_INVALID');
    return this.json(await this.request(new URL('/o/token/', this.config.apiOrigin), 'POST', {
      Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded',
    }, [bytes], signal, false));
  }

  async revoke(token: string, hint: 'access_token' | 'refresh_token', signal: AbortSignal): Promise<void> {
    if (!/^[\x21-\x7e]{16,4096}$/.test(token) || !['access_token', 'refresh_token'].includes(hint)) throw new PrinterError('TOKEN_REQUEST_INVALID');
    const bytes = Buffer.from(new URLSearchParams({ client_id: this.config.clientId, token, token_type_hint: hint }).toString());
    try {
      await this.request(new URL('/o/revoke_token/', this.config.apiOrigin), 'POST',
        { 'Content-Type': 'application/x-www-form-urlencoded' }, [bytes], signal, false, false);
    } finally { bytes.fill(0); }
  }

  async upload(intent: UploadIntent, pdf: Buffer, signal: AbortSignal): Promise<void> {
    let url: URL;
    try {
      url = new URL(intent.url);
      if (intent.method !== 'POST' || !this.config.quarantineOrigins.includes(url.origin) || url.username || url.password || url.hash || url.search ||
          !Number.isFinite(Date.parse(intent.expiresAt)) || Date.parse(intent.expiresAt) <= Date.now() ||
          !Number.isSafeInteger(intent.minimumBytes) || !Number.isSafeInteger(intent.maximumBytes) ||
          intent.minimumBytes < 1 || intent.maximumBytes > MAX_PDF_BYTES || pdf.length < intent.minimumBytes || pdf.length > intent.maximumBytes ||
          !intent.fields || Array.isArray(intent.fields) || Object.keys(intent.fields).length > 32 ||
          Object.entries(intent.fields).some(([key, value]) => !/^[A-Za-z0-9_-]{1,80}$/.test(key) || key.toLowerCase() === 'file' ||
            typeof value !== 'string' || value.length > 16384 || /[\r\n\0]/.test(value)) ||
          intent.fields['Content-Type'] !== 'application/pdf' || !/^incoming\/system-print\/[0-9a-f-]{36}\/[0-9a-f-]{36}\/payload$/.test(intent.fields.key)) throw new Error();
    } catch { throw new PrinterError('UPLOAD_INTENT_INVALID'); }
    const boundary = `fin3000-${randomBytes(24).toString('hex')}`;
    const fields = Object.entries(intent.fields).map(([name, value]) => `--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`).join('');
    const prefix = Buffer.from(`${fields}--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="document.pdf"\r\nContent-Type: application/pdf\r\n\r\n`);
    await this.request(url, 'POST', { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
      [prefix, pdf, Buffer.from(`\r\n--${boundary}--\r\n`)], signal, true);
  }

  private json(bytes: Buffer): unknown {
    try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
    catch { throw new HttpFailure('HTTP_RESPONSE_INVALID'); }
  }

  private request(url: URL, method: string, headers: Record<string, string>, chunks: Buffer[], signal: AbortSignal, upload: boolean, jsonResponse = !upload): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      if (signal.aborted) { reject(new HttpFailure('REQUEST_CANCELLED')); return; }
      const timers: ReturnType<typeof setTimeout>[] = [];
      const pump = new AbortController();
      let done = false, responseStarted = false;
      const transport = url.protocol === 'https:' ? https : http;
      const req = transport.request(url, { method, headers: {
        ...headers, 'Content-Length': String(chunks.reduce((sum, chunk) => sum + chunk.length, 0)),
        'User-Agent': 'Fin3000-Printer/2', 'Accept-Encoding': 'identity',
      }, agent: false });
      const finish = (error?: Error, value?: Buffer) => {
        if (done) return;
        done = true;
        for (const timer of timers) clearTimeout(timer);
        signal.removeEventListener('abort', abort);
        pump.abort(); req.destroy();
        if (error) reject(error); else resolve(value!);
      };
      const timeout = (ms: number, code: string) => {
        const timer = setTimeout(() => finish(new HttpFailure(code)), ms);
        timer.unref(); timers.push(timer); return timer;
      };
      const abort = () => finish(new HttpFailure('REQUEST_CANCELLED'));
      signal.addEventListener('abort', abort, { once: true });
      const connectTimer = timeout(5000, 'CONNECT_TIMEOUT');
      timeout(upload ? 300_000 : 30_000, 'REQUEST_TIMEOUT');
      req.on('socket', socket => {
        socket.once(url.protocol === 'https:' ? 'secureConnect' : 'connect', () => clearTimeout(connectTimer));
      });
      req.setTimeout(upload ? 30_000 : 15_000, () => finish(new HttpFailure('NETWORK_IDLE_TIMEOUT')));
      req.once('finish', () => { if (!responseStarted && !done) timeout(15_000, 'HEADERS_TIMEOUT'); });
      req.on('error', () => finish(new HttpFailure('NETWORK_UNAVAILABLE')));
      req.on('response', response => {
        responseStarted = true;
        // Header timeout is no longer relevant; keep total/connect budgets.
        for (const timer of timers.slice(2)) clearTimeout(timer);
        const status = response.statusCode ?? 0;
        if (status < 200 || status >= 300) {
          const raw = response.headers['retry-after'];
          const retry = retryAfterSeconds(typeof raw === 'string' ? raw : undefined, Date.now());
          finish(new HttpFailure(status >= 300 && status < 400 ? 'REDIRECT_REFUSED' : 'HTTP_FAILURE', status, retry)); response.destroy(); return;
        }
        if (jsonResponse && !/^application\/json(?:\s*;|$)/i.test(response.headers['content-type'] ?? '')) {
          finish(new HttpFailure('HTTP_RESPONSE_INVALID', status)); response.destroy(); return;
        }
        const maximum = upload ? 64 * 1024 : 256 * 1024;
        const parts: Buffer[] = []; let length = 0;
        response.on('data', chunk => {
          length += chunk.length;
          if (length > maximum) { finish(new HttpFailure('HTTP_RESPONSE_TOO_LARGE', status)); response.destroy(); }
          else parts.push(chunk);
        });
        response.on('end', () => finish(undefined, Buffer.concat(parts, length)));
        response.on('error', () => finish(new HttpFailure('NETWORK_UNAVAILABLE')));
        response.on('aborted', () => finish(new HttpFailure('NETWORK_UNAVAILABLE')));
      });
      void (async () => {
        try {
          for (const chunk of chunks) {
            if (done) return;
            if (!req.write(chunk)) await once(req, 'drain', { signal: pump.signal });
          }
          if (!done) req.end();
        } catch { finish(new HttpFailure('NETWORK_UNAVAILABLE')); }
      })();
    });
  }
}
