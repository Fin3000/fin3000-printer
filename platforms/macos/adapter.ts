/** Private child of the signed macOS app. AppKit owns the login Keychain and the CUPS socket. */
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { setTimeout as delay } from 'node:timers/promises';
import { validateBuildConfig } from '../../core/config.ts';
import { Coordinator } from '../../core/coordinator.ts';
import { NativeHttp } from '../../core/http.ts';
import { NativeOAuth } from '../../core/oauth.ts';
import type { DisplayedBinding } from '../../core/oauth.ts';
import { MAX_PDF_BYTES, PrinterError, sameBinding, UUID_PATTERN } from '../../core/protocol.ts';
import type { Outcome, StateSnapshot } from '../../core/protocol.ts';
import { PinnedReceiptVerifier } from '../../core/receipts.ts';
import { validateSnapshot } from '../../core/state-store.ts';
import { NativeTransfer } from '../../core/transfer.ts';

const config = validateBuildConfig(JSON.parse(readFileSync(new URL('../../config.json', import.meta.url), 'utf8')));
const clock = { now: Date.now };
const http = new NativeHttp(config);
const pending = new Map<string, {resolve(value: unknown): void; reject(error: Error): void}>();
const send = (value: object) => process.stdout.write(JSON.stringify(value) + '\n');
function native(action: string, value: unknown = null): Promise<unknown> {
  const id = randomUUID();
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    send({ type: 'request', id, action, value });
  });
}
const oauth = new NativeOAuth({config, http, clock,
  secrets: {
    async load() {
      const value = await native('secretLoad');
      if (value !== null && typeof value !== 'string') throw new PrinterError('SECRET_UNAVAILABLE');
      return value;
    },
    async save(value) { await native('secretSave', value); },
    async clear() { await native('secretClear'); },
  },
  browser: { async open(url) { await native('browser', url); } },
});
let durable = new Map<string, Outcome>();
function remember(snapshot: StateSnapshot) {
  durable = new Map(snapshot.jobs.map(job => [job.operationId, job.outcome]));
}
const transfer = new NativeTransfer(http, oauth);
const agent = new Coordinator({ clock, transfer, verifier: new PinnedReceiptVerifier(config.receiptKeys, clock),
  store: {
    async load() {
      const value = await native('stateLoad');
      if (value === null) return null;
      const snapshot = validateSnapshot(value); remember(snapshot); return snapshot;
    },
    async save(value) { await native('stateSave', value); remember(value); },
  },
});

let principal: DisplayedBinding | null = null, locked = true, generation: string | null = null;
let busy = false, removing = false, errorCode = '', sessionEpoch = 0;
let activeRequests = 0;
let sessionWork: Promise<void> = Promise.resolve();
let authAbort: AbortController | undefined;
let initialized = false, lastState = '';
function status() {
  const active = locked ? null : principal;
  const jobs = active ? agent.snapshot().filter(job => sameBinding(job.binding, active))
    .sort((a, b) => b.receivedAt - a.receivedAt).slice(0, 50)
    .map(({operationId, name, receivedAt, outcome}) => ({operationId, name, receivedAt, outcome})) : [];
  const message = JSON.stringify({type: 'state', locked, busy, connected: !!active, queue: !!generation,
    account: active?.accountName, target: active?.target.name, jobs, code: errorCode});
  if (lastState !== message) { process.stdout.write(message + '\n'); lastState = message; }
}
const code = (err: unknown) => err instanceof PrinterError ? err.code : 'ACTION_FAILED';

async function authenticate(interactive: boolean) {
  if (busy || locked || removing) return;
  busy = true; principal = null; errorCode = ''; status();
  const epoch = sessionEpoch;
  const abort = new AbortController(); authAbort = abort;
  const timer = setTimeout(() => abort.abort(), 300_000);
  try {
    const value = await (interactive ? oauth.authorize(abort.signal) : oauth.restore(abort.signal));
    if (locked || epoch !== sessionEpoch || abort.signal.aborted) throw new PrinterError('SESSION_LOCKED');
    if (!generation) {
      if (!interactive) throw new PrinterError('SETUP_REQUIRED');
      const installed = await native('configure');
      if (typeof installed !== 'string' || !UUID_PATTERN.test(installed)) throw new PrinterError('SETUP_REQUIRED');
      generation = installed;
    }
    if (locked || epoch !== sessionEpoch || abort.signal.aborted) throw new PrinterError('SESSION_LOCKED');
    const {accountName: _name, ...binding} = value;
    await agent.connect(binding);
    if (locked || epoch !== sessionEpoch) { await agent.sessionLocked(); throw new PrinterError('SESSION_LOCKED'); }
    principal = value;
  } catch (error) { errorCode = code(error); oauth.lock(); }
  finally { clearTimeout(timer); authAbort = undefined; busy = false; status(); }
}

async function session(nextLocked: boolean) {
  if (nextLocked === locked) return;
  locked = nextLocked; sessionEpoch++;
  if (locked) {
    principal = null; authAbort?.abort(); oauth.lock(); status();
    sessionWork = agent.sessionLocked();
    await sessionWork;
  } else {
    await sessionWork;
    if (!locked && generation) await authenticate(false);
  }
  status();
}

async function job(msg: Record<string, unknown>) {
  let ok = false;
  activeRequests++;
  try {
    if (locked || !principal || removing || !generation) throw new PrinterError('CONNECT_AND_REPRINT');
    if (msg.generation !== generation || typeof msg.nativeJobUuid !== 'string' || !UUID_PATTERN.test(msg.nativeJobUuid) ||
        typeof msg.title !== 'string' || typeof msg.pdf !== 'string' || msg.pdf.length > 4 * Math.ceil(MAX_PDF_BYTES / 3))
      throw new PrinterError('PDF_INVALID');
    const pdf = Buffer.from(msg.pdf, 'base64');
    let admitted;
    try { admitted = await agent.admit({generation, nativeJobUuid: msg.nativeJobUuid}, msg.title, pdf); }
    finally { pdf.fill(0); }
    // CUPS can release its spool when the signed receipt is durable. An uncertain
    // outcome remains in the manual history and is never sent again automatically.
    const deadline = Date.now() + 310_000;
    do {
      const outcome = durable.get(admitted.operationId);
      if (!outcome || !['waiting', 'confirming', 'transferring'].includes(outcome)) {
        ok = outcome === 'accepted'; break;
      }
      await delay(125);
    } while (Date.now() < deadline);
  } catch (err) { errorCode = code(err); }
  finally { activeRequests--; send({type:'jobResult', id:msg.id, ok}); status(); }
}

async function action(msg: Record<string, unknown>) {
  if (msg.action === 'session' && typeof msg.locked === 'boolean') { await session(msg.locked); return; }
  if (msg.action === 'cancelLogin') { authAbort?.abort(); return; }
  if (locked || busy) return;
  if (msg.action === 'connect') { await authenticate(true); return; }
  if (msg.action === 'history') { await native('browser', config.appOrigin + '/accounting/incoming-invoices/print-operations'); return; }
  if (msg.action === 'reconcile' && typeof msg.operationId === 'string' && principal) {
    const row = agent.snapshot().find(row => row.operationId === msg.operationId && sameBinding(row.binding, principal!));
    if (row?.outcome === 'uncertain') await agent.reconcile(row.operationId);
  }
  if (msg.action === 'remove') {
    const records = agent.snapshot();
    if (records.some(row => row.outcome === 'uncertain')) throw new PrinterError('RECONCILE_REQUIRED');
    if (activeRequests || records.some(row => ['waiting', 'transferring', 'confirming'].includes(row.outcome))) throw new PrinterError('JOBS_IN_PROGRESS');
    busy = true; removing = true; status();
    try {
      // Revocation locks OAuth even if the network is unavailable. Keep the
      // queue and allow another attempt or a fresh login after a failed removal.
      principal = null;
      await oauth.disconnect(AbortSignal.timeout(60_000));
      await native('remove'); generation = null;
      send({type:'removed'});
    } finally { removing = false; busy = false; status(); }
  }
}

const lines = createInterface({input: process.stdin, crlfDelay: Infinity});
lines.on('line', (line: string) => {
  if (line.length > 29_000_000) { process.exit(70); }
  let msg: Record<string, unknown>;
  try { msg = JSON.parse(line); } catch { process.exit(70); }
  if (msg.type === 'reply' && typeof msg.id === 'string') {
    const request = pending.get(msg.id); if (!request) return;
    pending.delete(msg.id);
    if (msg.ok === true) request.resolve(msg.value);
    else request.reject(new PrinterError(typeof msg.code === 'string' ? msg.code : 'NATIVE_UNAVAILABLE'));
  } else if (msg.type === 'start' && !initialized) {
    initialized = true;
    generation = typeof msg.generation === 'string' && UUID_PATTERN.test(msg.generation) ? msg.generation : null;
    void agent.start().then(async () => { await session(msg.locked !== false); status(); }).catch(() => {
      send({type:'fatal', code:'STATE_STORE_UNAVAILABLE'}); process.exitCode = 70; lines.close();
    });
  } else if (initialized && msg.type === 'job') void job(msg);
  else if (initialized && msg.type === 'control') void action(msg).catch(err => { errorCode = code(err); status(); });
});
let ticking = false;
const timer = setInterval(async () => {
  if (!initialized || ticking || removing) return;
  ticking = true;
  try { await agent.tick(); status(); } catch (err) { errorCode = code(err); status(); }
  finally { ticking = false; }
}, 1000);
timer.unref();
lines.on('close', () => { clearInterval(timer); oauth.lock(); process.exit(process.exitCode || 0); });
