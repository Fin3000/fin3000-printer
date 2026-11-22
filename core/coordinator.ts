/** The sole durable-state/queue writer. No PDF bytes are persisted in this store. */
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import {
  PrinterError, jobKey, manifestFingerprint, safeDocumentName, sameBinding, validateBinding, validatePdf,
} from './protocol.ts';
import type { Binding, Clock, JobIdentity, JobRecord, ReceiptVerifier, SecureStateStore, TransferPort } from './protocol.ts';
import { validateSnapshot } from './state-store.ts';
import { AUTH_RECOVERY_ERRORS, recoverySchedule } from './retry.ts';
import { HttpFailure } from './http.ts';

const TRANSFER_BUDGET = 5 * 60_000;
const HISTORY_MAX_AGE = 90 * 24 * 60 * 60_000;
const HISTORY_MAX_ROWS = 100;

export class Coordinator {
  private records: JobRecord[] = [];
  private pdfs = new Map<string, Buffer>();
  private binding: Binding | null = null;
  private serial: Promise<unknown> = Promise.resolve();
  private transfers = new Set<Promise<void>>();
  private active: { id: string; controller: AbortController } | null = null;
  private dispatching = false;
  private draining = false;
  private initialized = false;
  private failed = false;
  private store: SecureStateStore;
  private transfer: TransferPort;
  private verifier: ReceiptVerifier;
  private clock: Clock;
  private random: () => number;

  constructor(ports: { store: SecureStateStore; transfer: TransferPort; verifier: ReceiptVerifier; clock: Clock; random?: () => number }) {
    this.store = ports.store; this.transfer = ports.transfer; this.verifier = ports.verifier; this.clock = ports.clock;
    this.random = ports.random ?? Math.random;
  }

  private mutate<T>(action: () => Promise<T>): Promise<T> {
    const next = this.serial.then(async () => {
      if (this.failed) throw new PrinterError('STATE_STORE_UNAVAILABLE');
      return action();
    });
    this.serial = next.catch(() => {});
    return next;
  }

  private trackTransfer(work: Promise<void>): Promise<void> {
    this.transfers.add(work);
    const finished = () => { this.transfers.delete(work); };
    // Background recovery has no desktop task to join at shutdown. Register
    // both paths without creating an unobserved rejected finally() promise.
    void work.then(finished, finished);
    return work;
  }

  private async persist(): Promise<void> {
    this.pruneHistory();
    try { await this.store.save(structuredClone({ version: 1 as const, jobs: this.records })); }
    catch { this.failed = true; this.active?.controller.abort(); this.releaseAll(); throw new PrinterError('STATE_STORE_UNAVAILABLE'); }
  }

  private release(id: string): void {
    this.pdfs.get(id)?.fill(0);
    this.pdfs.delete(id);
  }
  private releaseAll(): void { for (const id of this.pdfs.keys()) this.release(id); }
  private queued(): JobRecord[] { return this.records.filter(row => row.outcome === 'waiting'); }
  private unclear(): boolean { return this.records.some(row => row.delivery === 'possibly_delivered'); }
  private record(id: string): JobRecord {
    const row = this.records.find(row => row.operationId === id);
    if (!row) throw new PrinterError('OPERATION_UNKNOWN');
    return row;
  }
  private pruneHistory(): void {
    const terminal = this.records
      .filter(row => ['accepted', 'never_accepted', 'cancelled'].includes(row.outcome))
      .sort((a, b) => b.receivedAt - a.receivedAt);
    const retained = new Set(
      terminal
        .filter(row => row.receivedAt >= this.clock.now() - HISTORY_MAX_AGE)
        .slice(0, HISTORY_MAX_ROWS)
        .map(row => row.operationId),
    );
    this.records = this.records.filter(row =>
      !['accepted', 'never_accepted', 'cancelled'].includes(row.outcome) || retained.has(row.operationId));
  }
  private pump(): void {
    if (this.dispatching || this.draining || this.unclear()) return;
    this.dispatching = true;
    const work = this.dispatchNext().finally(() => {
      this.dispatching = false;
      if (!this.draining && !this.unclear() && this.queued().length) this.pump();
    });
    void this.trackTransfer(work).catch(() => {});
  }

  async start(): Promise<void> {
    await this.mutate(async () => {
      if (this.initialized) return;
      let saved;
      try { saved = await this.store.load(); }
      catch { this.failed = true; throw new PrinterError('STATE_STORE_UNAVAILABLE'); }
      if (saved) {
        if (saved.version !== 1 || !Array.isArray(saved.jobs)) throw new PrinterError('STATE_VERSION_UNSUPPORTED');
        this.records = validateSnapshot(saved).jobs;
        for (const row of this.records) {
          if (row.delivery === 'possibly_delivered') {
            row.outcome = 'uncertain'; row.code = 'RECONCILE_REQUIRED';
            row.recovery ??= recoverySchedule(0, this.clock.now(), this.random());
          }
          else if (row.outcome === 'waiting' || row.outcome === 'confirming') { row.outcome = 'cancelled'; row.code = 'REPRINT_AFTER_RESTART'; }
        }
        await this.persist();
      }
      this.initialized = true;
    });
  }

  async connect(binding: Binding): Promise<void> {
    await this.mutate(async () => {
      if (this.draining) throw new PrinterError('DRAINING');
      validateBinding(binding);
      if (this.records.some(row => row.delivery === 'possibly_delivered' && !sameBinding(row.binding, binding))) {
        throw new PrinterError('ORIGINAL_ACCOUNT_REQUIRED');
      }
      if (this.queued().length || this.active) throw new PrinterError('JOBS_IN_PROGRESS');
      // The auth adapter calls this ONLY after token storage and a fresh principal check.
      this.binding = structuredClone(binding);
      for (const row of this.records) if (row.outcome === 'uncertain' && sameBinding(row.binding, binding) && row.code && AUTH_RECOVERY_ERRORS.has(row.code)) row.code = 'RECONCILE_REQUIRED';
    });
  }

  async admit(identity: JobIdentity, title: string, bytes: Buffer): Promise<{ operationId: string; replay: boolean }> {
    const result = await this.mutate(async () => {
      if (!this.initialized) throw new PrinterError('NOT_INITIALIZED');
      const identityKey = jobKey(identity);
      const previous = this.records.find(row => jobKey(row.identity) === identityKey);
      validatePdf(bytes);
      const digest = createHash('sha256').update(bytes).digest('hex');
      if (previous) {
        if (previous.pdfSha256 !== digest) throw new PrinterError('NATIVE_IDENTITY_CONFLICT');
        return { operationId: previous.operationId, replay: true };
      }
      if (!this.binding) throw new PrinterError('CONNECT_AND_REPRINT');
      if (this.draining) throw new PrinterError('DRAINING');
      if (this.records.some(row => row.outcome === 'uncertain')) throw new PrinterError('RECONCILE_REQUIRED');
      if (this.queued().length + (this.active ? 1 : 0) >= 3) throw new PrinterError('QUEUE_FULL');
      const itemId = randomUUID(), operationId = randomUUID(), name = safeDocumentName(title);
      const row: JobRecord = {
        operationId, clientBatchId: randomUUID(), clientItemId: itemId, identity: structuredClone(identity),
        binding: structuredClone(this.binding), name, size: bytes.length,
        requestFingerprint: manifestFingerprint(itemId, name, bytes.length), pdfSha256: digest,
        callbackNonce: randomBytes(32).toString('base64url'), outcome: 'waiting', delivery: 'not_dispatched',
        receivedAt: this.clock.now(), extended: false,
      };
      this.records.push(row);
      this.pdfs.set(operationId, Buffer.from(bytes));
      await this.persist(); // The Linux handoff ACK is allowed only after this succeeds.
      return { operationId, replay: false };
    });
    this.pump();
    return result;
  }

  private async dispatchNext(): Promise<void> {
    let row: JobRecord | undefined, bytes: Buffer | undefined, controller: AbortController | undefined;
    await this.mutate(async () => {
      if (this.active || this.draining || !this.binding || this.unclear()) return;
      const current = this.records.find(candidate =>
        candidate.outcome === 'waiting' && sameBinding(candidate.binding, this.binding!));
      if (!current) return;
      bytes = this.pdfs.get(current.operationId);
      if (!bytes) throw new PrinterError('PDF_UNAVAILABLE');
      current.outcome = 'transferring'; current.delivery = 'possibly_delivered';
      controller = new AbortController(); this.active = { id: current.operationId, controller };
      await this.persist(); // Before even manifest admission: it is already a side effect.
      row = structuredClone(current);
    });
    if (!row || !bytes || !controller) return;
    const timeout = setTimeout(() => controller!.abort(), TRANSFER_BUDGET);
    timeout.unref();
    try {
      const receipt = await this.abortable(this.transfer.send(row!, bytes!, controller!.signal), controller!.signal);
      await this.finish(row.operationId, receipt);
    } catch (error) {
      await this.markUnclear(row.operationId, error);
    } finally { clearTimeout(timeout); }
  }

  private async abortable<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
    let abort: () => void = () => {};
    const stopped = new Promise<never>((_resolve, reject) => {
      abort = () => reject(new PrinterError('REQUEST_ABORTED'));
      if (signal.aborted) abort(); else signal.addEventListener('abort', abort, { once: true });
    });
    try { return await Promise.race([work, stopped]); }
    finally { signal.removeEventListener('abort', abort); }
  }

  private async finish(operationId: string, token: string, imported = false): Promise<void> {
    await this.mutate(async () => {
      const row = this.record(operationId);
      if (imported && (this.active || row.outcome !== 'uncertain')) throw new PrinterError('RECEIPT_NOT_EXPECTED');
      const outcome = this.verifier.verify(token, structuredClone(row));
      row.outcome = outcome; row.delivery = 'settled'; row.receipt = token; delete row.code; delete row.recovery;
      if (this.active?.id === operationId) this.active = null;
      this.release(operationId);
      await this.persist();
    });
  }

  private async markUnclear(operationId: string, error?: unknown): Promise<void> {
    await this.mutate(async () => {
      const row = this.record(operationId);
      if (row.delivery === 'settled') return;
      row.outcome = 'uncertain'; row.code = error instanceof PrinterError && AUTH_RECOVERY_ERRORS.has(error.code) ? error.code : 'RECONCILE_REQUIRED';
      row.recovery = recoverySchedule(row.recovery?.attempt ?? 0, this.clock.now(), this.random(),
        error instanceof HttpFailure ? error.retryAfter : undefined, row.recovery?.notBefore);
      for (const queued of this.queued()) { queued.outcome = 'cancelled'; queued.code = 'REPRINT_AFTER_RECOVERY'; }
      this.releaseAll(); this.active = null;
      await this.persist();
    });
  }

  reconcile(operationId: string, options: { background?: boolean } = {}): Promise<void> {
    return this.trackTransfer(this.recover(operationId, options));
  }

  private async recover(operationId: string, options: { background?: boolean }): Promise<void> {
    let row: JobRecord | undefined;
    const controller = new AbortController();
    await this.mutate(async () => {
      const current = this.record(operationId);
      if (this.active) throw new PrinterError('ACTION_IN_PROGRESS');
      if (current.outcome !== 'uncertain' || !this.binding || !sameBinding(current.binding, this.binding)) throw new PrinterError('ORIGINAL_ACCOUNT_REQUIRED');
      if (this.draining || this.clock.now() < (options.background ? current.recovery?.nextAttemptAt ?? 0 : current.recovery?.notBefore ?? 0)) throw new PrinterError('RETRY_LATER');
      current.recovery = recoverySchedule((current.recovery?.attempt ?? 0) + 1, this.clock.now(), this.random(), 0, current.recovery?.notBefore);
      row = structuredClone(current); this.active = { id: operationId, controller };
      await this.persist(); // Reserve next attempt BEFORE request, including crash/restart.
    });
    const timeout = setTimeout(() => controller.abort(), 60_000); timeout.unref();
    try { await this.finish(operationId, await this.abortable(this.transfer.reconcile(row!, controller.signal), controller.signal)); }
    catch (error) { await this.markUnclear(operationId, error); }
    finally { clearTimeout(timeout); }
  }

  async importReceipt(operationId: string, receipt: string): Promise<void> {
    await this.finish(operationId, receipt, true);
  }

  async cancel(operationId: string): Promise<void> {
    await this.mutate(async () => {
      const row = this.record(operationId);
      if (row.outcome !== 'waiting' || row.delivery !== 'not_dispatched') return;
      row.outcome = 'cancelled'; row.code = 'CANCELLED_BEFORE_SEND';
      this.release(operationId); await this.persist();
    });
    this.pump();
  }

  async tick(): Promise<void> {
    let recovery: string | undefined;
    await this.mutate(async () => {
      if (!this.draining && !this.active && this.binding) recovery = this.records.find(row => row.outcome === 'uncertain' &&
        (!row.code || !AUTH_RECOVERY_ERRORS.has(row.code)) && sameBinding(row.binding, this.binding!) &&
        this.clock.now() >= (row.recovery?.nextAttemptAt ?? Infinity))?.operationId;
    });
    if (recovery) void this.reconcile(recovery, { background: true }).catch(() => {});
    else this.pump();
  }

  async sessionLocked(): Promise<void> {
    await this.mutate(async () => {
      for (const row of this.queued()) { row.outcome = 'cancelled'; row.code = 'SESSION_LOCKED'; this.release(row.operationId); }
      this.active?.controller.abort();
      this.binding = null; await this.persist();
    });
  }

  async drain(): Promise<void> {
    this.draining = true;
    try { await this.sessionLocked(); }
    finally {
      // Stopping transport is not evidence of non-delivery. Its existing
      // completion path must durably settle the receipt or retain uncertainty
      // before the runtime closes the single-writer state lease.
      this.active?.controller.abort();
      await Promise.allSettled([...this.transfers]);
    }
    await this.mutate(async () => {}); // Fence writes and propagate disk failure.
  }

  snapshot(): JobRecord[] { return structuredClone(this.records); }
}
