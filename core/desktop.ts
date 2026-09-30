/** UI orchestration. Only Coordinator can admit, dispatch or settle a document. */
import type { Coordinator } from './coordinator.ts';
import type { Control } from './control-wire.ts';
import type { Binding, JobIdentity, JobRecord } from './protocol.ts';
import { PrinterError } from './protocol.ts';
import { AUTH_RECOVERY_ERRORS } from './retry.ts';
import { recoveryExport } from './recovery-export.ts';

interface AuthPort {
  authorize(signal: AbortSignal): Promise<Binding>;
  restore(signal: AbortSignal): Promise<Binding>;
  disconnect(signal: AbortSignal): Promise<void>;
  lock(): void;
}
export interface DesktopNative {
  start(): Promise<void>;
  stop(): Promise<void>;
  setup(action: 'configure' | 'remove'): Promise<void>;
}
export interface DesktopState {
  type: 'state'; queueReady: boolean; locked: boolean; connected: boolean;
  accountName: string | null; target: string | null; busy: string | null; code: string | null; draining: boolean;
  removalReady: boolean; removed: boolean;
  jobs: Array<Pick<JobRecord, 'operationId' | 'name' | 'size' | 'outcome' | 'receivedAt'> & {
    target: string | null; code: string | null;
  }>;
}
type Agent = Pick<Coordinator, 'start' | 'admit' | 'connect' | 'cancel' | 'reconcile' | 'importReceipt' | 'sessionLocked' | 'drain' | 'tick' | 'snapshot'>;

export class DesktopController {
  private agent: Agent;
  private auth: AuthPort;
  private native: DesktopNative;
  private emit: (state: DesktopState) => void;
  private open: (destination: 'recovery') => Promise<void>;
  private exportRecovery: (operationId: string, content: string) => void;
  private now: () => number;
  private binding: Binding | null = null;
  private locked = true;
  private queueReady = false;
  private draining = false;
  private removalReady = false;
  private removed = false;
  private busy: string | null = null;
  private code: string | null = null;
  private sessionEpoch = 0;
  private authAbort: AbortController | null = null;
  private work = new Set<Promise<void>>();

  constructor(ports: { agent: Agent; auth: AuthPort; native: DesktopNative; emit: (state: DesktopState) => void;
    exportRecovery: (operationId: string, content: string) => void;
    open: (destination: 'recovery') => Promise<void>; now: () => number }) {
    this.agent = ports.agent; this.auth = ports.auth; this.native = ports.native;
    this.emit = ports.emit; this.open = ports.open; this.now = ports.now;
    this.exportRecovery = ports.exportRecovery;
  }

  async start(): Promise<void> {
    await this.agent.start();
    try { await this.native.start(); this.queueReady = true; }
    catch (error) { this.code = error instanceof PrinterError ? error.code : 'SETUP_REQUIRED'; }
    this.publish();
  }

  private publish(): void {
    const rows = this.agent.snapshot(), active = rows.filter(row => !['accepted', 'never_accepted', 'cancelled'].includes(row.outcome));
    const authFailure = rows.find(row => row.outcome === 'uncertain' && row.code && AUTH_RECOVERY_ERRORS.has(row.code));
    if (authFailure && this.binding) { this.binding = null; this.auth.lock(); this.code = authFailure.code!; }
    const history = rows.filter(row => !active.includes(row)).sort((a, b) => b.receivedAt - a.receivedAt).slice(0, 20);
    // No token, receipt, digest, nonce, subject or network/provider response goes to GTK.
    this.emit({ type: 'state', queueReady: this.queueReady, locked: this.locked, connected: this.binding !== null,
      accountName: this.binding?.accountName ?? null,
      target: this.binding?.target.id === null ? null : this.binding?.target.name ?? null, busy: this.busy, code: this.code, draining: this.draining,
      removalReady: this.removalReady, removed: this.removed,
      jobs: [...active, ...history].slice(0, 50).map(row => ({ operationId: row.operationId, name: row.name,
        size: row.size, outcome: row.outcome, receivedAt: row.receivedAt,
        target: row.binding.target.id === null ? null : row.binding.target.name,
        code: row.code ?? null,
      })) });
  }

  private launch(kind: string, action: () => Promise<void>): void {
    if (this.busy) throw new PrinterError('ACTION_IN_PROGRESS');
    this.busy = kind; this.code = null;
    const task = Promise.resolve().then(action).catch(error => {
      this.code = error instanceof PrinterError ? error.code : 'ACTION_FAILED';
    }).finally(() => { this.busy = null; this.work.delete(task); this.publish(); });
    this.work.add(task); this.publish();
  }

  private authenticate(interactive: boolean): void {
    if (this.locked || !this.queueReady || this.draining) throw new PrinterError('CONNECT_NOT_AVAILABLE');
    if (this.agent.snapshot().some(row => ['confirming', 'waiting', 'transferring'].includes(row.outcome))) throw new PrinterError('JOBS_IN_PROGRESS');
    const epoch = this.sessionEpoch;
    this.launch(interactive ? 'login' : 'restore', async () => {
      const abort = new AbortController(); this.authAbort = abort; this.binding = null;
      try {
        const binding = await (interactive ? this.auth.authorize(abort.signal) : this.auth.restore(abort.signal));
        if (this.locked || epoch !== this.sessionEpoch || abort.signal.aborted) throw new PrinterError('SESSION_LOCKED');
        await this.agent.connect(binding); this.binding = binding;
      } finally { if (this.authAbort === abort) this.authAbort = null; }
    });
  }

  async admit(identity: JobIdentity, title: string, bytes: Buffer): Promise<{ operationId: string; replay: boolean }> {
    try {
      if (this.locked || !this.queueReady) throw new PrinterError('CONNECT_AND_REPRINT');
      return await this.agent.admit(identity, title, bytes);
    } catch (error) { this.code = error instanceof PrinterError ? error.code : 'HANDOFF_REJECTED'; throw error; }
    finally { this.publish(); }
  }

  async command(command: Exclude<Control, { action: 'browserResult' }>): Promise<void> {
    try {
      if (command.action === 'session') {
        if (command.locked === this.locked) return;
        this.locked = command.locked; this.sessionEpoch++;
        if (this.locked) {
          this.authAbort?.abort(); this.auth.lock(); this.binding = null;
          await this.agent.sessionLocked();
        } else if (this.queueReady && !this.draining && !this.busy) this.authenticate(false);
        return;
      }
      if (command.action === 'cancelLogin') { this.authAbort?.abort(); return; }
      if (this.locked) throw new PrinterError('SESSION_LOCKED');
      if (this.removed && ['configure', 'connect', 'prepareRemoval', 'remove'].includes(command.action)) throw new PrinterError('REMOVED_RESTART_REQUIRED');
      switch (command.action) {
        case 'connect': this.authenticate(true); break;
        case 'configure':
          if (this.draining || this.agent.snapshot().some(row => ['confirming', 'waiting', 'transferring'].includes(row.outcome))) throw new PrinterError('JOBS_IN_PROGRESS');
          this.launch('setup', async () => {
            this.binding = null; this.auth.lock(); await this.agent.sessionLocked();
            await this.native.stop(); this.queueReady = false;
            await this.native.setup('configure');
            if (this.draining) throw new PrinterError('DRAINING');
            await this.native.start();
            if (!this.draining) this.queueReady = true;
          });
          break;
        case 'reconcile':
          this.launch('reconcile', () => this.agent.reconcile(command.operationId)); break;
        case 'cancel': await this.agent.cancel(command.operationId); break;
        case 'importReceipt': this.launch('importReceipt', () => this.agent.importReceipt(command.operationId, command.receipt)); break;
        case 'exportRecovery': {
          if (this.busy) throw new PrinterError('ACTION_IN_PROGRESS');
          const row = this.agent.snapshot().find(item => item.operationId === command.operationId);
          if (!row) throw new PrinterError('RECOVERY_NOT_AVAILABLE');
          const content = recoveryExport(row);
          this.exportRecovery(row.operationId, content); this.code = null; break;
        }
        case 'openRecovery': await this.open('recovery'); break;
        case 'prepareRemoval':
          this.launch('drain', async () => { this.draining = true; this.binding = null; this.auth.lock();
            await this.native.stop(); this.queueReady = false; await this.agent.drain();
            await this.auth.disconnect(AbortSignal.timeout(60_000)); this.removalReady = true; });
          break;
        case 'remove':
          if (!this.draining) throw new PrinterError('DRAIN_REQUIRED');
          if (!this.removalReady) throw new PrinterError('REVOCATION_PENDING');
          this.launch('remove', async () => { await this.native.setup('remove'); this.removed = true; }); break;
      }
    } catch (error) { this.code = error instanceof PrinterError ? error.code : 'ACTION_FAILED'; }
    finally { this.publish(); }
  }

  async tick(): Promise<void> { await this.agent.tick(); this.publish(); }
  async nativeUnavailable(): Promise<void> {
    this.queueReady = false; this.binding = null; this.code = 'NATIVE_UNAVAILABLE';
    this.auth.lock(); await this.agent.sessionLocked(); this.publish();
  }
  async stop(): Promise<void> {
    this.draining = true; this.locked = true; this.sessionEpoch++; this.authAbort?.abort(); this.auth.lock();
    this.binding = null; this.queueReady = false;
    try { await this.agent.drain(); }
    finally {
      // A pending setup/auth/receipt action can still own asynchronous work.
      // Join it before the runtime releases state; stop ingress last so even
      // setup that crossed native.start() cannot leave a listener behind.
      try { await this.idle(); } finally { await this.native.stop(); }
    }
    this.publish();
  }
  async idle(): Promise<void> { await Promise.all([...this.work]); }
}
