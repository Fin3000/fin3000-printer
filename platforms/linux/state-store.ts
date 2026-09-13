/** Linux single-writer lease + inode-pinned, atomic, fsynced metadata storage. */
import { constants } from 'node:fs';
import { lstat, mkdir, open, realpath, rename, unlink } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { isAbsolute, resolve } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { PrinterError } from '../../core/protocol.ts';
import type { SecureStateStore, StateSnapshot } from '../../core/protocol.ts';
import { MAX_STATE_BYTES, validateSnapshot, validateStateRelease } from '../../core/state-store.ts';
import type { StateRelease } from '../../core/state-store.ts';

interface StateActivation {
  version: 1;
  release: StateRelease;
  backup: { file: string; sha256: string } | null;
}

const CHECKPOINT_BYTES = MAX_STATE_BYTES + 8192;
const sameRelease = (left: StateRelease, right: StateRelease): boolean => JSON.stringify(left) === JSON.stringify(right);

export class LinuxStateStore implements SecureStateStore {
  private directory: FileHandle;
  private lease: FileHandle;
  private closed = false;
  private uid: number;

  private constructor(directory: FileHandle, lease: FileHandle, uid: number) {
    this.directory = directory; this.lease = lease; this.uid = uid;
  }

  static async acquire(path: string, inputRelease: StateRelease): Promise<LinuxStateStore> {
    const release = validateStateRelease(inputRelease);
    const uid = process.getuid?.();
    if (process.platform !== 'linux' || uid === undefined || uid === 0 || !isAbsolute(path) || resolve(path) !== path) throw new PrinterError('STATE_PATH_INVALID');
    await mkdir(path, { mode: 0o700 }).catch(error => { if (error.code !== 'EEXIST') throw error; });
    if (await realpath(path) !== path) throw new PrinterError('STATE_PATH_INVALID');
    const directory = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    let lease: FileHandle | undefined;
    try {
      const stat = await directory.stat();
      if (!stat.isDirectory() || stat.uid !== uid || (stat.mode & 0o777) !== 0o700) throw new PrinterError('STATE_PERMISSIONS_INVALID');
      lease = await open(`/proc/self/fd/${directory.fd}/.agent.lock`, constants.O_RDWR | constants.O_CREAT | constants.O_NOFOLLOW, 0o600);
      const lockStat = await lease.stat();
      if (!lockStat.isFile() || lockStat.nlink !== 1 || lockStat.uid !== uid || (lockStat.mode & 0o777) !== 0o600) throw new PrinterError('STATE_PERMISSIONS_INVALID');
      const flock = await lstat('/usr/bin/flock');
      if (!flock.isFile() || flock.uid !== 0 || (flock.mode & 0o022)) throw new PrinterError('STATE_LOCK_UNAVAILABLE');
      // flock's inherited FD shares the open-file description. The lease stays
      // held after the short child exits, until this coordinator closes its FD.
      const result = spawnSync('/usr/bin/flock', ['--exclusive', '--nonblock', '3'], {
        stdio: ['ignore', 'ignore', 'ignore', lease.fd], timeout: 5000,
        env: { PATH: '/usr/bin:/bin', LANG: 'C' },
      });
      if (result.status !== 0 || result.error) throw new PrinterError(result.status === 1 ? 'INSTANCE_ALREADY_RUNNING' : 'STATE_LOCK_UNAVAILABLE');
      const store = new LinuxStateStore(directory, lease, uid);
      await store.prepareRelease(release);
      return store;
    } catch (error) { await lease?.close(); await directory.close(); throw error; }
  }

  private path(name: string): string {
    if (this.closed) throw new PrinterError('STATE_STORE_CLOSED');
    return `/proc/self/fd/${this.directory.fd}/${name}`;
  }

  private async readPrivate(name: string, limit: number): Promise<Buffer | null> {
    let file: FileHandle;
    try { file = await open(this.path(name), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null; throw new PrinterError('STATE_INVALID'); }
    try {
      const stat = await file.stat();
      if (!stat.isFile() || stat.nlink !== 1 || stat.uid !== this.uid || (stat.mode & 0o777) !== 0o600 || stat.size > limit) throw new PrinterError('STATE_INVALID');
      const buffer = Buffer.alloc(stat.size + 1);
      let length = 0;
      while (length < buffer.length) {
        const { bytesRead } = await file.read(buffer, length, buffer.length - length, null);
        if (!bytesRead) break;
        length += bytesRead;
      }
      const data = buffer.subarray(0, length);
      if (data.length !== stat.size || data.length > limit) throw new PrinterError('STATE_INVALID');
      return data;
    } finally { await file.close(); }
  }

  private parse(bytes: Buffer): unknown {
    try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
    catch { throw new PrinterError('STATE_INVALID'); }
  }

  async load(): Promise<StateSnapshot | null> {
    const bytes = await this.readPrivate('state.json', MAX_STATE_BYTES);
    return bytes === null ? null : validateSnapshot(this.parse(bytes));
  }

  private async activation(): Promise<StateActivation | null> {
    const bytes = await this.readPrivate('activation.json', 4096);
    if (bytes === null) return null;
    const value = this.parse(bytes) as StateActivation;
    if (!value || Object.keys(value).sort().join(',') !== 'backup,release,version' || value.version !== 1) throw new PrinterError('STATE_INVALID');
    const release = validateStateRelease(value.release), backup = value.backup;
    if (backup !== null) {
      if (!backup || Object.keys(backup).sort().join(',') !== 'file,sha256' ||
          typeof backup.file !== 'string' || !/^state-before-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\.json$/.test(backup.file) ||
          typeof backup.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(backup.sha256)) throw new PrinterError('STATE_INVALID');
      const checkpoint = await this.readPrivate(backup.file, CHECKPOINT_BYTES);
      if (!checkpoint || createHash('sha256').update(checkpoint).digest('hex') !== backup.sha256) throw new PrinterError('STATE_INVALID');
      const data = this.parse(checkpoint) as { version: number; from: unknown; to: unknown; state: unknown };
      if (!data || Object.keys(data).sort().join(',') !== 'from,state,to,version' || data.version !== 1 ||
          !sameRelease(validateStateRelease(data.to), release) ||
          (data.from !== null && validateStateRelease(data.from).package !== release.package)) throw new PrinterError('STATE_INVALID');
      validateSnapshot(data.state);
    }
    return { version: 1, release, backup };
  }

  private async prepareRelease(release: StateRelease): Promise<void> {
    const state = await this.load(), previous = await this.activation();
    const qa = release.package.endsWith('-qa');
    if ((previous && (state === null || previous.release.package !== release.package)) ||
        state?.jobs.some(row => row.binding.audience !== `fin3000-printer:${qa ? 'qa' : 'production'}`)) throw new PrinterError('STATE_INVALID');
    if (previous && sameRelease(previous.release, release)) return;
    let backup: StateActivation['backup'] = null;
    if (state !== null) {
      const bytes = Buffer.from(JSON.stringify({ version: 1, from: previous?.release ?? null, to: release, state }));
      if (bytes.length > CHECKPOINT_BYTES) throw new PrinterError('STATE_LIMIT_REACHED');
      const name = `state-before-${randomUUID()}.json`;
      // A new exclusive file is never an overwrite or an automatic restore.
      // A crash before activation can leave an unreferenced private checkpoint;
      // retries create a new one and never guess which old file to delete.
      const file = await open(this.path(name), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      try { await file.writeFile(bytes); await file.sync(); } finally { await file.close(); }
      await this.directory.sync();
      const digest = createHash('sha256').update(bytes).digest('hex');
      const verified = await this.readPrivate(name, CHECKPOINT_BYTES);
      if (!verified || createHash('sha256').update(verified).digest('hex') !== digest) throw new PrinterError('STATE_INVALID');
      backup = { file: name, sha256: digest };
    } else {
      // Only a genuinely empty first installation may initialize empty state.
      // Once activation exists, missing state is corruption, not a reset.
      await this.save({ version: 1, jobs: [] });
    }
    await this.writeAtomic('activation.json', Buffer.from(JSON.stringify({ version: 1, release, backup })));
  }

  async save(snapshot: StateSnapshot): Promise<void> {
    const bytes = Buffer.from(JSON.stringify(validateSnapshot(snapshot)));
    if (bytes.length > MAX_STATE_BYTES) throw new PrinterError('STATE_LIMIT_REACHED');
    await this.writeAtomic('state.json', bytes);
  }

  private async writeAtomic(name: 'state.json' | 'activation.json', bytes: Buffer): Promise<void> {
    const existing = await lstat(this.path(name)).catch(error => { if (error.code === 'ENOENT') return null; throw error; });
    if (existing && (!existing.isFile() || existing.nlink !== 1 || existing.uid !== this.uid || (existing.mode & 0o777) !== 0o600)) throw new PrinterError('STATE_INVALID');
    const temporary = `.fin3000-state-${randomUUID()}.tmp`;
    const file = await open(this.path(temporary), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try {
      await file.writeFile(bytes); await file.sync(); await file.close();
      await rename(this.path(temporary), this.path(name));
      await this.directory.sync();
    } catch (error) {
      await file.close().catch(() => {});
      await unlink(this.path(temporary)).catch(() => {});
      throw error;
    }
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true; await this.lease.close(); await this.directory.close();
  }
}
