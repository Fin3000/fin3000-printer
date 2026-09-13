/** Only fixed, root-owned helpers. No shell, search PATH, secrets in args, or inherited injection env. */
import { lstat, realpath } from 'node:fs/promises';
import { dirname, isAbsolute } from 'node:path';
import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { PrinterError } from '../../core/protocol.ts';

/** Timeout must complete even after pkexec becomes root and kill returns EPERM. */
export function boundedSetupResult(child: ChildProcess, timeoutMs = 180_000): Promise<{ code: number | null; raw: string }> {
  return new Promise((resolve, reject) => {
    const parts: Buffer[] = []; let size = 0, done = false;
    const finish = (error?: Error, code: number | null = null) => {
      if (done) return; done = true; clearTimeout(timer);
      const raw = error ? '' : Buffer.concat(parts, size).toString('utf8');
      for (const part of parts) part.fill(0);
      parts.length = 0;
      if (error) {
        // The root journal reconciles an operation that may still finish. Do
        // not await this kill, kill a process group, or claim rollback.
        child.kill('SIGTERM'); child.stdout?.destroy(); child.unref(); reject(error);
      } else resolve({ code, raw });
    };
    const timer = setTimeout(() => finish(new PrinterError('SETUP_UNAVAILABLE')), timeoutMs);
    child.on('error', () => finish(new PrinterError('SETUP_UNAVAILABLE')));
    child.stdout?.on('error', () => finish(new PrinterError('SETUP_UNAVAILABLE')));
    child.stdout?.on('data', (bytes: Buffer) => {
      if (done) return;
      size += bytes.length;
      if (size > 4096) finish(new PrinterError('SETUP_UNAVAILABLE')); else parts.push(bytes);
    });
    child.once('close', code => finish(undefined, code));
  });
}

export function desktopEnvironment(source: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const uid = process.getuid?.();
  if (!uid || source.XDG_RUNTIME_DIR !== `/run/user/${uid}` ||
      source.DBUS_SESSION_BUS_ADDRESS !== `unix:path=/run/user/${uid}/bus`) throw new PrinterError('DESKTOP_SESSION_UNAVAILABLE');
  const result: NodeJS.ProcessEnv = { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8',
    XDG_RUNTIME_DIR: source.XDG_RUNTIME_DIR, DBUS_SESSION_BUS_ADDRESS: source.DBUS_SESSION_BUS_ADDRESS };
  // These are presentation hints, never executable paths/configuration sources.
  for (const key of ['LANG', 'LANGUAGE', 'LC_ALL', 'XDG_SESSION_ID', 'XDG_SESSION_TYPE', 'WAYLAND_DISPLAY', 'DISPLAY']) {
    if (source[key] && source[key]!.length <= 128 && /^[A-Za-z0-9_.:@/-]+$/.test(source[key]!)) result[key] = source[key];
  }
  return result;
}

export async function assertRootOwned(path: string): Promise<void> {
  if (!isAbsolute(path) || await realpath(path) !== path) throw new PrinterError('HELPER_TRUST_INVALID');
  for (let current = path; current !== '/'; current = dirname(current)) {
    const stat = await lstat(current);
    if (stat.uid !== 0 || stat.mode & 0o022 || (current === path ? !stat.isFile() : !stat.isDirectory())) throw new PrinterError('HELPER_TRUST_INVALID');
  }
}

const AUTOSTART_UNIT = 'fin3000-printer.service';
const AUTOSTART_PATH = `/usr/lib/systemd/user/${AUTOSTART_UNIT}`;
const AUTOSTART_PROPERTIES = ['Id', 'LoadState', 'FragmentPath', 'DropInPaths', 'UnitFileState'];

async function userSystemctl(args: string[]): Promise<string> {
  await assertRootOwned('/usr/bin/systemctl');
  const child = spawn('/usr/bin/systemctl', ['--user', '--no-pager', '--no-ask-password', ...args], {
    cwd: '/usr/lib/fin3000-printer', env: desktopEnvironment(process.env), stdio: ['ignore', 'pipe', 'ignore'],
  });
  const result = await boundedSetupResult(child, 15_000);
  if (result.code !== 0) throw new PrinterError('AUTOSTART_UNAVAILABLE');
  return result.raw;
}

/** Only the packaged current-user unit; never unmask, start/stop, or replace overrides. */
export class LinuxAutostart {
  private run: (args: string[]) => Promise<string>;
  private trust: (path: string) => Promise<void>;
  constructor(run: (args: string[]) => Promise<string> = userSystemctl,
    trust: (path: string) => Promise<void> = assertRootOwned) { this.run = run; this.trust = trust; }

  async inspect(): Promise<'enabled' | 'disabled'> {
    try {
      await this.trust(AUTOSTART_PATH);
      const raw = await this.run(['show', '--all', `--property=${AUTOSTART_PROPERTIES.join(',')}`, AUTOSTART_UNIT]);
      if (Buffer.byteLength(raw) > 4096 || !raw.endsWith('\n')) throw new Error();
      const values = new Map<string, string>();
      for (const line of raw.slice(0, -1).split('\n')) {
        const separator = line.indexOf('='), key = line.slice(0, separator), value = line.slice(separator + 1);
        if (separator < 1 || !AUTOSTART_PROPERTIES.includes(key) || values.has(key)) throw new Error();
        values.set(key, value);
      }
      const state = values.get('UnitFileState');
      if (values.size !== AUTOSTART_PROPERTIES.length || values.get('Id') !== AUTOSTART_UNIT ||
          values.get('LoadState') !== 'loaded' || values.get('FragmentPath') !== AUTOSTART_PATH ||
          values.get('DropInPaths') !== '' || !['enabled', 'disabled'].includes(state ?? '')) throw new Error();
      return state as 'enabled' | 'disabled';
    } catch { throw new PrinterError('AUTOSTART_UNAVAILABLE'); }
  }

  async requireEnabled(): Promise<void> {
    if (await this.inspect() !== 'enabled') throw new PrinterError('AUTOSTART_UNAVAILABLE');
  }

  async set(enabled: boolean): Promise<void> {
    try {
      if (typeof enabled !== 'boolean') throw new Error();
      // Read the effective definition before any change. Never repair a mask
      // or a user/admin override implicitly. Enabling without --now preserves
      // the existing GTK singleton; removal must not kill its own parent UI.
      await this.inspect();
      await this.run(['daemon-reload']);
      const wanted = enabled ? 'enabled' : 'disabled';
      if (await this.inspect() !== wanted) await this.run([enabled ? 'enable' : 'disable', AUTOSTART_UNIT]);
      if (await this.inspect() !== wanted) throw new Error();
    } catch { throw new PrinterError('AUTOSTART_UNAVAILABLE'); }
  }
}

export async function secretProcess(request: unknown): Promise<unknown> {
  const executable = '/usr/bin/fin3000-printer', helper = '/usr/lib/fin3000-printer/platforms/linux/secret-store.js';
  await assertRootOwned(executable); await assertRootOwned(helper);
  const env = desktopEnvironment(process.env), input = Buffer.from(JSON.stringify(request));
  if (input.length > 32768) throw new PrinterError('SECRET_REQUEST_INVALID');
  return new Promise((resolve, reject) => {
    const child = spawn(executable, ['--secrets'], { env, cwd: '/usr/lib/fin3000-printer', stdio: ['pipe', 'pipe', 'ignore'] });
    const parts: Buffer[] = []; let size = 0, done = false;
    const finish = (error?: Error, value?: unknown) => {
      if (done) return; done = true; clearTimeout(timeout);
      child.kill('SIGKILL'); for (const part of parts) part.fill(0); input.fill(0);
      if (error) reject(error); else resolve(value);
    };
    const timeout = setTimeout(() => finish(new PrinterError('SECRET_STORE_UNAVAILABLE')), 15000); timeout.unref();
    child.stdin.on('error', () => finish(new PrinterError('SECRET_STORE_UNAVAILABLE')));
    child.on('error', () => finish(new PrinterError('SECRET_STORE_UNAVAILABLE')));
    child.stdout.on('data', bytes => {
      size += bytes.length;
      if (size > 32768) finish(new PrinterError('SECRET_RESPONSE_INVALID')); else parts.push(bytes);
    });
    child.on('close', code => {
      if (done) return;
      try {
        if (code !== 0) throw new Error();
        const data = Buffer.concat(parts, size);
        let value;
        try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data)); }
        finally { data.fill(0); }
        finish(undefined, value);
      } catch { finish(new PrinterError('SECRET_RESPONSE_INVALID')); }
    });
    child.stdin.end(input);
  });
}
