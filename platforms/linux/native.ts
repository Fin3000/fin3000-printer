/** Fixed Linux ingress and Polkit processes; never a general command bridge. */
import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { readFile, realpath, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import type { Readable } from 'node:stream';
import { consumeNativeJobs } from '../../core/native-wire.ts';
import type { NativeAdmission } from '../../core/native-wire.ts';
import type { DesktopNative } from '../../core/desktop.ts';
import { PrinterError, UUID_PATTERN } from '../../core/protocol.ts';
import { assertRootOwned, boundedSetupResult, desktopEnvironment, LinuxAutostart } from './process.ts';

const ROOT = '/usr/lib/fin3000-printer';

async function generation(): Promise<string> {
  const uid = process.getuid!(), path = `/etc/fin3000-printer/installations/${uid}.json`;
  await assertRootOwned(path);
  if ((await stat(path)).size > 4096) throw new PrinterError('INSTALLATION_DRIFT');
  const raw = JSON.parse(await readFile(path, 'utf8')), home = await stat(homedir());
  if (Object.keys(raw).sort().join(',') !== 'generation,homeDevice,homeInode,queue,socketPath,uid,username,version' ||
      raw.version !== 1 || raw.uid !== uid || raw.queue !== `Fin3000-${uid}` ||
      raw.socketPath !== `/run/user/${uid}/fin3000-printer/ingest.sock` ||
      typeof raw.generation !== 'string' || !UUID_PATTERN.test(raw.generation) ||
      raw.homeDevice !== home.dev || raw.homeInode !== home.ino || home.uid !== uid || !home.isDirectory()) throw new PrinterError('INSTALLATION_DRIFT');
  return raw.generation;
}

async function ready(stream: Readable, child: ChildProcess, expected: string): Promise<void> {
  return new Promise((resolve, reject) => {
    let raw = '', done = false;
    const finish = (error?: Error) => {
      if (done) return; done = true; clearTimeout(timer);
      stream.removeListener('data', data); stream.removeListener('error', failed); child.removeListener('exit', failed);
      if (error) reject(error); else resolve();
    };
    const failed = () => finish(new PrinterError('NATIVE_UNAVAILABLE'));
    const data = (bytes: Buffer) => {
      raw += bytes.toString('ascii');
      if (raw.length > 4096) { failed(); return; }
      if (!raw.endsWith('\n')) return;
      try {
        const result = JSON.parse(raw);
        if (Object.keys(result).sort().join(',') !== 'generation,ready' || result.ready !== true || result.generation !== expected) throw new Error();
        finish();
      } catch { failed(); }
    };
    const timer = setTimeout(failed, 10_000); timer.unref();
    stream.on('data', data); stream.on('error', failed); child.on('exit', failed); child.once('error', failed);
  });
}

export class LinuxNative implements DesktopNative {
  private autostart = new LinuxAutostart();
  private child: ChildProcess | null = null;
  private reader: Promise<void> | null = null;
  private admission: NativeAdmission;
  private unavailable: () => void;
  constructor(admission: NativeAdmission, unavailable: () => void) { this.admission = admission; this.unavailable = unavailable; }

  async start(): Promise<void> {
    if (this.child) return;
    const id = await generation(), helper = `${ROOT}/platforms/linux/ingress.py`;
    await this.autostart.requireEnabled();
    const python = await realpath('/usr/bin/python3');
    if (!/^\/usr\/bin\/python3\.\d+$/.test(python)) throw new PrinterError('HELPER_TRUST_INVALID');
    await assertRootOwned(python); await assertRootOwned(helper);
    const launcher = '/usr/bin/fin3000-printer';
    await assertRootOwned(launcher);
    const child = spawn(launcher, ['--ingress'], { cwd: ROOT, env: desktopEnvironment(process.env), stdio: ['pipe', 'pipe', 'ignore', 'pipe'] });
    this.child = child;
    child.stdin!.on('error', () => {});
    const reply = async (frame: Buffer) => {
      if (!child.stdin!.write(frame)) await once(child.stdin!, 'drain');
    };
    this.reader = consumeNativeJobs(child.stdout!, reply, this.admission, id).catch(() => { child.kill('SIGTERM'); });
    child.on('exit', () => {
      if (this.child === child) { this.child = null; this.unavailable(); }
    });
    try { await ready(child.stdio[3] as Readable, child, id); }
    catch (error) { await this.stop(); throw error; }
  }

  async stop(): Promise<void> {
    const child = this.child; this.child = null;
    if (!child) return;
    child.stdin?.end(); child.kill('SIGTERM');
    const exited = once(child, 'exit').catch(() => {});
    const timer = setTimeout(() => child.kill('SIGKILL'), 2000); timer.unref();
    try { if (child.exitCode === null && child.signalCode === null) await exited; await this.reader; }
    finally { clearTimeout(timer); this.reader = null; }
  }

  async setup(action: 'configure' | 'remove'): Promise<void> {
    if (action !== 'configure' && action !== 'remove') throw new PrinterError('COMMAND_INVALID');
    const helper = '/usr/bin/fin3000-printer';
    await assertRootOwned('/usr/bin/pkexec'); await assertRootOwned(helper);
    if (action === 'remove') await this.autostart.set(false);
    else await this.autostart.inspect();
    const child = spawn('/usr/bin/pkexec', [helper, '--setup', action], { cwd: ROOT, env: desktopEnvironment(process.env), stdio: ['ignore', 'pipe', 'ignore'] });
    const { code, raw } = await boundedSetupResult(child);
    if (code === 126 || code === 127) throw new PrinterError('SETUP_CANCELLED');
    let result;
    try { result = JSON.parse(raw); } catch { throw new PrinterError('SETUP_UNAVAILABLE'); }
    if (code !== 0 || result.ok !== true || Object.keys(result).join(',') !== 'ok') {
      const known = ['QUEUE_NAME_OCCUPIED', 'QUEUE_DRIFT', 'INSTALLATION_DRIFT', 'APPARMOR_DRIFT', 'CUPS_POLICY_UNSUPPORTED',
        'APPARMOR_REQUIRED', 'PRINT_JOBS_PENDING', 'OS_UNSUPPORTED', 'DESKTOP_SESSION_REQUIRED', 'REMOVAL_INCOMPLETE'];
      throw new PrinterError(known.includes(result.code) ? result.code : 'SETUP_UNAVAILABLE');
    }
    if (action === 'configure') await this.autostart.set(true);
  }
}
