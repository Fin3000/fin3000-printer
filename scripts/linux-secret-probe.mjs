#!/usr/bin/env node
// G0 fixture only. Never connect to the user's session bus or keyring.
import { spawn, execFile } from 'node:child_process';
import { access, chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { assertProbeHost } from './linux-cups-probe.mjs';
import { parseLinuxRelease } from './preflight.mjs';

const execute = promisify(execFile);
const script = fileURLToPath(import.meta.url);
const fixture = resolve(dirname(script), '../tests/fixtures/linux-secret-probe.js');

export function secretProbeEnvironment(root) {
  if (!/^\/tmp\/fin3000-secret-probe-[A-Za-z0-9]+$/.test(root)) throw new Error('Invalid private secret probe directory');
  return { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8',
    XDG_DATA_HOME: `${root}/data`, XDG_CONFIG_HOME: `${root}/config`,
    XDG_RUNTIME_DIR: `${root}/runtime`, TMPDIR: `${root}/tmp`,
    FIN3000_SECRET_PROBE_ROOT: root };
}

export function assertPrivateChild(root, env) {
  const expected = secretProbeEnvironment(root);
  if (env.DBUS_SESSION_BUS_ADDRESS?.split(',')[0] !== `unix:path=${root}/runtime/bus` || env.DBUS_STARTER_ADDRESS ||
      env.DISPLAY || env.WAYLAND_DISPLAY || env.GNOME_KEYRING_CONTROL ||
      Object.entries(expected).some(([key, value]) => env[key] !== value)) {
    throw new Error('Private D-Bus session and isolated XDG directories required');
  }
}

async function privateChild(root, product = false) {
  assertPrivateChild(root, process.env);
  const info = await stat(root);
  if (info.uid !== process.getuid() || (info.mode & 0o777) !== 0o700) throw new Error('Secret probe directory is not private');
  // dbus-run-session owns the private bus lifetime. This daemon never sees the
  // real desktop bus, display, keyring control socket, or XDG data directory.
  const keyring = spawn('/usr/bin/gnome-keyring-daemon', ['--foreground', '--unlock', '--components=secrets',
    `--control-directory=${root}/runtime/keyring`], { env: process.env, stdio: ['pipe', 'ignore', 'ignore'] });
  const finished = new Promise(resolveExit => {
    keyring.once('error', resolveExit);
    keyring.once('close', resolveExit);
  });
  keyring.stdin.on('error', () => {});
  keyring.stdin.end(randomUUID()); // Disposable nonempty keyring password; never argv/logs.
  const abort = new AbortController();
  const interrupt = () => abort.abort();
  process.once('SIGINT', interrupt);
  process.once('SIGTERM', interrupt);
  try {
    const selected = product ? resolve(dirname(script), '../tests/fixtures/linux-product-secret.js') : fixture;
    const result = await execute('/usr/bin/gjs', product ? ['-m', selected] : [selected], {
      env: process.env, timeout: 12000, maxBuffer: 4096, signal: abort.signal,
    });
    const evidence = JSON.parse(result.stdout);
    if (evidence.stored !== true || evidence.roundTrip !== true || evidence.deleted !== true || evidence.lockedReadDenied !== true) {
      throw new Error('Incomplete native Secret Service evidence');
    }
    if (product && [evidence.productAdapter, evidence.refreshOverwrite, evidence.environmentSeparated, evidence.lockedWriteDenied].some(value => value !== true)) {
      throw new Error('Incomplete product Secret Service evidence');
    }
    process.stdout.write(JSON.stringify(evidence));
  } finally {
    process.removeListener('SIGINT', interrupt);
    process.removeListener('SIGTERM', interrupt);
    if (keyring.exitCode === null && keyring.signalCode === null) keyring.kill('SIGTERM');
    const force = setTimeout(() => keyring.kill('SIGKILL'), 1500);
    try { await finished; } finally { clearTimeout(force); }
  }
}

export async function runSecretProbe(product = false) {
  const release = parseLinuxRelease(await readFile('/etc/os-release', 'utf8'));
  assertProbeHost(process.platform, process.getuid?.(), release);
  for (const command of ['/usr/bin/dbus-run-session', '/usr/bin/gnome-keyring-daemon', '/usr/bin/gjs']) {
    await access(command, constants.X_OK);
  }
  const root = await mkdtemp('/tmp/fin3000-secret-probe-');
  const abort = new AbortController();
  const interrupt = () => abort.abort();
  process.once('SIGINT', interrupt);
  process.once('SIGTERM', interrupt);
  const deadline = setTimeout(interrupt, 18000);
  let child;
  try {
    await chmod(root, 0o700);
    for (const directory of ['data', 'config', 'runtime', 'runtime/keyring', 'tmp']) {
      await mkdir(`${root}/${directory}`, { mode: 0o700 });
    }
    // No autoactivation directories: this bus can only serve explicitly started
    // test processes, never desktop services such as GVfs or a real keyring.
    await writeFile(`${root}/bus.conf`, `<busconfig><type>session</type>
<listen>unix:path=${root}/runtime/bus</listen><auth>EXTERNAL</auth>
<policy context="default"><allow own="*"/><allow send_destination="*"/>
<allow receive_sender="*"/></policy></busconfig>`, { flag: 'wx', mode: 0o600 });
    child = spawn('/usr/bin/dbus-run-session', [`--config-file=${root}/bus.conf`, '--', process.execPath, script, '--private-child', root, ...(product ? ['product'] : [])], {
      env: secretProbeEnvironment(root), detached: true, stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    let stderr = '';
    let force;
    const terminate = () => {
      if (child.pid) {
        try { process.kill(-child.pid, 'SIGTERM'); } catch {}
        force ??= setTimeout(() => { try { process.kill(-child.pid, 'SIGKILL'); } catch {} }, 1500);
      }
    };
    child.stdout.on('data', data => { output += data; if (output.length > 4096) terminate(); });
    child.stderr.on('data', data => { stderr = (stderr + data).slice(-4096); });
    abort.signal.addEventListener('abort', terminate, { once: true });
    let code;
    try {
      if (abort.signal.aborted) terminate();
      code = await new Promise((resolveExit, reject) => {
        child.once('error', reject);
        child.once('close', resolveExit);
      });
    } finally {
      clearTimeout(force);
      abort.signal.removeEventListener('abort', terminate);
    }
    if (code !== 0 || abort.signal.aborted) throw new Error(`Isolated Secret Service probe failed (${code}). ${stderr}`);
    return { schemaVersion: 1, probe: 'linux-private-secret-service', status: 'PASS', ubuntu: release.version,
      ...JSON.parse(output), privateSessionBus: true, disposableKeyring: true,
      hostKeyringChanged: false, uploaded: false, productReady: false, gateStatus: 'BLOCKED' };
  } finally {
    clearTimeout(deadline);
    process.removeListener('SIGINT', interrupt);
    process.removeListener('SIGTERM', interrupt);
    // Dedicated process group only; no shared session/keyring daemon is targeted.
    if (child?.pid) { try { process.kill(-child.pid, 'SIGKILL'); } catch {} }
    await rm(root, { recursive: true, force: true });
  }
}

export async function main(args, io = process, probe = runSecretProbe) {
  if (args.length === 1 && args[0] === '--help') {
    io.stdout.write('Usage: node scripts/linux-secret-probe.mjs --run-synthetic [--product]\nDisposable isolated D-Bus/keyring, synthetic secret only; no desktop keyring access.\n');
    return 0;
  }
  const product = args.length === 2 && args[1] === '--product';
  if ((args.length !== 1 && !product) || args[0] !== '--run-synthetic') {
    io.stderr.write('Explicit --run-synthetic required; no credentials or extra arguments accepted.\n');
    return 2;
  }
  try { io.stdout.write(`${JSON.stringify(await probe(product), null, 2)}\n`); return 0; }
  catch (error) { io.stderr.write(`${error.message}\n`); return 1; }
}

if (process.argv[1] && resolve(process.argv[1]) === script) {
  const args = process.argv.slice(2);
  if ((args.length === 2 || args.length === 3 && args[2] === 'product') && args[0] === '--private-child') {
    try { await privateChild(args[1], args[2] === 'product'); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
  } else process.exitCode = await main(args);
}
