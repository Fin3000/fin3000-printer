/** Packaged Linux coordinator entry point. Only its owning GTK parent speaks stdio. */
import { randomUUID } from 'node:crypto';
import { fstatSync } from 'node:fs';
import { mkdir, readFile, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { Coordinator } from '../../core/coordinator.ts';
import { validateBuildConfig } from '../../core/config.ts';
import { consumeControls } from '../../core/control-wire.ts';
import { DesktopController } from '../../core/desktop.ts';
import { NativeHttp } from '../../core/http.ts';
import { NativeOAuth } from '../../core/oauth.ts';
import { PinnedReceiptVerifier } from '../../core/receipts.ts';
import { NativeTransfer } from '../../core/transfer.ts';
import { PrinterError } from '../../core/protocol.ts';
import { stateReleaseFromManifest } from '../../core/state-store.ts';
import { LinuxNative } from './native.ts';
import { LinuxSecretStore } from './secret-store.ts';
import { LinuxStateStore } from './state-store.ts';
import { assertRootOwned, desktopEnvironment } from './process.ts';

if (process.env.FIN3000_CORE_GUARD !== '1') process.exit(70);
delete process.env.FIN3000_CORE_GUARD;

const ROOT = '/usr/lib/fin3000-printer';
let desktop: DesktopController | undefined, store: LinuxStateStore | undefined;
let closing = false;
const browserWaiters = new Map<string, { finish: (ok: boolean) => void }>();

function emit(value: unknown): void {
  const data = JSON.stringify(value);
  if (Buffer.byteLength(data) > 256 * 1024 || process.stdout.writableLength > 512 * 1024) throw new PrinterError('UI_UNAVAILABLE');
  process.stdout.write(data + '\n');
}

async function openBrowser(url: string): Promise<void> {
  if (browserWaiters.size >= 2 || url.length > 8192 || closing) throw new PrinterError('BROWSER_UNAVAILABLE');
  await new Promise<void>((resolve, reject) => {
    const requestId = randomUUID();
    const finish = (ok: boolean) => {
      if (!browserWaiters.delete(requestId)) return;
      clearTimeout(timer);
      if (ok) resolve(); else reject(new PrinterError('BROWSER_UNAVAILABLE'));
    };
    const timer = setTimeout(() => finish(false), 15000); timer.unref();
    browserWaiters.set(requestId, { finish });
    try { emit({ type: 'browser', requestId, url }); } catch { finish(false); }
  });
}

async function shutdown(): Promise<void> {
  if (closing) return;
  closing = true;
  for (const pending of browserWaiters.values()) pending.finish(false);
  try { await desktop?.stop(); } finally { await store?.close(); }
}

async function main(): Promise<void> {
  const uid = process.getuid?.();
  if (!uid || uid < 1000 || uid > 60000 || process.argv.length !== 2 ||
      [0, 1].some(fd => { const info = fstatSync(fd); return info.uid !== uid || (!info.isFIFO() && !info.isSocket()); })) throw new PrinterError('INVOCATION_DENIED');
  desktopEnvironment(process.env);
  const configPath = `${ROOT}/build-config.json`;
  await assertRootOwned(configPath);
  if ((await stat(configPath)).size > 64 * 1024) throw new PrinterError('BUILD_CONFIG_INVALID');
  const config = validateBuildConfig(JSON.parse(await readFile(configPath, 'utf8')));
  const manifestPath = `${ROOT}/build-manifest.json`;
  await assertRootOwned(manifestPath);
  if ((await stat(manifestPath)).size > 64 * 1024) throw new PrinterError('BUILD_CONFIG_INVALID');
  const release = stateReleaseFromManifest(JSON.parse(await readFile(manifestPath, 'utf8')), config.environment);
  const clock = { now: () => Date.now() }, verifier = new PinnedReceiptVerifier(config.receiptKeys, clock);
  const stateParent = join(homedir(), '.local', 'state');
  await mkdir(stateParent, { recursive: true, mode: 0o700 });
  store = await LinuxStateStore.acquire(join(stateParent, `fin3000-printer${config.environment === 'qa' ? '-qa' : ''}`), release);
  // Display only the installed, validated identity, never an environment hint
  // or a proposed update. This public metadata performs no network request.
  emit({ type: 'release', version: release.version, sourceCommit: release.sourceCommit });
  const http = new NativeHttp(config);
  const oauth = new NativeOAuth({ config, http, secrets: new LinuxSecretStore(config.environment), browser: { open: openBrowser }, clock });
  const agent = new Coordinator({ store, transfer: new NativeTransfer(http, oauth), verifier, clock });
  const native = new LinuxNative({ admit: (...args) => desktop!.admit(...args) }, () => {
    if (!closing) void desktop?.nativeUnavailable().catch(() => {});
  });
  desktop = new DesktopController({ agent, auth: oauth, native, emit, now: clock.now,
    exportRecovery: (operationId, content) => emit({ type: 'recoveryExport', operationId, content }),
    open: destination => openBrowser(new URL(destination === 'original' ? '/accounting/incoming-invoices/upload'
      : '/accounting/incoming-invoices/print-operations', config.appOrigin).href) });
  await desktop.start();
  let ticking = false;
  const timer = setInterval(() => {
    if (closing || ticking) return;
    ticking = true;
    void desktop!.tick().catch(() => { process.stdin.destroy(); }).finally(() => { ticking = false; });
  }, 1000); timer.unref();
  try {
    await consumeControls(process.stdin, async command => {
      if (closing) return;
      if (command.action === 'browserResult') browserWaiters.get(command.requestId)?.finish(command.ok);
      else await desktop!.command(command);
    });
  } finally { clearInterval(timer); await shutdown(); }
}

process.stdout.on('error', () => { process.stdin.destroy(); });
for (const signal of ['SIGTERM', 'SIGINT'] as const) process.on(signal, () => { process.stdin.destroy(); });
try { await main(); }
catch (error) {
  const code = error instanceof PrinterError ? error.code : 'RUNTIME_UNAVAILABLE';
  try { emit({ type: 'fatal', code }); } catch { /* No error/PDF content in stderr. */ }
  await shutdown().catch(() => {});
  process.exitCode = 1;
}
