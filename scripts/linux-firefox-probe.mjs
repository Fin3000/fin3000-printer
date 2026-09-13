/** Explicit native Firefox Snap print-dialog probe. No extension, login or upload. */
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { fileURLToPath } from 'node:url';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { FirefoxProbeDriver } from './firefox-probe-driver.mjs';

export const QUEUE = 'Fin3000NativeSyntheticProbe';
export const MARKER = 'FIN3000 SYNTHETIC ONLY - NOT AN INVOICE';
export const FIREFOX_RUNNER_URL = new URL('./firefox-probe-driver.mjs', import.meta.url);
const root = fileURLToPath(new URL('../', import.meta.url));
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
export function sessionEnvironment(source) {
  const environment = {};
  for (const key of ['PATH', 'HOME', 'USER', 'LOGNAME', 'LANG', 'LC_ALL', 'DISPLAY',
    'XDG_RUNTIME_DIR', 'WAYLAND_DISPLAY', 'DBUS_SESSION_BUS_ADDRESS', 'XDG_CURRENT_DESKTOP']) {
    if (typeof source[key] === 'string') environment[key] = source[key];
  }
  environment.MOZ_ENABLE_WAYLAND = '1';
  return environment;
}
export const fixtureUrl = 'data:text/html;charset=utf-8,' + encodeURIComponent(
  '<!doctype html><meta charset="utf-8"><title>Fin3000 synthetic printer QA</title>' +
  '<style>@page{size:A4;margin:20mm}body{font:12pt sans-serif}</style><p>' + MARKER + '</p>');

export function requireNativeSession(session) {
  if (session.windowProtocol !== 'wayland' || !session.executable.startsWith('/snap/firefox/'))
    throw new Error('Requires actual Firefox Snap on Wayland, not a headless/X11 approximation');
}

// Firefox's built-in print preview lives in a privileged Firefox document.
// This is not a Chrome browser API and never accesses Chrome's profile.
const dialog = `const dialog = PrintUtils.getTabDialogBox(gBrowser.selectedBrowser)
  .getTabDialogManager().dialogs.find(d => d._frame?.contentDocument?.querySelector('#printer-picker'));
  const doc = dialog?._frame.contentDocument;`;

export function selectQueueScript() {
  return dialog + `
    if (!doc) return false;
    const picker = doc.querySelector('#printer-picker');
    if (![...picker.options].some(o => o.value === ${JSON.stringify(QUEUE)})) return false;
    picker.value = ${JSON.stringify(QUEUE)};
    picker.dispatchEvent(new doc.defaultView.Event('input', {bubbles:true}));
    return true;`;
}

export function submitScript() {
  return dialog + `
    if (!doc || doc.querySelector('#printer-picker').value !== ${JSON.stringify(QUEUE)})
      throw new Error('Refusing to print to any other destination');
    const handler = doc.defaultView.PrintEventHandler;
    if (handler?.settings?.printerName !== ${JSON.stringify(QUEUE)} || handler.printForm.printerChanging)
      return false;
    const button = doc.querySelector('#print-button');
    if (!button || button.disabled) return false;
    button.click();
    return true;`;
}

async function freePort() {
  const server = createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

function nativeReceiver() {
  const child = spawn('/usr/bin/pkexec', ['--disable-internal-agent', '/usr/bin/python3', '-I',
    path.join(root, 'scripts/linux-native-probe.py'), '--await-firefox-synthetic'],
  { stdio: ['ignore', 'pipe', 'pipe'], env: sessionEnvironment(process.env) });
  const state = { ready: false, report: null, exited: false, error: '', code: null };
  let pending = '';
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', data => { state.error = (state.error + data).slice(-4096); });
  child.stdout.on('data', data => {
    pending += data;
    if (pending.length > 16384) { state.error = 'Oversized native status'; pending = ''; }
    const lines = pending.split('\n');
    pending = lines.pop();
    for (const line of lines) {
      try {
        const message = JSON.parse(line);
        if (message.status === 'READY_FOR_FIREFOX' && message.queue === QUEUE) state.ready = true;
        else if (message.status === 'PASS') state.report = message;
      } catch { state.error = 'Invalid native status'; }
    }
  });
  child.on('error', error => { state.error = error.message; state.exited = true; });
  child.on('exit', code => { state.exited = true; state.code = code; });
  return state;
}

async function waitReceiver(receiver, condition, timeout, signal) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    signal.throwIfAborted();
    if (condition()) return;
    if (receiver.exited) throw new Error('Native receiver failed: ' + receiver.error);
    await pause(200);
  }
  throw new Error('Native receiver timed out; its bounded elevated process performs its own cleanup');
}

export async function runSynthetic() {
  if (process.platform !== 'linux' || process.getuid() === 0 || !process.env.WAYLAND_DISPLAY)
    throw new Error('Start as the ordinary user in the authorized GNOME/Wayland desktop session');
  const release = await readFile('/etc/os-release', 'utf8');
  if (!/^ID=ubuntu$/m.test(release) || !/^VERSION_ID="(24\.04|26\.04)"$/m.test(release))
    throw new Error('Only the authorized Ubuntu 24.04/26.04 test hosts are in scope');
  if (process.env.FIN3000_FIREFOX)
    throw new Error('Custom Firefox binaries are not allowed in the native Snap probe');
  const port = await freePort();
  const driver = spawn('/snap/bin/geckodriver', ['--port', String(port), '--host', '127.0.0.1',
    '--log', 'error', '--allow-system-access'],
  { stdio: 'ignore', env: sessionEnvironment(process.env) });
  let driverError;
  driver.on('error', error => { driverError = error; });
  const runner = new FirefoxProbeDriver(port);
  const abort = new AbortController();
  const interrupt = () => abort.abort(new Error('Firefox probe interrupted'));
  process.once('SIGINT', interrupt);
  process.once('SIGTERM', interrupt);
  let receiver;
  let stage = 'firefox-start';
  try {
    await runner.wait(async () => {
      try { return (await fetch(runner.base + '/status', {signal: AbortSignal.timeout(1000)})).ok; }
      catch { return false; }
    }, 20_000, { signal: abort.signal, fatal: () => driverError });
    await runner.start();
    abort.signal.throwIfAborted();
    await runner.call('POST', '/url', { url: fixtureUrl });
    await runner.chrome();
    const session = await runner.script(`return {
      windowProtocol: Cc['@mozilla.org/gfx/info;1'].getService(Ci.nsIGfxInfo).windowProtocol,
      executable: Services.dirsvc.get('XREExeF', Ci.nsIFile).path
    };`);
    requireNativeSession(session);
    await runner.script(`for (const name of ['headerleft','headercenter','headerright','footerleft','footercenter','footerright'])
      Services.prefs.setStringPref('print.print_' + name, '');
      Services.prefs.setBoolPref('print.always_print_silent', false);
      Services.prefs.setBoolPref('print.prefer_system_dialog', false);`);
    console.log(JSON.stringify({ status: 'FIREFOX_READY', version: runner.version, ...session }));
    stage = 'native-receiver-start';
    abort.signal.throwIfAborted();
    receiver = nativeReceiver();
    await waitReceiver(receiver, () => receiver.ready, 120_000, abort.signal);
    stage = 'select-test-queue';
    await runner.script('PrintUtils.startPrintWindow(gBrowser.selectedBrowser.browsingContext); return true;');
    await runner.wait(() => runner.script(selectQueueScript()), 20_000, { signal: abort.signal });
    abort.signal.throwIfAborted();
    stage = 'submit-test-print';
    await runner.wait(() => runner.script(submitScript()), 20_000, { signal: abort.signal });
    stage = 'receive-pdf';
    await waitReceiver(receiver, () => receiver.exited && receiver.code === 0 && receiver.report, 135_000, abort.signal);
    const report = { ...receiver.report, firefoxVersion: runner.version, ...session,
      firefoxPrintDialogTested: true, nativeSystemDialogTested: false, saveAsUsed: false,
      extensionInstalled: false, productReady: false, uploaded: false };
    console.log(JSON.stringify(report));
    return report;
  } catch (error) {
    const state = await runner.script(dialog + `return doc ? {
      destinations:[...doc.querySelector('#printer-picker').options].map(o=>o.value),
      selected:doc.querySelector('#printer-picker').value,
      active:doc.defaultView.PrintEventHandler?.settings?.printerName,
      changing:doc.defaultView.PrintEventHandler?.printForm?.printerChanging,
      printDisabled:doc.querySelector('#print-button')?.disabled,
      visibleErrors:[...doc.querySelectorAll('[role=alert]')].filter(e=>e.checkVisibility()).map(e=>e.textContent.slice(0,300))
    } : null;`).catch(() => null);
    console.error(JSON.stringify({stage, printDialog:state}));
    throw error;
  } finally {
    await runner.close();
    if (driver.exitCode === null && driver.signalCode === null) driver.kill('SIGTERM');
    process.removeListener('SIGINT', interrupt);
    process.removeListener('SIGTERM', interrupt);
    // The unprivileged orchestrator cannot signal an elevated pkexec process.
    // Its receiver expires after 120 seconds and restores the exact test queue.
    if (receiver && !receiver.exited)
      console.error('Native receiver still has its bounded cleanup timer; do not start another probe yet.');
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3 || process.argv[2] !== '--run-synthetic') {
    console.error('Explicit authorized host test: node scripts/linux-firefox-probe.mjs --run-synthetic');
    process.exitCode = 2;
  } else {
    await runSynthetic().catch(error => {
      console.error(error.message, error.webdriverMessage || '');
      process.exitCode = 1;
    });
  }
}
