#!/usr/bin/env node
// Synthetic CUPS 2.x transport experiment, NOT the production printer adapter.
import { access, chmod, mkdir, mkdtemp, readFile, readdir, readlink, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash, randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { parseLinuxRelease } from './preflight.mjs';

const execute = promisify(execFile);
const QUEUE = 'Fin3000SyntheticProbe';
const COMMANDS = ['/usr/sbin/cupsd', '/usr/bin/lp', '/usr/bin/lpstat', '/usr/bin/pdfinfo', '/usr/bin/pdftotext'];
const HELPERS = ['/usr/lib/cups/daemon/cups-exec', '/usr/lib/cups/filter/gziptoany'];
const hash = bytes => createHash('sha256').update(bytes).digest('hex');

export function assertProbeHost(platform, uid, release, architecture = process.arch) {
  if (platform !== 'linux' || architecture !== 'x64' || !Number.isInteger(uid) || uid <= 0 ||
      release.id !== 'ubuntu' || !['24.04', '26.04'].includes(release.version)) {
    throw new Error('Probe requires an unprivileged user on Ubuntu 24.04/26.04 x64; no sudo.');
  }
}

export function probeConfiguration(root, uid, gid) {
  if (!/^\/tmp\/fin3000-printer-probe-[A-Za-z0-9]+$/.test(root) ||
      !Number.isInteger(uid) || uid <= 0 || !Number.isInteger(gid) || gid < 0) {
    throw new Error('Invalid private probe directory or process identity.');
  }
  return {
    'data/mime/mime.types': 'application/pdf pdf string(0,%PDF)\n',
    'conf/cups-files.conf': `ServerRoot ${root}/conf
StateDir ${root}/state
RequestRoot ${root}/spool
CacheDir ${root}/cache
TempDir ${root}/tmp
ServerKeychain ${root}/ssl
ServerBin ${root}/bin
DataDir ${root}/data
DocumentRoot ${root}/www
AccessLog ${root}/logs/access
ErrorLog ${root}/logs/error
PageLog ${root}/logs/page
Printcap ${root}/printcap
User ${uid}
Group ${gid}
LogFileGroup ${gid}
ConfigFilePerm 0600
LogFilePerm 0600
CreateSelfSignedCerts No
FileDevice Yes
`,
    'conf/cupsd.conf': `Listen ${root}/state/cups.sock
ServerName localhost
Browsing No
BrowseLocalProtocols none
DefaultShared No
WebInterface No
DefaultEncryption Never
LogLevel debug
PreserveJobHistory Yes
PreserveJobFiles No
DirtyCleanInterval 0
MaxJobs 10
MaxRequestSize 1024k
<Location />
Order deny,allow
Allow all
</Location>
<Location /admin>
Order allow,deny
Deny all
</Location>
<Policy default>
<Limit Print-Job Create-Job Send-Document Get-Job-Attributes Get-Jobs Get-Printer-Attributes CUPS-Get-Printers>
Order deny,allow
Allow all
</Limit>
<Limit All>
Order allow,deny
Deny all
</Limit>
</Policy>
`,
    'conf/printers.conf': `<Printer ${QUEUE}>
Info Fin3000 SYNTHETIC ONLY
DeviceURI file://${root}/received.pdf
State Idle
Accepting Yes
Shared No
JobSheets none none
OpPolicy default
ErrorPolicy abort-job
</Printer>
`,
    // Deliberately deprecated file-device/PPD test sink, not a shipped driver.
    // Pass PDF bytes unchanged; this does not prove application PDF rendering.
    [`conf/ppd/${QUEUE}.ppd`]: `*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageVersion: English
*LanguageEncoding: ISOLatin1
*PCFileName: "F3PROBE.PPD"
*Manufacturer: "Fin3000"
*Product: "(Synthetic probe)"
*ModelName: "Fin3000 Synthetic Probe"
*NickName: "Fin3000 Synthetic Probe"
*ShortNickName: "Synthetic Probe"
*PSVersion: "(3010.000) 0"
*LanguageLevel: "3"
*ColorDevice: False
*DefaultColorSpace: Gray
*FileSystem: False
*cupsVersion: 2.0
*cupsManualCopies: True
*cupsFilter2: "application/pdf application/pdf 0 gziptoany"
*OpenUI *PageSize/Media Size: PickOne
*OrderDependency: 10 AnySetup *PageSize
*DefaultPageSize: A4
*PageSize A4/A4: "<</PageSize[595 842]>>setpagedevice"
*CloseUI: *PageSize
*DefaultImageableArea: A4
*ImageableArea A4: "0 0 595 842"
*DefaultPaperDimension: A4
*PaperDimension A4: "595 842"
`,
  };
}

export function syntheticPdf(marker) {
  if (!/^[a-zA-Z0-9-]{1,80}$/.test(marker)) throw new Error('Invalid synthetic marker');
  const stream = `BT /F1 12 Tf 40 790 Td (FIN3000 SYNTHETIC TEST - NOT AN INVOICE) Tj 0 -24 Td (${marker}) Tj ET\n`;
  const objects = ['<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
    `<< /Length ${Buffer.byteLength(stream)} >>\nstream\n${stream}endstream`];
  let pdf = '%PDF-1.4\n';
  const offsets = [0];
  for (const [i, object] of objects.entries()) {
    offsets.push(Buffer.byteLength(pdf));
    pdf += `${i + 1} 0 obj\n${object}\nendobj\n`;
  }
  const start = Buffer.byteLength(pdf);
  pdf += `xref\n0 ${offsets.length}\n0000000000 65535 f \n`;
  for (const offset of offsets.slice(1)) pdf += `${String(offset).padStart(10, '0')} 00000 n \n`;
  pdf += `trailer\n<< /Size ${offsets.length} /Root 1 0 R >>\nstartxref\n${start}\n%%EOF\n`;
  return Buffer.from(pdf);
}

// No inherited credentials, proxy, loader injection or default CUPS destination.
export function probeEnvironment(root) {
  probeConfiguration(root, 1, 1); // Validate the path even when used independently.
  return { PATH: '/usr/bin:/usr/sbin:/bin', LANG: 'C', LC_ALL: 'C',
    CUPS_SERVER: `${root}/state/cups.sock`, CUPS_SERVERROOT: `${root}/conf`,
    CUPS_ENCRYPTION: 'Never', TMPDIR: `${root}/tmp` };
}

async function run(command, args, env, signal) {
  return (await execute(command, args, { env, signal, timeout: 5000, maxBuffer: 128 * 1024 })).stdout;
}

export function verifyPdfEvidence(expected, received, marker, info, text) {
  if (hash(expected) !== hash(received)) throw new Error('Received PDF bytes differ from synthetic input');
  if (!/^Pages:\s+1$/m.test(info) || !text.includes(marker)) throw new Error('PDF content validation failed');
}

async function startScheduler(root, env) {
  const child = spawn(COMMANDS[0], ['-f', '-c', `${root}/conf/cupsd.conf`, '-s', `${root}/conf/cups-files.conf`],
    { env, stdio: 'ignore' });
  const finished = new Promise(resolveExit => {
    child.once('error', () => resolveExit());
    child.once('close', () => resolveExit());
  });
  return { child, finished };
}

async function stopScheduler(scheduler) {
  if (!scheduler) return;
  const { child, finished } = scheduler;
  if (child.exitCode === null && child.signalCode === null && child.pid) {
    child.kill('SIGTERM');
    const forceStop = setTimeout(() => child.kill('SIGKILL'), 2000);
    try { await finished; } finally { clearTimeout(forceStop); }
  } else await finished;
}

async function verifyPrivateSockets(pid, root) {
  const inodes = new Set();
  for (const fd of await readdir(`/proc/${pid}/fd`)) {
    const link = await readlink(`/proc/${pid}/fd/${fd}`).catch(() => '');
    const match = /^socket:\[(\d+)\]$/.exec(link);
    if (match) inodes.add(match[1]);
  }
  for (const family of ['tcp', 'tcp6', 'udp', 'udp6']) {
    const rows = (await readFile(`/proc/${pid}/net/${family}`, 'utf8')).trim().split('\n').slice(1);
    if (rows.some(row => inodes.has(row.trim().split(/\s+/)[9]))) throw new Error('Unexpected IP socket in probe scheduler');
  }
  const unix = (await readFile(`/proc/${pid}/net/unix`, 'utf8')).trim().split('\n').slice(1);
  const listeners = unix.map(row => row.trim().split(/\s+/)).filter(row => inodes.has(row[6]) && row[3] === '00010000');
  if (listeners.length !== 1 || listeners[0][7] !== `${root}/state/cups.sock`) throw new Error('Unexpected Unix listener');
  if (((await stat(root)).mode & 0o777) !== 0o700) throw new Error('Probe root is not private');
}

export async function runSyntheticProbe() {
  const release = parseLinuxRelease(await readFile('/etc/os-release', 'utf8'));
  assertProbeHost(process.platform, process.getuid?.(), release);
  for (const command of [...COMMANDS, ...HELPERS]) await access(command, constants.X_OK);
  // Fixed /tmp base; caller-supplied paths and real documents are not accepted.
  const root = await mkdtemp('/tmp/fin3000-printer-probe-');
  const env = probeEnvironment(root);
  const abort = new AbortController();
  const interrupt = () => abort.abort();
  process.once('SIGINT', interrupt);
  process.once('SIGTERM', interrupt);
  const deadline = setTimeout(interrupt, 30000);
  let scheduler;
  let failure;
  const jobs = [];
  try {
    await chmod(root, 0o700);
    for (const dir of ['conf/ppd', 'state', 'spool', 'cache', 'tmp', 'ssl', 'bin/backend', 'bin/filter', 'bin/notifier', 'data/mime', 'data/banners', 'www', 'logs']) {
      await mkdir(`${root}/${dir}`, { recursive: true, mode: 0o700 });
    }
    for (const [file, content] of Object.entries(probeConfiguration(root, process.getuid(), process.getgid()))) {
      await writeFile(`${root}/${file}`, content, { flag: 'wx', mode: 0o600 });
    }
    await mkdir(`${root}/bin/daemon`, { mode: 0o700 });
    await symlink('/usr/lib/cups/daemon/cups-exec', `${root}/bin/daemon/cups-exec`);
    await symlink('/usr/lib/cups/filter/gziptoany', `${root}/bin/filter/gziptoany`);
    // Ubuntu's patched file backend opens an existing sink with O_EXCL, without
    // O_CREAT. Allocate it ourselves, never relax host CUPS/AppArmor policy.
    await writeFile(`${root}/received.pdf`, '', { flag: 'wx', mode: 0o600 });
    await run(COMMANDS[0], ['-t', '-c', `${root}/conf/cupsd.conf`, '-s', `${root}/conf/cups-files.conf`], env, abort.signal);
    // Two scheduler lifetimes: prove the private queue still receives after restart.
    for (let iteration = 0; iteration < 2; iteration++) {
      scheduler = await startScheduler(root, env);
      let ready = false;
      for (let attempt = 0; attempt < 30; attempt++) {
        if (scheduler.child.exitCode !== null || scheduler.child.signalCode !== null) break;
        try {
          await run(COMMANDS[2], ['-h', env.CUPS_SERVER, '-p', QUEUE], env, abort.signal);
          ready = true;
          break;
        } catch { await delay(100, undefined, { signal: abort.signal }); }
      }
      if (!ready) throw new Error('Private CUPS scheduler did not become ready');
      await verifyPrivateSockets(scheduler.child.pid, root);
      const marker = randomUUID();
      const pdf = syntheticPdf(marker);
      await writeFile(`${root}/synthetic.pdf`, pdf, { mode: 0o600 });
      const submission = await run(COMMANDS[1], ['-h', env.CUPS_SERVER, '-d', QUEUE, '-t', 'SYNTHETIC-NOT-AN-INVOICE',
        '-o', 'document-format=application/pdf', '--', `${root}/synthetic.pdf`], env, abort.signal);
      const job = submission.match(/request id is (Fin3000SyntheticProbe-\d+)/)?.[1];
      if (!job) throw new Error('No synthetic job ID returned');
      let completed = false;
      for (let attempt = 0; attempt < 60; attempt++) {
        const output = await run(COMMANDS[2], ['-h', env.CUPS_SERVER, '-W', 'completed', '-o', QUEUE], env, abort.signal);
        if (output.split('\n').some(line => line.startsWith(`${job} `))) { completed = true; break; }
        await delay(100, undefined, { signal: abort.signal });
      }
      if (!completed) throw new Error('Synthetic job did not finish');
      const received = await readFile(`${root}/received.pdf`);
      const info = await run(COMMANDS[3], [`${root}/received.pdf`], env, abort.signal);
      const text = await run(COMMANDS[4], [`${root}/received.pdf`, '-'], env, abort.signal);
      verifyPdfEvidence(pdf, received, marker, info, text);
      await verifyPrivateSockets(scheduler.child.pid, root);
      jobs.push({ sequence: iteration + 1, bytes: received.length, sha256: hash(received), pages: 1, exactBytes: true });
      await stopScheduler(scheduler);
      scheduler = undefined;
    }
  } catch (error) {
    const log = await readFile(`${root}/logs/error`, 'utf8').catch(() => '');
    failure = new Error(`${error.message}\nPrivate synthetic CUPS log:\n${log.split('\n').filter(line => line.startsWith('E ') || line.includes('[Job ')).slice(-65).join('\n')}`, { cause: error });
  } finally {
    await stopScheduler(scheduler);
    clearTimeout(deadline);
    process.removeListener('SIGINT', interrupt);
    process.removeListener('SIGTERM', interrupt);
    // root is the exact directory allocated above, never a user-provided path.
    await rm(root, { recursive: true, force: true });
  }
  if (failure) throw failure;
  return { schemaVersion: 1, probe: 'linux-cups-synthetic-file-sink', status: 'PASS',
    ubuntu: release.version, jobs, schedulerRestart: true, privateUnixSocketOnly: true,
    cleanupComplete: true, hostPrinterConfigurationChanged: false, uploaded: false,
    productReady: false, gate: 'G0-L', gateStatus: 'BLOCKED',
    notProven: ['production-authenticated-transport', 'foreign-uid-runtime-test',
      'GUI-app-printing-and-Snap', 'both-Ubuntu-releases', 'Secret-Service-and-Polkit', 'installation-and-signing'] };
}

export async function main(args, io = process, probe = runSyntheticProbe) {
  if (args.length === 1 && args[0] === '--help') {
    io.stdout.write('Usage: node scripts/linux-cups-probe.mjs --run-synthetic\nUnprivileged private CUPS test, two synthetic PDFs, no upload or host printer changes.\n');
    return 0;
  }
  if (args.length !== 1 || args[0] !== '--run-synthetic') {
    io.stderr.write('Explicit --run-synthetic required. No input files or extra arguments accepted.\n');
    return 2;
  }
  try { io.stdout.write(`${JSON.stringify(await probe(), null, 2)}\n`); return 0; }
  catch (error) { io.stderr.write(`Synthetic probe failed: ${error.message}\n`); return 1; }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = await main(process.argv.slice(2));
