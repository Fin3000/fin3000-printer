import assert from 'node:assert/strict';
import { test } from 'node:test';
import { assertProbeHost, main, probeConfiguration, probeEnvironment, syntheticPdf, verifyPdfEvidence } from '../scripts/linux-cups-probe.mjs';

const root = '/tmp/fin3000-printer-probe-Ab1234';

test('native probe refuses root, unknown UID and unsupported operating systems', () => {
  for (const release of ['24.04', '26.04']) assert.doesNotThrow(() => assertProbeHost('linux', 1000, { id: 'ubuntu', version: release }, 'x64'));
  for (const uid of [0, -1, undefined, NaN]) assert.throws(() => assertProbeHost('linux', uid, { id: 'ubuntu', version: '26.04' }));
  for (const platform of ['win32', 'darwin']) assert.throws(() => assertProbeHost(platform, 1000, { id: 'ubuntu', version: '26.04' }));
  assert.throws(() => assertProbeHost('linux', 1000, { id: 'debian', version: '26.04' }));
  assert.throws(() => assertProbeHost('linux', 1000, { id: 'ubuntu', version: '22.04' }));
  assert.throws(() => assertProbeHost('linux', 1000, { id: 'ubuntu', version: '26.04' }, 'arm64'));
});

test('probe paths reject traversal, whitespace, config injection and broad roots', () => {
  for (const path of ['/', '/tmp', '/home/synthetic-user', root + '/..', root + '\nListen 0.0.0.0:631', root + ' x', 'relative']) {
    assert.throws(() => probeConfiguration(path, 1000, 1000));
    assert.throws(() => probeEnvironment(path));
  }
  assert.throws(() => probeConfiguration(root, 0, 1000));
  assert.throws(() => probeConfiguration(root, 1000, '1000\nUser root'));
});

test('scheduler uses one private Unix socket and no discovery or web interface', () => {
  const config = probeConfiguration(root, 1000, 1000)['conf/cupsd.conf'];
  assert.deepEqual(config.split('\n').filter(line => /^(Listen|Port) /i.test(line)), [`Listen ${root}/state/cups.sock`]);
  for (const directive of ['Browsing No', 'BrowseLocalProtocols none', 'DefaultShared No', 'WebInterface No']) assert.ok(config.includes(directive));
  assert.match(config, /<Location \/admin>\nOrder allow,deny\nDeny all/);
  assert.match(config, /<Limit All>\nOrder allow,deny\nDeny all/);
});

test('all writable CUPS directories, logs and file output stay inside private root', () => {
  const configs = probeConfiguration(root, 1000, 1000);
  const directives = ['ServerRoot', 'StateDir', 'RequestRoot', 'CacheDir', 'TempDir', 'ServerKeychain',
    'ServerBin', 'DataDir', 'DocumentRoot', 'AccessLog', 'ErrorLog', 'PageLog', 'Printcap'];
  for (const key of directives) {
    const value = configs['conf/cups-files.conf'].split('\n').find(line => line.startsWith(key + ' '));
    assert.ok(value?.startsWith(`${key} ${root}/`), `${key} must not fall back to a host directory`);
  }
  assert.match(configs['conf/printers.conf'], /Shared No/);
  assert.ok(configs['conf/printers.conf'].includes(`DeviceURI file://${root}/received.pdf`));
  assert.doesNotMatch(JSON.stringify(configs), /api\.fin3000\.com|https?:|\/etc\/cups|\/run\/cups/);
});

test('child environment is allowlisted, with explicit private CUPS destination', () => {
  const env = probeEnvironment(root);
  assert.equal(env.CUPS_SERVER, root + '/state/cups.sock');
  assert.equal(env.CUPS_SERVERROOT, root + '/conf');
  assert.deepEqual(Object.keys(env).sort(), ['PATH', 'LANG', 'LC_ALL', 'CUPS_SERVER', 'CUPS_SERVERROOT', 'CUPS_ENCRYPTION', 'TMPDIR'].sort());
});

test('synthetic PDF has a correct xref table and no arbitrary document content', () => {
  const pdf = syntheticPdf('synthetic-probe-123').toString('ascii');
  assert.ok(pdf.startsWith('%PDF-1.4\n'));
  assert.ok(pdf.includes('NOT AN INVOICE'));
  assert.ok(pdf.includes('(synthetic-probe-123)'));
  const start = Number(pdf.match(/startxref\n(\d+)\n%%EOF/)[1]);
  assert.equal(pdf.slice(start, start + 4), 'xref');
  const entries = pdf.slice(start).split('\n').slice(3, 8);
  assert.equal(entries.length, 5);
  for (const [i, entry] of entries.entries()) assert.ok(pdf.slice(Number(entry.slice(0, 10))).startsWith(`${i + 1} 0 obj\n`));
  for (const marker of ['', 'x) Tj /JS', 'a'.repeat(81), '/home/synthetic-user/invoice.pdf']) assert.throws(() => syntheticPdf(marker));
});

test('help and invalid arguments never start a daemon or accept user documents', async () => {
  const io = { stdout: { write() {} }, stderr: { write() {} } };
  const forbidden = () => { throw new Error('Probe must not be called'); };
  assert.equal(await main(['--help'], io, forbidden), 0);
  for (const args of [[], ['invoice.pdf'], ['--run-synthetic', 'invoice.pdf'], ['--host', '/run/cups/cups.sock']]) assert.equal(await main(args, io, forbidden), 2);
});

test('a completed queue entry alone cannot pass without exact valid PDF evidence', () => {
  const pdf = syntheticPdf('fixture');
  assert.doesNotThrow(() => verifyPdfEvidence(pdf, pdf, 'fixture', 'Pages: 1\n', 'fixture\n'));
  for (const received of [Buffer.alloc(0), pdf.subarray(0, -1), syntheticPdf('stale-job')]) {
    assert.throws(() => verifyPdfEvidence(pdf, received, 'fixture', 'Pages: 1\n', 'fixture\n'));
  }
  assert.throws(() => verifyPdfEvidence(pdf, pdf, 'fixture', 'Pages: 2\n', 'fixture\n'));
  assert.throws(() => verifyPdfEvidence(pdf, pdf, 'fixture', 'Pages: 1\n', 'old-document\n'));
});

test('CLI distinguishes successful isolated probe from failures', async () => {
  let output = '';
  let error = '';
  const io = { stdout: { write: text => { output += text; } }, stderr: { write: text => { error += text; } } };
  const report = { status: 'PASS', gateStatus: 'BLOCKED', productReady: false, uploaded: false };
  assert.equal(await main(['--run-synthetic'], io, async () => report), 0);
  assert.deepEqual(JSON.parse(output), report);
  assert.equal(await main(['--run-synthetic'], io, async () => { throw new Error('Fixture failure'); }), 1);
  assert.match(error, /Fixture failure/);
});
