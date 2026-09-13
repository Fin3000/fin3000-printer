import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { buildReport, commandOnPath, main, matrix, parseLinuxRelease } from '../scripts/preflight.mjs';

function factsFor(target, architecture = target.architectures[0]) {
  return {
    platform: target.runtimePlatform, architecture, nodeMajor: 22,
    linux: { id: 'ubuntu', version: '26.04' },
    tools: Object.fromEntries(target.tools.map(name => [name, true])),
  };
}

test('V1 requires two Ubuntu x64 targets; Windows V2 and macOS V3 stay on the roadmap', () => {
  assert.equal(matrix.schemaVersion, 2);
  assert.equal(matrix.activeMilestone, 1);
  assert.deepEqual(matrix.platforms.map(p => [p.id, p.firstMilestone]), [['windows', 2], ['macos', 3], ['linux', 1]]);
  const active = matrix.platforms.filter(p => p.firstMilestone <= matrix.activeMilestone);
  assert.deepEqual(active.map(p => p.id), ['linux']);
  assert.deepEqual(active[0].operatingSystems, ['Ubuntu 24.04 LTS', 'Ubuntu 26.04 LTS']);
  assert.deepEqual(active[0].architectures, ['x64']);
  assert.equal(active.reduce((n, p) => n + p.operatingSystems.length * p.architectures.length, 0), 2);
});

test('Linux probes target the adopted CUPS Unix transport, not an extra IPP server', () => {
  const linux = matrix.platforms.find(p => p.id === 'linux');
  assert.ok(linux.requiredEvidence.includes('authenticated-cups-unix-transport'));
  for (const tool of ['gcc', 'apparmor_parser', 'lpadmin', 'python3', 'gjs', 'setfacl', 'gpgv'])
    assert.ok(linux.tools.includes(tool));
  for (const tool of ['ippeveprinter', 'ipptool']) assert.ok(!linux.tools.includes(tool));
});

for (const target of matrix.platforms.filter(p => p.firstMilestone <= matrix.activeMilestone)) {
  for (const architecture of target.architectures) {
    test(`${target.id}/${architecture}: all tools present never passes any G0 gate`, () => {
      const report = buildReport(factsFor(target, architecture));
      assert.equal(report.host.prerequisiteStatus, 'PRESENT_UNVERIFIED');
      assert.equal(report.productReady, false);
      assert.deepEqual(report.gates.map(g => g.id), ['G0-L', 'G0-D']);
      assert.ok(report.gates.every(gate => gate.status === 'BLOCKED' && gate.missingEvidence.length > 0));
      assert.equal(report.gates.find(g => g.id === target.gate).reason, 'native-print-security-and-lifecycle-evidence-required');
    });
  }
  test(`${target.id}: a missing build tool is reported separately from native evidence`, () => {
    const facts = factsFor(target);
    delete facts.tools[target.tools[0]];
    const report = buildReport(facts);
    assert.equal(report.host.prerequisiteStatus, 'MISSING');
    assert.ok(report.host.prerequisites.includes(`tool-not-on-path:${target.tools[0]}`));
  });
}

for (const target of matrix.platforms.filter(p => p.firstMilestone > matrix.activeMilestone)) {
  for (const architecture of target.architectures) {
    test(`${target.id}/${architecture}: deferred platforms never imply support or add a V1 gate`, () => {
      const report = buildReport(factsFor(target, architecture));
      assert.equal(report.host.prerequisiteStatus, 'MISSING');
      assert.deepEqual(report.host.prerequisites, [`platform-deferred-to-v${target.firstMilestone}`]);
      assert.deepEqual(report.host.tools, {});
      assert.deepEqual(report.gates.map(g => g.id), ['G0-L', 'G0-D']);
      assert.equal(report.gates[0].reason, 'native-host-not-inspected');
      assert.equal(report.productReady, false);
      assert.ok(report.gates.every(g => g.status === 'BLOCKED'));
    });
  }
}

test('Ubuntu delivery requires only current-platform evidence, not Windows or Apple signing', () => {
  const report = buildReport(factsFor(matrix.platforms.find(p => p.id === 'linux')));
  assert.equal(report.activeMilestone, 1);
  assert.equal(report.schemaVersion, 2);
  assert.deepEqual(report.gates[1].missingEvidence, ['release-native-os-cpu-test-hosts', 'licenses-and-sbom', 'linux-signing-trust']);
  assert.deepEqual(report.roadmap, [
    { platform: 'windows', milestone: 2, status: 'DEFERRED' },
    { platform: 'macos', milestone: 3, status: 'DEFERRED' },
  ]);
});

test('both planned Ubuntu versions still require real native evidence', () => {
  const target = matrix.platforms.find(p => p.id === 'linux');
  for (const version of ['24.04', '26.04']) {
    const report = buildReport({ ...factsFor(target), linux: { id: 'ubuntu', version } });
    assert.equal(report.host.prerequisiteStatus, 'PRESENT_UNVERIFIED');
    assert.equal(report.productReady, false);
    assert.ok(report.gates.every(g => g.status === 'BLOCKED'));
  }
});

test('later milestones retain earlier platforms and never infer native readiness', () => {
  const original = matrix.activeMilestone;
  try {
    matrix.activeMilestone = 2;
    let report = buildReport(factsFor(matrix.platforms.find(p => p.id === 'linux')));
    assert.deepEqual(report.gates.map(g => g.id), ['G0-W', 'G0-L', 'G0-D']);
    assert.deepEqual(report.roadmap, [{ platform: 'macos', milestone: 3, status: 'DEFERRED' }]);
    assert.ok(report.gates.at(-1).missingEvidence.includes('windows-publisher-and-trust'));
    assert.ok(report.gates.at(-1).missingEvidence.includes('linux-signing-trust'));
    assert.ok(!report.gates.at(-1).missingEvidence.includes('apple-team-and-notarization'));
    matrix.activeMilestone = 3;
    report = buildReport(factsFor(matrix.platforms.find(p => p.id === 'linux')));
    assert.deepEqual(report.gates.map(g => g.id), ['G0-W', 'G0-M', 'G0-L', 'G0-D']);
    assert.deepEqual(report.roadmap, []);
    assert.ok(report.gates.at(-1).missingEvidence.includes('apple-team-and-notarization'));
    assert.ok(report.gates.every(g => g.status === 'BLOCKED'));
    assert.equal(report.productReady, false);
  } finally {
    matrix.activeMilestone = original;
  }
});

test('unknown OS, architecture and runtime fail closed', () => {
  const report = buildReport({ platform: 'freebsd', architecture: 'riscv64', nodeMajor: 20 });
  assert.equal(report.host.prerequisiteStatus, 'MISSING');
  assert.deepEqual(report.host.prerequisites, ['unsupported-platform', 'unsupported-architecture', 'node-22-or-newer-required']);
  assert.ok(report.gates.every(g => g.status === 'BLOCKED'));
});

test('unsupported/missing Linux distribution and version do not imply Ubuntu support', () => {
  const target = matrix.platforms[2];
  for (const linux of [undefined, { id: 'ubuntu', version: '22.04' }, { id: 'debian', version: '26.04' }]) {
    const report = buildReport({ ...factsFor(target), linux });
    assert.ok(report.host.prerequisites.includes('unsupported-linux-release'));
  }
});

test('OS release parser never evaluates shell or accepts arbitrary metadata', () => {
  assert.deepEqual(parseLinuxRelease('ID=ubuntu\nVERSION_ID="26.04"\n'), { id: 'ubuntu', version: '26.04' });
  assert.deepEqual(parseLinuxRelease('ID="$(touch stolen)"\nVERSION_ID="26.04;sh"\nPRETTY_NAME=secret'), { id: 'unknown', version: 'unknown' });
});

test('diagnostics allowlist excludes extra secrets, paths and tool output', () => {
  const facts = { ...factsFor(matrix.platforms[0]), hostname: 'SECRET_HOST', token: 'SECRET_TOKEN', home: '/SECRET_HOME' };
  facts.tools.extra = 'SECRET_TOOL_OUTPUT';
  assert.doesNotMatch(JSON.stringify(buildReport(facts)), /SECRET/);
});

test('command discovery does not execute files or accept directories/relative PATH entries', t => {
  const root = mkdtempSync(join(tmpdir(), 'fin3000-preflight-test-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const file = join(root, 'probe');
  writeFileSync(file, 'not executable source: must never be run');
  chmodSync(file, 0o600);
  // Windows ACLs do not implement POSIX executable bits.
  if (process.platform !== 'win32') assert.equal(commandOnPath('probe', { PATH: root }), false);
  chmodSync(file, 0o700);
  assert.equal(commandOnPath('probe', { PATH: root }), true);
  mkdirSync(join(root, 'directory'));
  assert.equal(commandOnPath('directory', { PATH: root }), false);
  assert.equal(commandOnPath('probe', { PATH: '.:relative' }, 'linux'), false);
  assert.equal(commandOnPath('absent', { PATH: root }), false);
});

test('Windows PATH uses semicolons and case-insensitive environment keys without execution', () => {
  const visited = [];
  const inspect = (file, platform) => {
    assert.equal(platform, 'win32');
    visited.push(file);
    return file === 'C:\\SDK tools\\cl.exe';
  };
  assert.equal(commandOnPath('cl.exe', { pAtH: '.;relative;C:\\missing;C:\\SDK tools' }, 'win32', inspect), true);
  assert.deepEqual(visited, ['C:\\missing\\cl.exe', 'C:\\SDK tools\\cl.exe']);
});

test('macOS PATH uses colons and does not invent tools absent from the GUI environment', () => {
  const inspected = [];
  assert.equal(commandOnPath('xcodebuild', { PATH: 'relative:/usr/bin:/opt/homebrew/bin' }, 'darwin', file => {
    inspected.push(file);
    return false;
  }), false);
  assert.deepEqual(inspected, ['/usr/bin/xcodebuild', '/opt/homebrew/bin/xcodebuild']);
});

test('CLI help/invalid flags never collect host data', () => {
  const io = { stdout: { write() {} }, stderr: { write() {} } };
  const collect = () => { throw new Error('must not collect'); };
  assert.equal(main(['--help'], io, collect), 0);
  for (const args of [['--install'], ['--pass'], ['--json', '--json'], ['--host', 'windows'], ['--milestone', '2']]) {
    assert.equal(main(args, io, collect), 2);
  }
});

test('JSON and human CLI output return blocked, not success', () => {
  for (const args of [[], ['--json']]) {
    let output = '';
    const io = { stdout: { write(text) { output += text; } }, stderr: { write() {} } };
    assert.equal(main(args, io, () => factsFor(matrix.platforms[2])), 3);
    if (args.length) {
      assert.equal(JSON.parse(output).productReady, false);
      assert.equal(JSON.parse(output).activeMilestone, 1);
    } else {
      assert.match(output, /G0-L: BLOCKED/);
      assert.match(output, /windows: DEFERRED to V2/);
      assert.match(output, /macos: DEFERRED to V3/);
      assert.doesNotMatch(output, /G0-[WM]:/);
    }
  }
});
