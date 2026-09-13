#!/usr/bin/env node
// G0 prerequisite discovery only. No subprocesses, listeners or network calls.
import { constants, accessSync, readFileSync, statSync } from 'node:fs';
import { posix, win32, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const matrix = JSON.parse(readFileSync(new URL('../support-matrix.json', import.meta.url), 'utf8'));
const REPORT_SCHEMA_VERSION = 2;

function isActiveTarget(target) {
  return target !== undefined && target.firstMilestone <= matrix.activeMilestone;
}

export function parseLinuxRelease(text) {
  const result = { id: 'unknown', version: 'unknown' };
  for (const line of text.split('\n')) {
    const match = /^(ID|VERSION_ID)=(?:"([a-zA-Z0-9._-]+)"|([a-zA-Z0-9._-]+))$/.exec(line);
    if (match) result[match[1] === 'ID' ? 'id' : 'version'] = match[2] ?? match[3];
  }
  return result;
}

// Inspect presence on PATH without executing the discovered program. Relative
// PATH entries/current-directory lookup are intentionally not trusted.
function executableExists(candidate, platform) {
  try {
    if (!statSync(candidate).isFile()) return false;
    accessSync(candidate, platform === 'win32' ? constants.F_OK : constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

export function commandOnPath(name, env = process.env, platform = process.platform, inspect = executableExists) {
  const pathKey = platform === 'win32'
    ? Object.keys(env).find(key => key.toLowerCase() === 'path')
    : 'PATH';
  const pathValue = env[pathKey] ?? '';
  const paths = platform === 'win32' ? win32 : posix;
  const separator = paths.delimiter;
  for (const directory of pathValue.split(separator)) {
    if (!paths.isAbsolute(directory)) continue;
    if (inspect(paths.join(directory, name), platform)) return true;
  }
  return false;
}

export function collectHostFacts() {
  let linux = { id: 'unknown', version: 'unknown' };
  if (process.platform === 'linux') {
    try { linux = parseLinuxRelease(readFileSync('/etc/os-release', 'utf8')); } catch { /* unknown stays blocked */ }
  }
  const target = matrix.platforms.find(item => item.runtimePlatform === process.platform);
  return {
    platform: process.platform,
    architecture: process.arch,
    nodeMajor: Number(process.versions.node.split('.')[0]),
    linux,
    tools: Object.fromEntries((isActiveTarget(target) ? target.tools : []).map(name => [name, commandOnPath(name)])),
  };
}

export function buildReport(facts) {
  const target = matrix.platforms.find(item => item.runtimePlatform === facts.platform);
  const supportedCpu = target?.architectures.includes(facts.architecture) ?? false;
  const supportedLinux = facts.platform !== 'linux' ||
    (facts.linux?.id === target?.linuxDistribution && target?.linuxVersions.includes(facts.linux?.version));
  const prerequisites = [];
  if (!target) prerequisites.push('unsupported-platform');
  if (target && !isActiveTarget(target)) prerequisites.push(`platform-deferred-to-v${target.firstMilestone}`);
  if (!supportedCpu) prerequisites.push('unsupported-architecture');
  if (!supportedLinux) prerequisites.push('unsupported-linux-release');
  if (!Number.isInteger(facts.nodeMajor) || facts.nodeMajor < 22) prerequisites.push('node-22-or-newer-required');
  for (const tool of isActiveTarget(target) ? target.tools : []) {
    if (facts.tools?.[tool] !== true) prerequisites.push(`tool-not-on-path:${tool}`);
  }
  // Allowlisted fields only: never return paths, hostname, environment, tokens,
  // username, printer names, certificates or subprocess output.
  const host = {
    platform: target?.id ?? 'unsupported',
    architecture: ['x64', 'arm64'].includes(facts.architecture) ? facts.architecture : 'unsupported',
    nodeMajor: Number.isInteger(facts.nodeMajor) ? facts.nodeMajor : null,
    prerequisiteStatus: prerequisites.length ? 'MISSING' : 'PRESENT_UNVERIFIED',
    prerequisites,
    tools: Object.fromEntries((isActiveTarget(target) ? target.tools : []).map(name => [name, facts.tools?.[name] === true])),
  };
  if (facts.platform === 'linux') {
    host.linuxRelease = supportedLinux ? `Ubuntu ${facts.linux.version} LTS` : 'unsupported-or-unknown';
  }
  const activeTargets = matrix.platforms.filter(isActiveTarget);
  const gates = activeTargets.map(item => ({
    id: item.gate,
    status: 'BLOCKED',
    reason: item.runtimePlatform === facts.platform
      ? 'native-print-security-and-lifecycle-evidence-required'
      : 'native-host-not-inspected',
    missingEvidence: [...item.requiredEvidence],
  }));
  gates.push({
    id: matrix.deliveryGate.id,
    status: 'BLOCKED',
    reason: 'test-hosts-signing-and-license-evidence-required',
    missingEvidence: [...matrix.deliveryGate.requiredEvidence, ...activeTargets.flatMap(item => item.deliveryEvidence)],
  });
  const roadmap = matrix.platforms.filter(item => !isActiveTarget(item)).map(item => ({
    platform: item.id, milestone: item.firstMilestone, status: 'DEFERRED',
  }));
  return { schemaVersion: REPORT_SCHEMA_VERSION, stage: matrix.stage, activeMilestone: matrix.activeMilestone, readOnly: true, productReady: false, host, gates, roadmap };
}

export function main(args, io = process, collect = collectHostFacts) {
  if (args.length === 1 && args[0] === '--help') {
    io.stdout.write('Usage: node scripts/preflight.mjs [--json | --help]\nOffline G0 prerequisites only. No printer or account changes.\nExit 0: help; 2: invalid arguments; 3: native evidence still missing.\n');
    return 0;
  }
  if (args.length > 1 || (args.length === 1 && args[0] !== '--json')) {
    io.stderr.write('Invalid arguments. Use --help.\n');
    return 2;
  }
  const report = buildReport(collect());
  if (args[0] === '--json') {
    io.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    io.stdout.write(`Fin3000 printer V${report.activeMilestone}: G0 prerequisites only, no installed printer\nHost: ${report.host.platform}/${report.host.architecture} — ${report.host.prerequisiteStatus}\n`);
    for (const item of report.host.prerequisites) io.stdout.write(`  ${item}\n`);
    for (const gate of report.gates) io.stdout.write(`${gate.id}: ${gate.status} — ${gate.reason}\n`);
    for (const item of report.roadmap) io.stdout.write(`${item.platform}: DEFERRED to V${item.milestone} — not a V${report.activeMilestone} gate\n`);
    io.stdout.write('Tool presence does not prove native printing, isolation, signing or release readiness.\n');
  }
  return 3;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
