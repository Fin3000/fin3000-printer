#!/usr/bin/env node
// Dedicated ephemeral containers; never use the host CUPS daemon or mounted data.
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const execute = promisify(execFile);
const fixtures = resolve(dirname(fileURLToPath(import.meta.url)), '../tests/fixtures/linux-auth');
export const BASE_IMAGES = Object.freeze({
  '24.04': 'ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517',
  '26.04': 'ubuntu@sha256:2260313b31c8c011cd2eebe728008efac1b3982be73eb71348ea2648d2c0e09b',
});

export function containerArguments(name, image) {
  if (!/^fin3000-g0-auth-[a-f0-9-]{36}$/.test(name) || !/^sha256:[a-f0-9]{64}$/.test(image)) throw new Error('Invalid fixture identity');
  return ['--context', 'default', 'run', '--rm', '--init', '--name', name,
    '--label', `com.fin3000.synthetic-probe=${name}`, '--network', 'none', '--read-only',
    '--pids-limit', '64', '--memory', '256m', '--cpus', '1', '--cap-drop', 'ALL',
    ...['SETUID', 'SETGID', 'CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'KILL'].flatMap(cap => ['--cap-add', cap]),
    '--security-opt', 'no-new-privileges', '--tmpfs', '/tmp:rw,nosuid,nodev,exec,size=32m', image];
}

export async function runAuthProbe(ubuntu) {
  if (!Object.hasOwn(BASE_IMAGES, ubuntu)) throw new Error('Only Ubuntu 24.04/26.04 fixture images are supported');
  // Pin the local default daemon explicitly. Never inherit DOCKER_HOST/context,
  // auth config, proxy, or a production deployment credential from the caller.
  const env = { PATH: '/usr/bin:/usr/local/bin:/bin', LANG: 'C.UTF-8' };
  const context = JSON.parse((await execute('docker', ['context', 'inspect', 'default'], { env, timeout: 5000 })).stdout);
  if (context.length !== 1 || context[0].Endpoints?.docker?.Host !== 'unix:///var/run/docker.sock') {
    throw new Error('Probe requires the local default Docker socket; remote contexts are forbidden');
  }
  const built = await execute('docker', ['--context', 'default', 'build', '--quiet', '--platform', 'linux/amd64',
    '--build-arg', `BASE_IMAGE=${BASE_IMAGES[ubuntu]}`, '--file', `${fixtures}/Dockerfile`, fixtures],
  { env, timeout: 180000, maxBuffer: 8192 });
  const image = built.stdout.trim();
  const name = `fin3000-g0-auth-${randomUUID()}`;
  const args = containerArguments(name, image);
  const abort = new AbortController();
  const interrupt = () => abort.abort();
  process.once('SIGINT', interrupt);
  process.once('SIGTERM', interrupt);
  try {
    const result = await execute('docker', args, { env, timeout: 35000, maxBuffer: 16384, signal: abort.signal });
    const evidence = JSON.parse(result.stdout);
    if (evidence.status !== 'PASS' || evidence.agent?.accepted !== 1 || evidence.agent?.rejected !== 2 ||
        evidence.agent?.peerUid !== 0 || evidence.unauthorizedSubmissions?.length !== 4) throw new Error('Incomplete native evidence');
    return { ...evidence, ubuntu, baseImage: BASE_IMAGES[ubuntu], fixtureImage: image,
      buildNetworkUsed: true, dockerBuildCacheRetained: true, runtimeNetwork: 'none', hostMounts: false };
  } finally {
    process.removeListener('SIGINT', interrupt);
    process.removeListener('SIGTERM', interrupt);
    // Remove only the exact container with our random name AND matching label.
    // No prune, wildcard, volume, or host-directory cleanup.
    try {
      const inspected = JSON.parse((await execute('docker', ['--context', 'default', 'inspect', name], { env, timeout: 5000 })).stdout);
      if (inspected[0]?.Config?.Labels?.['com.fin3000.synthetic-probe'] === name) {
        await execute('docker', ['--context', 'default', 'rm', '--force', name], { env, timeout: 5000 });
      }
    } catch (error) {
      if (!/no such object/i.test(error.stderr ?? '')) throw error;
    }
  }
}

export async function main(args, io = process, probe = runAuthProbe) {
  if (args.length === 1 && args[0] === '--help') {
    io.stdout.write('Usage: node scripts/linux-auth-probe.mjs --run-synthetic --ubuntu=24.04|26.04\nBuilds a public Ubuntu test image; runs synthetic prints in a networkless disposable container. No host mounts or printer changes.\n');
    return 0;
  }
  const ubuntu = args[1]?.replace(/^--ubuntu=/, '');
  if (args.length !== 2 || args[0] !== '--run-synthetic' || args[1] !== `--ubuntu=${ubuntu}` || !Object.hasOwn(BASE_IMAGES, ubuntu)) {
    io.stderr.write('Explicit --run-synthetic and --ubuntu=24.04 or --ubuntu=26.04 required.\n');
    return 2;
  }
  try { io.stdout.write(`${JSON.stringify(await probe(ubuntu), null, 2)}\n`); return 0; }
  catch (error) { io.stderr.write(`Synthetic authorization probe failed: ${error.message}\n`); return 1; }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = await main(process.argv.slice(2));
