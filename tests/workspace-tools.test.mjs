import assert from 'node:assert/strict';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

function workspaceRoot() {
  let candidate = process.env.FIN3000_WORKSPACE ? resolve(process.env.FIN3000_WORKSPACE) : dirname(fileURLToPath(import.meta.url));
  for (;;) {
    if (existsSync(join(candidate, 'scripts/changed-files.sh')) && existsSync(join(candidate, 'scripts/release.sh'))) return candidate;
    const parent = dirname(candidate);
    if (parent === candidate || process.env.FIN3000_WORKSPACE) throw new Error('Set FIN3000_WORKSPACE to test the real workspace scripts');
    candidate = parent;
  }
}

const source = workspaceRoot();
const repoName = 'tools/fin3000-printer';

function run(cwd, command, args, expected = 0) {
  const result = spawnSync(command, args, { cwd, encoding: 'utf8', timeout: 15000 });
  assert.equal(result.error, undefined);
  assert.equal(result.status, expected, `${command}: ${result.stdout}\n${result.stderr}`);
  return result.stdout;
}

function git(repo, ...args) {
  return run(repo, 'git', ['-c', 'core.hooksPath=/dev/null', '-c', 'user.name=Fin3000 fixture', '-c', 'user.email=fixture@example.invalid', ...args]);
}

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'fin3000-workspace-test-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(join(root, 'scripts'));
  for (const name of ['changed-files.sh', 'release.sh']) copyFileSync(join(source, 'scripts', name), join(root, 'scripts', name));
  return root;
}

function initRepo(root, name, branch = 'main') {
  const repo = join(root, name);
  mkdirSync(repo, { recursive: true });
  git(repo, 'init', '-b', branch);
  return repo;
}

function commitFile(repo, path, content = 'fixture\n') {
  mkdirSync(dirname(join(repo, path)), { recursive: true });
  writeFileSync(join(repo, path), content);
  git(repo, 'add', '--', path);
  git(repo, 'commit', '-m', 'fixture');
}

test('new printer repo is visible even before main has a commit', t => {
  const root = fixture(t);
  const repo = initRepo(root, repoName, 'feature/system-print-to-fin3000');
  commitFile(repo, 'core/fixture.ts');
  const args = [join(root, 'scripts/changed-files.sh'), `${repoName}/core/fixture.ts`];
  assert.match(run(root, 'bash', args, 3), /BELEGT:/);
  assert.match(run(repo, 'bash', args), /FREI:/);
  assert.match(run(root, 'bash', [args[0], `${repoName}:core/fixture.ts`], 3), /BELEGT:/);
});

test('the same branch name in another repository is not mistaken for our work', t => {
  const root = fixture(t);
  const printer = initRepo(root, repoName, 'feature/system-print-to-fin3000');
  commitFile(printer, 'README.md');
  const frontend = initRepo(root, 'frontend', 'feature/system-print-to-fin3000');
  commitFile(frontend, 'src/consent.ts');
  assert.match(run(printer, 'bash', [join(root, 'scripts/changed-files.sh'), 'frontend/src/consent.ts'], 3), /BELEGT:/);
});

test('unborn worktree and nested untracked files are visible, but own files are free', t => {
  const root = fixture(t);
  const repo = initRepo(root, repoName);
  const worktree = join(root, 'workingtree/tools/system-print');
  git(repo, 'worktree', 'add', '--orphan', '-b', 'feature/system-print', worktree);
  mkdirSync(join(worktree, 'core'), { recursive: true });
  writeFileSync(join(worktree, 'core/a.test.mjs'), 'fixture');
  const script = join(root, 'scripts/changed-files.sh');
  assert.match(run(root, 'bash', [script, `${repoName}/core/a.test.mjs`], 3), /BELEGT:/);
  assert.match(run(worktree, 'bash', [script, `${repoName}/core/a.test.mjs`]), /FREI:/);
  assert.match(run(root, 'bash', [script, `${repoName}/core/aXtest.mjs`]), /FREI:/);
  assert.match(run(root, 'bash', [script, `${repoName}/core/a.test`]), /FREI:/);
});

test('multiple branches editing one file still show CONFLICT', t => {
  const root = fixture(t);
  const repo = initRepo(root, repoName);
  commitFile(repo, 'README.md', 'base');
  git(repo, 'switch', '-c', 'feature/a');
  commitFile(repo, 'README.md', 'a');
  git(repo, 'switch', 'main');
  git(repo, 'switch', '-c', 'feature/b');
  commitFile(repo, 'README.md', 'b');
  assert.match(run(root, 'bash', [join(root, 'scripts/changed-files.sh'), `${repoName}/README.md`], 3), /CONFLICT/);
});

function releaseRepo(root, branch = 'feature/release-printer') {
  const repo = initRepo(root, repoName, branch);
  writeFileSync(join(repo, 'package.json'), JSON.stringify({ name: 'fin3000-printer', version: '0.0.0' }, null, 2) + '\n');
  writeFileSync(join(repo, 'package-lock.json'), JSON.stringify({ name: 'fin3000-printer', version: '0.0.0', lockfileVersion: 3, packages: { '': { name: 'fin3000-printer', version: '0.0.0' } } }, null, 2) + '\n');
  writeFileSync(join(repo, 'CHANGELOG.md'), '# Changelog\n\n## [Unreleased]\n\n- Fixture change.\n');
  git(repo, 'add', '--', 'package.json', 'package-lock.json', 'CHANGELOG.md');
  git(repo, 'commit', '-m', 'fixture');
  return repo;
}

test('desktop release updates only its own package/lock/changelog without commit or tag', t => {
  const root = fixture(t);
  const repo = releaseRepo(root);
  const before = git(repo, 'rev-parse', 'HEAD');
  const output = run(root, 'bash', [join(root, 'scripts/release.sh'), 'cut', repo, 'minor']);
  assert.match(output, /fin3000-printer 0\.0\.0 -> 0\.1\.0/);
  const pkg = JSON.parse(readFileSync(join(repo, 'package.json'), 'utf8'));
  const lock = JSON.parse(readFileSync(join(repo, 'package-lock.json'), 'utf8'));
  assert.equal(pkg.version, '0.1.0');
  assert.equal(lock.version, pkg.version);
  assert.equal(lock.packages[''].version, pkg.version);
  assert.match(readFileSync(join(repo, 'CHANGELOG.md'), 'utf8'), /## \[0\.1\.0\]/);
  assert.equal(git(repo, 'rev-parse', 'HEAD'), before);
  assert.equal(git(repo, 'tag', '--list'), '');
});

test('release still rejects main and leaves all files unchanged', t => {
  const root = fixture(t);
  const repo = releaseRepo(root, 'main');
  run(root, 'bash', [join(root, 'scripts/release.sh'), 'cut', repo, 'minor'], 1);
  assert.equal(git(repo, 'status', '--porcelain'), '');
});

test('invalid desktop lockfile fails before changing the changelog', t => {
  const root = fixture(t);
  const repo = releaseRepo(root);
  commitFile(repo, 'package-lock.json', JSON.stringify({ version: '9.9.9', packages: {} }));
  run(root, 'bash', [join(root, 'scripts/release.sh'), 'cut', repo, 'minor'], 1);
  assert.equal(git(repo, 'status', '--porcelain'), '');
});

test('frontend releases retain their existing classification', t => {
  const root = fixture(t);
  const repo = releaseRepo(root);
  commitFile(repo, 'package.json', JSON.stringify({ name: 'Fin3000', version: '0.0.0' }, null, 2) + '\n');
  const output = run(root, 'bash', [join(root, 'scripts/release.sh'), 'cut', repo, 'patch']);
  assert.match(output, /frontend 0\.0\.0 -> 0\.0\.1/);
});
