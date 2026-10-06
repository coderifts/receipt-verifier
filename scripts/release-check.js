#!/usr/bin/env node
'use strict';

/**
 * Release check for @coderifts/receipt-verifier (T18, 2026-10-06). Run before every publish:
 *
 *   node scripts/release-check.js [--tag vX.Y.Z]
 *
 * It measures the package a user would install, not the working tree:
 *   1. the vendored keyring matches its .sha256 (a published verifier must never ship a keyring
 *      nobody reviewed);
 *   2. the version: package.json = the tag (when given), and CHANGELOG.md has its heading
 *      (v1.0.3 was tagged with package.json still at 1.0.2 — measured);
 *   3. `npm pack`, and the tarball holds every file the CLI and the exports load at run time
 *      (derived from the require graph, not a hand list) and nothing from test/, .github/ or the
 *      Python sources;
 *   4. the tarball installed into an empty project, offline: the installed bin verifies the fixture
 *      receipt against the keyring it ships (also through `npx --no-install`);
 *   5. the P58 repro with the installed bin: a receipt for its own commit is VERIFIED_CURRENT with
 *      commit_binding BOUND (exit 0); the same sidecar copied beside another commit is
 *      RECEIPT_COMMIT_MISMATCH (exit 1).
 * Exit 0 only when every step passes. No network: pack and install are local and --offline.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const BIN = 'coderifts-receipt-verifier';
const FORBIDDEN = [/^test\//, /^\.github\//, /\.py$/, /^contract-verify\//, /^scripts\//];

const sha256hex = (b) => crypto.createHash('sha256').update(b).digest('hex');

/** 1. keys/coderifts-keys.json against keys/coderifts-keys.json.sha256 (sha256sum format). */
function checkKeyringDigest(root = ROOT) {
  const keys = path.join(root, 'keys', 'coderifts-keys.json');
  const pin = `${keys}.sha256`;
  if (!fs.existsSync(keys) || !fs.existsSync(pin)) return { ok: false, reason: 'keyring or its .sha256 is missing' };
  const expected = fs.readFileSync(pin, 'utf8').trim().split(/\s+/)[0];
  const actual = sha256hex(fs.readFileSync(keys));
  return expected === actual
    ? { ok: true, digest: actual }
    : { ok: false, reason: `keyring digest ${actual} does not match the pinned ${expected}` };
}

/** 2. package.json version = tag (if given) and a CHANGELOG heading for it. */
function checkVersion(root = ROOT, tag = null) {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const problems = [];
  if (tag && tag !== `v${pkg.version}`) problems.push(`tag ${tag} is not v${pkg.version} (package.json)`);
  const changelog = fs.readFileSync(path.join(root, 'CHANGELOG.md'), 'utf8');
  if (!new RegExp(`^## ${pkg.version.replace(/\./g, '\\.')}\\b`, 'm').test(changelog)) problems.push(`CHANGELOG.md has no "## ${pkg.version}" heading`);
  return problems.length ? { ok: false, reason: problems.join('; ') } : { ok: true, version: pkg.version };
}

/** The files the package loads at run time: bin + exports + every local require they reach + the keyring. */
function requiredFiles(root = ROOT) {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const start = [...Object.values(pkg.bin || {}), ...Object.values(pkg.exports || {}), pkg.main].filter(Boolean)
    .map((p) => p.replace(/^\.\//, ''));
  const need = new Set(['package.json', 'README.md', 'LICENSE', 'keys/coderifts-keys.json', 'keys/coderifts-keys.json.sha256']);
  const seen = new Set();
  const queue = [...start];
  while (queue.length) {
    const rel = queue.shift();
    if (seen.has(rel)) continue;
    seen.add(rel);
    need.add(rel);
    if (!rel.endsWith('.js')) continue;
    const src = fs.readFileSync(path.join(root, rel), 'utf8');
    for (const m of src.matchAll(/require\(\s*'\.\/([^']+)'\s*\)/g)) {
      queue.push(m[1].endsWith('.js') || m[1].endsWith('.json') ? m[1] : `${m[1]}.js`);
    }
  }
  return [...need].sort();
}

/** 3. what the tarball must and must not hold. */
function checkTarballFiles(files, required) {
  const have = new Set(files);
  const missing = required.filter((f) => !have.has(f));
  const forbidden = files.filter((f) => FORBIDDEN.some((re) => re.test(f)));
  const problems = [];
  if (missing.length) problems.push(`the tarball lacks ${missing.join(', ')}`);
  if (forbidden.length) problems.push(`the tarball carries ${forbidden.join(', ')}`);
  return problems.length ? { ok: false, reason: problems.join('; '), missing, forbidden } : { ok: true };
}

function run(cmd, args, opts = {}) {
  const env = { ...process.env };
  delete env.CODERIFTS_API_KEY; // never a keyed call from a release check
  const res = spawnSync(cmd, args, { encoding: 'utf8', env, ...opts });
  let json = null;
  try { json = JSON.parse(res.stdout); } catch (_) { /* not json */ }
  return { code: res.status, stdout: res.stdout, stderr: res.stderr, json };
}

/** 5. the P58 repro, with the INSTALLED package: its bin and its exports. */
function p58Repro(installDir) {
  const pkgDir = path.join(installDir, 'node_modules', '@coderifts', 'receipt-verifier');
  const { reconstructSignedInput, canonicalJson } = require(path.join(pkgDir, 'verify.js'));
  const { SIDECAR_DIR } = require(path.join(pkgDir, 'receipt-from-commit.js'));
  const bin = path.join(installDir, 'node_modules', '.bin', BIN);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rv-release-p58-'));
  try {
    const g = (...a) => execFileSync('git', a, { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
    g('init', '-q', '.'); g('config', 'user.email', 'release@check'); g('config', 'user.name', 'release-check');
    const commit = (spec, msg) => { fs.writeFileSync(path.join(dir, 'openapi.yaml'), spec); g('add', '-A'); g('commit', '-q', '-m', msg); return g('rev-parse', 'HEAD'); };
    const V1 = 'openapi: 3.0.3\npaths:\n  /users: {}\n';
    const V2 = 'openapi: 3.0.3\npaths:\n  /users: {}\n  /orders: {}\n';
    const V3 = 'openapi: 3.0.3\npaths:\n  /orders: {}\n';
    const base = commit(V1, 'base');
    const head = commit(V2, 'add /orders');
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const kid = 'release-check-k1';
    const keys = path.join(dir, 'keys.json');
    fs.writeFileSync(keys, JSON.stringify({ keys: [{ kid, public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }), status: 'active', valid_from: null, retired_at: null }] }));
    const digest = `sha256:${sha256hex([V1, V2].map(sha256hex).join(''))}`;
    const envelope = { decision: 'ALLOW', execution_action: 'CONTINUE', base, head, artifact_digest: digest };
    const now = Date.now();
    const payload = {
      v: 4, kid, fp: `sha256:${sha256hex('fp')}`, prev: 'null', caller: 'anon', ts: new Date(now).toISOString(),
      reg: sha256hex('reg'), ir: `sha256:${sha256hex('ir')}`, expires_at: new Date(now + 3600e3).toISOString(),
      bh: `sha256:${sha256hex(canonicalJson({ ...envelope }))}`,
    };
    const sig = crypto.sign(null, Buffer.from(reconstructSignedInput(payload), 'utf8'), privateKey);
    const doc = { sha: head, receipt: `${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${sig.toString('base64url')}`, envelope };
    const sidecar = (sha, d) => { fs.mkdirSync(path.join(dir, SIDECAR_DIR), { recursive: true }); fs.writeFileSync(path.join(dir, SIDECAR_DIR, `${sha}.json`), JSON.stringify(d)); };
    sidecar(head, doc);

    const own = run(bin, ['--from-commit', head, '--keys', keys, '--contract', 'openapi.yaml'], { cwd: dir });
    g('reset', '-q', '--hard', base);
    const forced = commit(V3, 'force-pushed: /users removed');
    sidecar(forced, { ...doc, sha: forced });
    const copied = run(bin, ['--from-commit', forced, '--keys', keys], { cwd: dir });

    const problems = [];
    if (own.code !== 0 || !own.json || own.json.status !== 'VERIFIED_CURRENT' || own.json.commit_binding?.status !== 'BOUND') {
      problems.push(`own commit: exit ${own.code}, ${own.stdout.trim() || own.stderr.trim()}`);
    }
    if (copied.code !== 1 || !copied.json || copied.json.status !== 'RECEIPT_COMMIT_MISMATCH') {
      problems.push(`copied sidecar: exit ${copied.code}, ${copied.stdout.trim() || copied.stderr.trim()}`);
    }
    return problems.length ? { ok: false, reason: problems.join('; ') }
      : { ok: true, own: `${own.json.status} / ${own.json.commit_binding.status}`, copied: copied.json.status };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** The whole check on `root`. Returns { ok, steps: [{ name, ok, detail }] }. */
function releaseCheck({ root = ROOT, tag = null } = {}) {
  const steps = [];
  const step = (name, r, detail) => { steps.push({ name, ok: r.ok, detail: r.ok ? detail : r.reason }); return r.ok; };
  step('keyring digest', checkKeyringDigest(root), 'keys/coderifts-keys.json matches its .sha256');
  step('version', checkVersion(root, tag), `${tag || 'no tag given'}; CHANGELOG heading present`);

  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'rv-release-'));
  try {
    const packed = run('npm', ['pack', '--json', '--pack-destination', work], { cwd: root });
    if (packed.code !== 0 || !Array.isArray(packed.json)) {
      step('npm pack', { ok: false, reason: (packed.stderr || packed.stdout).trim() });
      return { ok: false, steps };
    }
    const info = packed.json[0];
    const files = info.files.map((f) => f.path);
    step('npm pack', { ok: true }, `${info.filename}: ${info.entryCount} files, ${info.size} bytes packed, ${info.unpackedSize} unpacked`);
    if (!step('tarball contents', checkTarballFiles(files, requiredFiles(root)), 'every run-time file present; no test/, .github/, scripts/ or Python files')) {
      return { ok: false, steps, files };
    }

    const project = path.join(work, 'project');
    fs.mkdirSync(project);
    fs.writeFileSync(path.join(project, 'package.json'), JSON.stringify({ name: 'release-check-consumer', private: true }));
    const inst = run('npm', ['install', '--offline', '--no-audit', '--no-fund', '--ignore-scripts', '--no-package-lock', path.join(work, info.filename)], { cwd: project });
    if (!step('install (offline, empty project)', inst.code === 0 ? { ok: true } : { ok: false, reason: inst.stderr.trim() }, 'installed from the tarball')) {
      return { ok: false, steps, files };
    }

    const token = fs.readFileSync(path.join(root, 'test', 'fixtures-receipt.txt'), 'utf8').trim();
    const viaBin = run(path.join(project, 'node_modules', '.bin', BIN), [token], { cwd: project });
    step('installed bin verifies the fixture (shipped keyring)', viaBin.code === 0 && viaBin.json?.status === 'VERIFIED_CURRENT'
      ? { ok: true } : { ok: false, reason: `exit ${viaBin.code}: ${viaBin.stdout.trim() || viaBin.stderr.trim()}` }, 'VERIFIED_CURRENT, exit 0');
    const viaNpx = run('npx', ['--no-install', BIN, token], { cwd: project });
    step('npx --no-install', viaNpx.code === 0 && viaNpx.json?.status === 'VERIFIED_CURRENT'
      ? { ok: true } : { ok: false, reason: `exit ${viaNpx.code}: ${viaNpx.stdout.trim() || viaNpx.stderr.trim()}` }, 'VERIFIED_CURRENT, exit 0');
    let p58;
    try { p58 = p58Repro(project); } catch (err) { p58 = { ok: false, reason: err.message }; }
    step('P58 --from-commit repro (installed package)', p58, p58.ok ? `own commit ${p58.own}; copied sidecar ${p58.copied}` : '');
    return { ok: steps.every((s) => s.ok), steps, files, size: info.size, unpackedSize: info.unpackedSize };
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}

module.exports = { checkKeyringDigest, checkVersion, requiredFiles, checkTarballFiles, releaseCheck };

if (require.main === module) {
  const i = process.argv.indexOf('--tag');
  const tag = i > -1 ? process.argv[i + 1] : (process.env.GITHUB_REF_TYPE === 'tag' ? process.env.GITHUB_REF_NAME : null);
  const r = releaseCheck({ tag });
  for (const s of r.steps) console.log(`${s.ok ? 'ok  ' : 'FAIL'}  ${s.name}${s.detail ? ` — ${s.detail}` : ''}`);
  console.log(r.ok ? 'RELEASE CHECK PASSED' : 'RELEASE CHECK FAILED');
  process.exit(r.ok ? 0 : 1);
}
