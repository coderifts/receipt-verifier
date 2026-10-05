'use strict';

/**
 * P58 (2026-10-05) — `--from-commit <sha>` binds the receipt to THAT commit.
 *
 * MEASURED (CC-2 T15, item 8): an old receipt's sidecar copied beside a force-pushed SHA verified
 * VERIFIED_CURRENT, exit 0. `--from-commit` found the sidecar by the new SHA, checked the signature
 * and the envelope's body hash, and never asked whether the envelope was about that commit: its
 * `head` named the old one, and the spec at the new commit did not hash to its `artifact_digest`.
 *
 * Held here, on real throwaway repositories and a receipt minted with a test key:
 *   - the receipt for the commit it names verifies, with commit_binding BOUND (head, and content
 *     when --contract names the file);
 *   - the same sidecar copied to another commit fails RECEIPT_COMMIT_MISMATCH, naming both;
 *   - editing the envelope's head to match is caught by the signature (body hash);
 *   - a receipt whose artifact_digest the commit's files do not produce fails CONTENT_MISMATCH;
 *   - a sidecar without an envelope fails RECEIPT_NOT_BOUND_TO_COMMIT;
 *   - an abbreviated head in the envelope binds by prefix;
 *   - a trailer without an envelope keeps its verdict and says what it cannot check.
 */

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { execFileSync, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { reconstructSignedInput, canonicalJson } = require('../verify.js');
const { TRAILER_KEY, SIDECAR_DIR } = require('../receipt-from-commit.js');

const CLI = path.join(__dirname, '..', 'cli.js');
const KID = 'p58-test-k1';
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const made = [];
after(() => { for (const d of made) { try { fs.rmSync(d, { recursive: true, force: true }); } catch (_) { /* */ } } });

const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');
const US = '\x1f';
/** The app's artifact_digest (src/change-set.js), for one or more { before, after } artifacts in order. */
const artifactDigest = (arts) => `sha256:${sha256hex(arts.map((a) => `${sha256hex(a.before)}${sha256hex(a.after)}`).join(US))}`;

function keysFile(dir) {
  const f = path.join(dir, 'keys.json');
  fs.writeFileSync(f, JSON.stringify({ keys: [{ kid: KID, public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }), status: 'active', valid_from: null, retired_at: null }] }));
  return f;
}

/** A v4 receipt over `envelope`, signed with the test key: the token and the envelope it binds. */
function mint(envelope) {
  const rest = { ...envelope };
  const bh = `sha256:${sha256hex(canonicalJson(rest))}`;
  const now = Date.now();
  const payload = {
    v: 4, kid: KID, fp: `sha256:${sha256hex('fp')}`, prev: 'null', caller: 'anon', ts: new Date(now).toISOString(),
    reg: sha256hex('reg'), ir: `sha256:${sha256hex('ir')}`, expires_at: new Date(now + 3600e3).toISOString(), bh,
  };
  const sig = crypto.sign(null, Buffer.from(reconstructSignedInput(payload), 'utf8'), privateKey);
  return `${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${sig.toString('base64url')}`;
}

function repo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'p58-'));
  made.push(dir);
  const g = (...a) => execFileSync('git', a, { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  g('init', '-q', '.'); g('config', 'user.email', 't@t'); g('config', 'user.name', 't');
  const commit = (spec, message = 'm') => {
    fs.writeFileSync(path.join(dir, 'openapi.yaml'), spec);
    g('add', '-A'); g('commit', '-q', '-m', message);
    return g('rev-parse', 'HEAD');
  };
  const sidecar = (sha, doc) => {
    fs.mkdirSync(path.join(dir, SIDECAR_DIR), { recursive: true });
    fs.writeFileSync(path.join(dir, SIDECAR_DIR, `${sha}.json`), JSON.stringify(doc));
  };
  return { dir, g, commit, sidecar };
}

function run(args, cwd) {
  const res = spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  let json = null;
  try { json = JSON.parse(res.stdout); } catch (_) { /* not json */ }
  return { code: res.status, json, stdout: res.stdout, stderr: res.stderr };
}

const V1 = 'openapi: 3.0.3\npaths:\n  /users: {}\n';
const V2 = 'openapi: 3.0.3\npaths:\n  /users: {}\n  /orders: {}\n';
const V3 = 'openapi: 3.0.3\npaths:\n  /orders: {}\n';   // the force-pushed content: /users removed

/** base → head with a receipt minted for head, its sidecar beside head. */
function scenario() {
  const r = repo();
  const base = r.commit(V1, 'base');
  const head = r.commit(V2, 'add /orders');
  const envelope = { decision: 'ALLOW', execution_action: 'CONTINUE', base, head, artifact_digest: artifactDigest([{ before: V1, after: V2 }]) };
  const doc = { sha: head, receipt: mint(envelope), envelope };
  r.sidecar(head, doc);
  return { r, base, head, envelope, doc, keys: keysFile(r.dir) };
}

describe('P58 · --from-commit binds the receipt to the commit asked about', () => {
  it('the receipt for the commit it names verifies, and says it is bound (head + content)', () => {
    const s = scenario();
    const out = run(['--from-commit', s.head, '--keys', s.keys, '--contract', 'openapi.yaml'], s.r.dir);
    assert.equal(out.code, 0, out.stdout + out.stderr);
    assert.equal(out.json.status, 'VERIFIED_CURRENT');
    assert.equal(out.json.commit_binding.status, 'BOUND');
    assert.equal(out.json.commit_binding.head, 'match');
    assert.equal(out.json.commit_binding.content, 'match');
  });

  it('⚠⚠ the T15 force-push: the old sidecar copied beside the new SHA fails RECEIPT_COMMIT_MISMATCH, naming both', () => {
    const s = scenario();
    s.r.g('reset', '-q', '--hard', s.base);
    const forced = s.r.commit(V3, 'add /orders (amended: /users removed)');
    s.r.sidecar(forced, { ...s.doc, sha: forced });
    const out = run(['--from-commit', forced, '--keys', s.keys], s.r.dir);
    assert.equal(out.code, 1, out.stdout + out.stderr);
    assert.equal(out.json.valid, false);
    assert.equal(out.json.status, 'RECEIPT_COMMIT_MISMATCH');
    assert.ok(out.json.reason.includes(s.head) && out.json.reason.includes(forced), out.json.reason);
    assert.equal(out.json.signature_status, 'VERIFIED_CURRENT', 'the signature itself is fine; the binding is not');
  });

  it('⚠ editing the envelope\'s head to the new SHA is caught by the signature (body hash)', () => {
    const s = scenario();
    s.r.g('reset', '-q', '--hard', s.base);
    const forced = s.r.commit(V3, 'amended');
    s.r.sidecar(forced, { sha: forced, receipt: s.doc.receipt, envelope: { ...s.envelope, head: forced } });
    const out = run(['--from-commit', forced, '--keys', s.keys], s.r.dir);
    assert.equal(out.code, 1);
    assert.equal(out.json.status, 'INVALID_SIGNATURE');
    assert.equal(out.json.reason, 'body_hash_mismatch');
  });

  it('a receipt whose artifact_digest the commit\'s files do not produce fails CONTENT_MISMATCH, naming the file', () => {
    const r = repo();
    const base = r.commit(V1, 'base');
    const head = r.commit(V3, 'remove /users');
    const envelope = { decision: 'ALLOW', base, head, artifact_digest: artifactDigest([{ before: V1, after: V2 }]) };
    r.sidecar(head, { sha: head, receipt: mint(envelope), envelope });
    const keys = keysFile(r.dir);
    const out = run(['--from-commit', head, '--keys', keys, '--contract', 'openapi.yaml'], r.dir);
    assert.equal(out.code, 1, out.stdout + out.stderr);
    assert.equal(out.json.status, 'CONTENT_MISMATCH');
    assert.match(out.json.reason, /openapi\.yaml/);
    // without --contract the content is not checked, and the output says so
    const noContract = run(['--from-commit', head, '--keys', keys], r.dir);
    assert.equal(noContract.code, 0);
    assert.equal(noContract.json.commit_binding.content, 'not_checked');
  });

  it('a sidecar without an envelope fails RECEIPT_NOT_BOUND_TO_COMMIT: nothing ties it to the commit', () => {
    const s = scenario();
    s.r.sidecar(s.head, { sha: s.head, receipt: s.doc.receipt });
    const out = run(['--from-commit', s.head, '--keys', s.keys], s.r.dir);
    assert.equal(out.code, 1, out.stdout + out.stderr);
    assert.equal(out.json.status, 'RECEIPT_NOT_BOUND_TO_COMMIT');
  });

  it('an envelope whose head is abbreviated binds by prefix (7 to 39 hex characters)', () => {
    const r = repo();
    const base = r.commit(V1, 'base');
    const head = r.commit(V2, 'add');
    const envelope = { decision: 'ALLOW', base, head: head.slice(0, 12), artifact_digest: artifactDigest([{ before: V1, after: V2 }]) };
    r.sidecar(head, { sha: head, receipt: mint(envelope), envelope });
    const out = run(['--from-commit', head, '--keys', keysFile(r.dir)], r.dir);
    assert.equal(out.code, 0, out.stdout + out.stderr);
    assert.equal(out.json.commit_binding.head, 'match');
  });

  it('a trailer without an envelope keeps its verdict, and says on stderr what it cannot check', () => {
    const r = repo();
    r.commit(V1, 'base');
    const token = mint({ decision: 'ALLOW' });
    fs.writeFileSync(path.join(r.dir, 'openapi.yaml'), V2);
    r.g('add', '-A'); r.g('commit', '-q', '-m', `add\n\n${TRAILER_KEY}: ${token}`);
    const head = r.g('rev-parse', 'HEAD');
    const out = run(['--from-commit', head, '--keys', keysFile(r.dir)], r.dir);
    assert.equal(out.code, 0, out.stdout + out.stderr);
    assert.equal(out.json.status, 'VERIFIED_CURRENT');
    assert.match(out.stderr, /commit binding: the trailer carries no envelope/);
  });
});
