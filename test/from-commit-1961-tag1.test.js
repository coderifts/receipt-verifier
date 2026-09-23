'use strict';

/**
 * 1961 TAG 1 — `--from-commit`, both carriers, and the conflict that must never be resolved
 * silently.
 *
 * ⚠ THE LOAD-BEARING TEST is `trailer and sidecar DISAGREE → refused`. Preferring the trailer is
 * the right precedence and would look correct in every ordinary case; it is precisely wrong in the
 * one case that matters, because a disagreement is the signature of somebody editing the mutable
 * half. A test that only checked "the trailer wins" would bless that.
 *
 * Every case builds a real throwaway git repository. Nothing here touches a repository we care
 * about, and nothing goes to the network.
 */

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { receiptForCommit, TRAILER_KEY, SIDECAR_DIR } = require('../receipt-from-commit.js');

const CLI = path.join(__dirname, '..', 'cli.js');
const KEYS = path.join(__dirname, 'fixtures-keys.json');
const TOKEN = fs.readFileSync(path.join(__dirname, 'fixtures-receipt.txt'), 'utf8').trim();
const OTHER_TOKEN = `${TOKEN.split('.')[0]}.AAAA`;   // same shape, different bytes

const made = [];
after(() => { for (const d of made) { try { fs.rmSync(d, { recursive: true, force: true }); } catch (_) { /* */ } } });

function repo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'from-commit-'));
  made.push(dir);
  const g = (...a) => execFileSync('git', a, { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] });
  g('init', '-q', '.');
  g('config', 'user.email', 't@t'); g('config', 'user.name', 't');
  return { dir, g };
}

function commit(r, message) {
  fs.writeFileSync(path.join(r.dir, `f${Math.floor(Math.random() * 1e9)}`), 'x');
  r.g('add', '-A');
  r.g('commit', '-q', '-m', message);
  return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: r.dir, encoding: 'utf8' }).trim();
}

function sidecar(r, sha, doc) {
  const dir = path.join(r.dir, SIDECAR_DIR);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${sha}.json`), typeof doc === 'string' ? doc : JSON.stringify(doc));
}

function runCli(args, cwd) {
  // ⚠ stderr is captured on the SUCCESS path too. An earlier draft only kept it in the catch
  // branch, so a test asserting on a human note printed by a successful run saw an empty string —
  // and would have "passed" a --json flag that silenced nothing.
  const cap = { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] };
  const res = spawnSync(process.execPath, [CLI, ...args], cap);
  return { code: res.status, stdout: res.stdout || '', stderr: res.stderr || '' };
}

describe('TAG 1 · the two carriers', () => {
  it('⚠ the trailer carries it, and long values unfold', () => {
    const r = repo();
    const sha = commit(r, `subject\n\n${TRAILER_KEY}: ${TOKEN}`);
    const found = receiptForCommit(sha, { cwd: r.dir });
    assert.equal(found.token, TOKEN, 'the token did not survive the trailer round trip');
    assert.equal(found.carrier, 'trailer');
    assert.equal(found.sha, sha);
  });

  it('⚠ the sidecar carries it, and carries the ENVELOPE a trailer cannot', () => {
    const r = repo();
    const sha = commit(r, 'no trailer here');
    sidecar(r, sha, { sha, receipt: TOKEN, envelope: { decision: 'ALLOW' } });
    const found = receiptForCommit(sha, { cwd: r.dir });
    assert.equal(found.token, TOKEN);
    assert.equal(found.carrier, 'sidecar');
    assert.deepEqual(found.envelope, { decision: 'ALLOW' });
  });

  it('⚠ an ABBREVIATED sha resolves through git — the sidecar is keyed on the full one', () => {
    const r = repo();
    const sha = commit(r, 'x');
    sidecar(r, sha, { receipt: TOKEN });
    const found = receiptForCommit(sha.slice(0, 8), { cwd: r.dir });
    assert.equal(found.sha, sha, 'the abbreviation was not resolved — the sidecar would be missed');
  });
});

describe('TAG 1 · precedence, and the conflict', () => {
  it('⚠ both present and AGREEING → carrier "both", and the envelope still comes through', () => {
    const r = repo();
    const sha = commit(r, `s\n\n${TRAILER_KEY}: ${TOKEN}`);
    sidecar(r, sha, { receipt: TOKEN, envelope: { e: 1 } });
    const found = receiptForCommit(sha, { cwd: r.dir });
    assert.equal(found.carrier, 'both');
    assert.deepEqual(found.envelope, { e: 1 });
  });

  it('⚠⚠ both present and DISAGREEING → REFUSED, not silently resolved', () => {
    // The trailer is the right winner in principle. Letting it win here would hide the one thing
    // the precedence rule exists to expose: somebody edited the mutable half.
    const r = repo();
    const sha = commit(r, `s\n\n${TRAILER_KEY}: ${TOKEN}`);
    sidecar(r, sha, { receipt: OTHER_TOKEN });
    assert.throws(() => receiptForCommit(sha, { cwd: r.dir }), /receipt conflict/);
  });

  it('⚠ a MALFORMED sidecar throws — it is not treated as "no sidecar"', () => {
    // Falling through to "nothing found" would read as an innocent absence rather than the
    // broken file it is.
    const r = repo();
    const sha = commit(r, 'x');
    sidecar(r, sha, '{not json');
    assert.throws(() => receiptForCommit(sha, { cwd: r.dir }), /not valid JSON/);
  });

  it('⚠ a sidecar with no receipt field throws, rather than returning nothing', () => {
    const r = repo();
    const sha = commit(r, 'x');
    sidecar(r, sha, { sha, note: 'I forgot the token' });
    assert.throws(() => receiptForCommit(sha, { cwd: r.dir }), /no "receipt" field/);
  });
});

describe('TAG 1 · absence, and what it is not', () => {
  it('⚠⚠ NEGATIVE CONTROL — nothing attached throws, and says what that does NOT mean', () => {
    const r = repo();
    const sha = commit(r, 'a perfectly ordinary commit');
    assert.throws(() => receiptForCommit(sha, { cwd: r.dir }),
      /it does not mean none exists/);
  });

  it('⚠ an unknown ref is reported as unresolvable, not as "no receipt"', () => {
    const r = repo();
    commit(r, 'x');
    assert.throws(() => receiptForCommit('deadbeefdeadbeef', { cwd: r.dir }), /cannot resolve/);
  });
});

describe('TAG 1 · the CLI', () => {
  it('⚠ --from-commit verifies exactly as a pasted token does', () => {
    const r = repo();
    const sha = commit(r, `s\n\n${TRAILER_KEY}: ${TOKEN}`);
    const viaCommit = runCli(['--from-commit', sha, '--keys', KEYS], r.dir);
    const viaPaste = runCli([TOKEN, '--keys', KEYS], r.dir);
    assert.equal(viaCommit.code, viaPaste.code);
    assert.deepEqual(JSON.parse(viaCommit.stdout), JSON.parse(viaPaste.stdout),
      'the carrier changed the verdict — it must change nothing');
  });

  it('⚠⚠ "no receipt attached" is a USAGE error (exit 2), never a verdict', () => {
    // Emitting valid:false would be a verdict on a token that was never presented.
    const r = repo();
    commit(r, 'bare');
    const out = runCli(['--from-commit', 'HEAD', '--keys', KEYS], r.dir);
    assert.equal(out.code, 2);
    assert.equal(out.stdout.trim(), '', 'a verdict document was emitted for an absent receipt');
  });

  it('⚠ --from-commit with a positional receipt is refused as ambiguous', () => {
    const r = repo();
    const sha = commit(r, `s\n\n${TRAILER_KEY}: ${TOKEN}`);
    const out = runCli([TOKEN, '--from-commit', sha, '--keys', KEYS], r.dir);
    assert.equal(out.code, 2);
    assert.match(out.stderr, /mutually exclusive/);
  });

  it('⚠ --repo points elsewhere, so the verifier need not run inside the repository', () => {
    const r = repo();
    const sha = commit(r, `s\n\n${TRAILER_KEY}: ${TOKEN}`);
    const out = runCli(['--from-commit', sha, '--repo', r.dir, '--keys', KEYS], os.tmpdir());
    assert.equal(out.code, 0);
    assert.equal(JSON.parse(out.stdout).status, 'VERIFIED_CURRENT');
  });

  it('⚠⚠ a FORGED sidecar does not pass — the signature is the authority, not the pointer', () => {
    // The whole safety argument for allowing a mutable carrier at all.
    const r = repo();
    const sha = commit(r, 'x');
    const forged = `${Buffer.from(JSON.stringify({ v: 2, kid: '2026-07-k1', fp: 'sha256:0', prev: '', caller: 'me', ts: '2026-01-01T00:00:00Z' })).toString('base64url')}.${Buffer.alloc(64).toString('base64url')}`;
    sidecar(r, sha, { receipt: forged });
    const out = runCli(['--from-commit', sha, '--keys', KEYS], r.dir);
    assert.equal(out.code, 1);
    assert.equal(JSON.parse(out.stdout).status, 'INVALID_SIGNATURE');
  });
});

describe('TAG 9 · --json, and what it deliberately does NOT silence', () => {
  it('⚠ MEASURED FIRST: stdout was ALREADY pure JSON — the flag is about STDERR', () => {
    const r = repo();
    const sha = commit(r, `s\n\n${TRAILER_KEY}: ${TOKEN}`);
    const plain = runCli(['--from-commit', sha, '--keys', KEYS], r.dir);
    assert.doesNotThrow(() => JSON.parse(plain.stdout), 'stdout was not already JSON');
    // …and the note that makes 2>&1 unusable is on stderr.
    assert.match(plain.stderr, /receipt for .* via trailer/);
  });

  it('⚠⚠ --json makes 2>&1 PARSEABLE — the case this flag actually buys', () => {
    const r = repo();
    const sha = commit(r, `s\n\n${TRAILER_KEY}: ${TOKEN}`);
    const out = runCli(['--from-commit', sha, '--json', '--keys', KEYS], r.dir);
    assert.equal(out.stderr || '', '', 'a human note survived --json');
    const merged = `${out.stdout}${out.stderr || ''}`;
    assert.equal(JSON.parse(merged).status, 'VERIFIED_CURRENT');
  });

  it('⚠ the VERDICT is byte-identical with and without the flag', () => {
    const r = repo();
    const sha = commit(r, `s\n\n${TRAILER_KEY}: ${TOKEN}`);
    const a = runCli(['--from-commit', sha, '--keys', KEYS], r.dir);
    const b = runCli(['--from-commit', sha, '--json', '--keys', KEYS], r.dir);
    assert.equal(a.stdout, b.stdout, '--json changed the verdict bytes');
    assert.equal(a.code, b.code);
  });

  it('⚠⚠ NEGATIVE CONTROL — it never silences an ERROR', () => {
    // A flag asking for machine-readable output must not turn a usage error into silence: that
    // is a script that looks like it worked.
    const r = repo();
    commit(r, 'bare');
    const out = runCli(['--from-commit', 'HEAD', '--json', '--keys', KEYS], r.dir);
    assert.equal(out.code, 2);
    assert.match(out.stderr, /no receipt attached/, '--json swallowed the failure');
  });
});

describe('TAG 1 · the convention is documented, not only implemented', () => {
  it('⚠ the doc names both carriers, the precedence, and what it does not prove', () => {
    const doc = fs.readFileSync(path.join(__dirname, '..', 'docs', 'receipt-commit-binding.md'), 'utf8');
    assert.match(doc, /CodeRifts-Receipt/);
    assert.match(doc, /\.coderifts\/receipts/);
    assert.match(doc, /## What this does not prove/);
    // ⚠ The measurement that justified writing it at all must stay in the record.
    assert.match(doc, /zero occurrences/i);
  });
});
