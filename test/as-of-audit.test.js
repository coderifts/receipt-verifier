'use strict';

/*
 * 1.1.6 — `--as-of <ISO 8601>` (CLI) / `asOf` (verifyReceipt): audit mode. The expiry comparison uses the
 * stated instant; the signature, the key lookup, every key-status rule (RECEIPT_FORMAT §7.1), the envelope
 * binding and the chain rules are unchanged. Negative cases first. Ephemeral Ed25519 keys generated here;
 * no live key. Every receipt is minted in the past (ts = now − 6 h, expires_at = ts + 4 h) so "inside",
 * "after" and "before" the window are all real instants that are not in the future.
 */

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { execFileSync, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { verifyReceipt, reconstructSignedInput, canonicalJson, parseAsOf, AS_OF_NOTE } = require('../verify.js');
const { AS_OF_DOES_NOT_PROVE } = require('../cli.js');
const { SIDECAR_DIR } = require('../receipt-from-commit.js');

const CLI = path.join(__dirname, '..', 'cli.js');
const KID = 'asof-test-k1';
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const PEM = publicKey.export({ type: 'spki', format: 'pem' });
const HOUR = 3600e3;
const T0 = Math.floor((Date.now() - 6 * HOUR) / 1000) * 1000; // ts, whole second
const EXP = T0 + 4 * HOUR; // expires_at, in the past (now − 2 h)
const iso = (ms) => new Date(ms).toISOString();
const made = [];
after(() => { for (const p of made) fs.rmSync(p, { recursive: true, force: true }); });
const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');

function tmpdir(prefix) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  made.push(d);
  return d;
}

/** A keyring file with one entry for the test key; `entry` overrides status fields. */
function keysFile(entry = {}) {
  const f = path.join(tmpdir('asof-keys-'), 'keys.json');
  fs.writeFileSync(f, JSON.stringify({ keys: [{ kid: KID, public_key_pem: PEM, status: 'active', valid_from: null, retired_at: null, ...entry }] }));
  return f;
}

/** A signed receipt of version v (3 or 4) with the given ts / expires_at; v4 binds `envelope`'s body hash. */
function mint({ v = 4, ts = T0, exp = EXP, envelope = { decision: 'ALLOW' } } = {}) {
  const payload = v === 4
    ? { v: 4, kid: KID, fp: `sha256:${sha256hex('fp')}`, prev: 'null', caller: 'bundle', ts: iso(ts), reg: '', ir: '', expires_at: iso(exp), bh: `sha256:${sha256hex(canonicalJson(envelope))}` }
    : { v: 3, kid: KID, fp: `sha256:${sha256hex('fp')}`, prev: 'null', caller: 'bundle', ts: iso(ts), reg: sha256hex('reg'), ir: `sha256:${sha256hex('ir')}` };
  const sig = crypto.sign(null, Buffer.from(reconstructSignedInput(payload), 'utf8'), privateKey);
  return `${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${sig.toString('base64url')}`;
}

function run(args, cwd = path.join(__dirname, '..')) {
  const res = spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  let json = null;
  try { json = JSON.parse(res.stdout); } catch (_) { /* not json */ }
  return { code: res.status, json, stdout: res.stdout, stderr: res.stderr };
}

describe('--as-of: refusals first', () => {
  it('as-of before the receipt\'s ts → NOT_YET_VALID_AT_AS_OF, valid:false, exit 1', () => {
    const out = run([mint(), '--keys', keysFile(), '--as-of', iso(T0 - HOUR)]);
    assert.equal(out.code, 1, out.stdout + out.stderr);
    assert.equal(out.json.status, 'NOT_YET_VALID_AT_AS_OF');
    assert.equal(out.json.valid, false);
    assert.equal(out.json.valid_at_as_of, false);
    assert.equal(out.json.mode, 'audit');
  });

  it('as-of after the window → VERIFIED_EXPIRED at that instant, valid_at_as_of:false, exit 1', () => {
    const out = run([mint(), '--keys', keysFile(), '--as-of', iso(EXP + HOUR)]);
    assert.equal(out.code, 1);
    assert.equal(out.json.status, 'VERIFIED_EXPIRED');
    assert.equal(out.json.valid, false);
    assert.equal(out.json.valid_at_as_of, false);
    assert.equal(out.json.expired_now, true);
  });

  it('a revoked key with as-of inside the window → valid:false (no as-of rehabilitates it), exit 1', () => {
    for (const entry of [{ status: 'revoked', compromised_at: iso(T0 - HOUR) }, { status: 'revoked' }, { revoked_at: iso(T0 - HOUR) }]) {
      const out = run([mint(), '--keys', keysFile(entry), '--as-of', iso(T0 + HOUR)]);
      assert.equal(out.code, 1, JSON.stringify(entry));
      assert.equal(out.json.valid, false, JSON.stringify(entry));
      assert.equal(out.json.valid_at_as_of, false, JSON.stringify(entry));
      assert.match(out.json.status, /REVOKED/, JSON.stringify(entry));
      const without = run([mint(), '--keys', keysFile(entry)]);
      assert.equal(out.json.status, without.json.status, 'the key-status refusal is the same with and without --as-of');
    }
  });

  it('as-of later than now + leeway → exit 2, as_of_in_future, no verdict on stdout', () => {
    const out = run([mint(), '--keys', keysFile(), '--as-of', iso(Date.now() + HOUR)]);
    assert.equal(out.code, 2);
    assert.match(out.stderr, /as_of_in_future/);
    assert.equal(out.json, null);
  });

  it('an unparsable as-of (or one without a zone) → exit 2, usage error', () => {
    for (const bad of ['yesterday', '2026-10-29 13:00:00', '2026-10-29T13:00:00', '']) {
      const out = run([mint(), '--keys', keysFile(), '--as-of', bad]);
      assert.equal(out.code, 2, `${JSON.stringify(bad)}: ${out.stderr}`);
      assert.equal(out.json, null);
    }
  });

  it('--as-of with --chain → usage error', () => {
    const chain = path.join(tmpdir('asof-chain-'), 'c.txt');
    fs.writeFileSync(chain, `${mint()}\n`);
    assert.equal(run(['--chain', chain, '--keys', keysFile(), '--as-of', iso(T0 + HOUR)]).code, 2);
  });
});

describe('--as-of: inside the window', () => {
  it('VERIFIED_AT_AS_OF, valid_at_as_of:true, expired_now:true, the window, exit 0; the human line on stderr', () => {
    const asOf = iso(T0 + HOUR);
    const out = run([mint(), '--keys', keysFile(), '--as-of', asOf]);
    assert.equal(out.code, 0, out.stdout + out.stderr);
    assert.equal(out.json.status, 'VERIFIED_AT_AS_OF');
    assert.equal(out.json.valid, true);
    assert.equal(out.json.valid_at_as_of, true);
    assert.equal(out.json.expired_now, true);
    assert.equal(out.json.as_of, asOf);
    assert.deepEqual(out.json.window, { ts: iso(T0), expires_at: iso(EXP) });
    assert.ok(out.json.does_not_prove.includes(AS_OF_DOES_NOT_PROVE));
    const to = iso(EXP).replace('.000Z', 'Z');
    const toShort = iso(T0).slice(0, 11) === iso(EXP).slice(0, 11) ? to.slice(11) : to;
    assert.equal(out.stderr.trim(), `VERIFIED_AT_AS_OF ${asOf.replace('.000Z', 'Z')} · window ${iso(T0).replace('.000Z', 'Z')} to ${toShort} · expired now`);
    const quiet = run([mint(), '--keys', keysFile(), '--as-of', asOf, '--json']);
    assert.equal(quiet.stderr, '', '--json keeps stderr empty');
  });

  it('without --as-of the same receipt is VERIFIED_EXPIRED today (the reason audit mode exists)', () => {
    const out = run([mint(), '--keys', keysFile()]);
    assert.equal(out.json.status, 'VERIFIED_EXPIRED');
    assert.equal(out.code, 1);
    assert.equal(out.json.mode, undefined);
  });

  it('a retired key inside its validity: the same status and valid as today', () => {
    const entry = { status: 'retired', retired_at: iso(T0 + 30 * 60e3) };
    const today = run([mint(), '--keys', keysFile(entry)]);
    const audit = run([mint(), '--keys', keysFile(entry), '--as-of', iso(T0 + HOUR)]);
    assert.equal(audit.json.status, today.json.status);
    assert.equal(audit.json.valid, today.json.valid);
    assert.equal(audit.json.status, 'RETIRED_KEY_VALID_AT_ISSUE');
    assert.equal(audit.json.valid_at_as_of, true);
    assert.equal(audit.code, 0);
  });
});

describe('--as-of: receipts without an expiry and the API', () => {
  it('a v3 receipt keeps today\'s result and says why as-of did nothing', () => {
    const token = mint({ v: 3 });
    const today = run([token, '--keys', keysFile()]);
    const audit = run([token, '--keys', keysFile(), '--as-of', iso(T0 + HOUR)]);
    assert.equal(audit.json.status, today.json.status);
    assert.equal(audit.json.valid, today.json.valid);
    assert.equal(audit.code, today.code);
    assert.equal(audit.json.as_of_note, AS_OF_NOTE);
    assert.equal(audit.json.window.expires_at, null);
  });

  it('verifyReceipt({ asOf }) answers the same fields; a future or bad asOf throws with a code', () => {
    const keyring = { keys: [{ kid: KID, public_key_pem: PEM, status: 'active' }] };
    const r = verifyReceipt(mint(), { keyring, expectedKid: null }, { asOf: iso(T0 + HOUR) });
    assert.equal(r.status, 'VERIFIED_AT_AS_OF');
    assert.equal(r.valid_at_as_of, true);
    assert.throws(() => verifyReceipt(mint(), { keyring, expectedKid: null }, { asOf: iso(Date.now() + HOUR) }), (e) => e.code === 'as_of_in_future');
    assert.throws(() => parseAsOf('not a date'), (e) => e.code === 'as_of_unparsable');
    // The unified form (1129): asOf sits beside ctx, where envelope does.
    const unified = verifyReceipt(mint(), { ctx: { keyring, expectedKid: null }, asOf: iso(T0 + HOUR) });
    assert.equal(unified.status, 'VERIFIED_AT_AS_OF');
    assert.equal(unified.valid_at_as_of, true);
    const plain = verifyReceipt(mint(), { keyring, expectedKid: null }, {});
    assert.equal(plain.status, 'VERIFIED_EXPIRED', 'no asOf: today\'s behaviour');
    assert.equal(plain.mode, undefined);
  });
});

describe('--as-of with --from-commit (a sidecar fixture)', () => {
  function sidecarRepo() {
    const dir = tmpdir('asof-commit-');
    const g = (...a) => execFileSync('git', a, { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
    g('init', '-q', '.'); g('config', 'user.email', 't@t'); g('config', 'user.name', 't');
    const write = (body, msg) => { fs.writeFileSync(path.join(dir, 'openapi.yaml'), body); g('add', '-A'); g('commit', '-q', '-m', msg); return g('rev-parse', 'HEAD'); };
    const V1 = 'openapi: 3.0.3\npaths:\n  /users: {}\n';
    const V2 = 'openapi: 3.0.3\npaths:\n  /users: {}\n  /orders: {}\n';
    const base = write(V1, 'base');
    const head = write(V2, 'head');
    const US = '\x1f';
    const artifactDigest = `sha256:${sha256hex([{ before: V1, after: V2 }].map((a) => `${sha256hex(a.before)}${sha256hex(a.after)}`).join(US))}`;
    const envelope = { decision: 'ALLOW', execution_action: 'CONTINUE', base, head, artifact_digest: artifactDigest };
    fs.mkdirSync(path.join(dir, SIDECAR_DIR), { recursive: true });
    fs.writeFileSync(path.join(dir, SIDECAR_DIR, `${head}.json`), JSON.stringify({ sha: head, receipt: mint({ envelope }), envelope }));
    return { dir, head };
  }

  it('inside the window: VERIFIED_AT_AS_OF and the commit binding still BOUND, exit 0; after it: exit 1', () => {
    const r = sidecarRepo();
    const keys = keysFile();
    const inside = run(['--from-commit', r.head, '--keys', keys, '--contract', 'openapi.yaml', '--as-of', iso(T0 + HOUR)], r.dir);
    assert.equal(inside.code, 0, inside.stdout + inside.stderr);
    assert.equal(inside.json.status, 'VERIFIED_AT_AS_OF');
    assert.equal(inside.json.commit_binding.status, 'BOUND');
    const later = run(['--from-commit', r.head, '--keys', keys, '--contract', 'openapi.yaml', '--as-of', iso(EXP + HOUR)], r.dir);
    assert.equal(later.code, 1);
    assert.equal(later.json.status, 'VERIFIED_EXPIRED');
    assert.equal(later.json.valid_at_as_of, false);
  });
});
