'use strict';

/*
 * 1.1.7 (2026-10-31) — grants: `environment`, the `grant` subcommand, `--as-of`, the key default.
 *
 * MEASURED before this file (round 10l, HEAD 2c11499):
 *   - a cr.exec.v2 grant carrying `environment` (the app issuer adds it when present,
 *     coderifts-app src/verdict-core/execution-grant-v2.js) → MALFORMED / unknown_field;
 *   - `--intended-environment` and `--as-of` → exit 2 "unknown flag";
 *   - `coderifts-receipt-verifier <grant>` → INVALID_SIGNATURE / signature_mismatch (it read the grant
 *     as a receipt), and `coderifts-receipt-verifier grant <token>` → exit 2 "unexpected argument";
 *   - `node verify-grant.js <grant>` with no --key / --keys fetched app.coderifts.com.
 * Every key here is generated in memory for this run. Every CLI child runs with the network trap
 * preloaded, from a fresh temporary cwd. Negative cases first in each block.
 */

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const { canonicalJson } = require('../verify.js');
const G = require('../verify-grant.js');

const ROOT = path.join(__dirname, '..');
const TRAP = path.join(__dirname, 'network-trap-preload.js');
const SNAPSHOT_SHA12 = crypto.createHash('sha256')
  .update(fs.readFileSync(path.join(ROOT, 'keys', 'coderifts-keys.json'))).digest('hex').slice(0, 12);

const dirs = [];
after(() => { for (const d of dirs) fs.rmSync(d, { recursive: true, force: true }); });
const tmp = () => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'grant-117-')); dirs.push(d); return d; };

const KEY = crypto.generateKeyPairSync('ed25519');
const PEM = KEY.publicKey.export({ type: 'spki', format: 'pem' });
const KEY_SHA256 = crypto.createHash('sha256').update(KEY.publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
const WORK = tmp();
const PEM_FILE = path.join(WORK, 'pub.pem');
fs.writeFileSync(PEM_FILE, PEM);

const sha = (s) => `sha256:${crypto.createHash('sha256').update(String(s)).digest('hex')}`;
const iso = (ms) => new Date(Math.floor(ms / 1000) * 1000).toISOString().replace('.000Z', 'Z');
const NOW = Date.now();
const H = 3600e3;

function grant(over = {}, signer = KEY.privateKey) {
  const body = {
    v: 'cr.exec.v2', kid: 'k-117', grant_id: crypto.randomUUID(), receipt_hash: sha('r'), tenant_id: 't1',
    executor_id: 'exec-a', adapter_id: 'fs', operation: 'write', target_uri: 'fs://repo/out.txt',
    expected_state_token: sha(''), after_payload_hash: sha('x'), nonce_hash: sha('n'), policy_hash: sha('p'),
    audience_hash: sha('aud'), not_before: iso(NOW - 60e3), expires_at: iso(NOW + 600e3), max_attempts: 1, ...over,
  };
  const sig = crypto.sign(null, Buffer.from(`crexec.v2|${canonicalJson(body)}`, 'utf8'), signer);
  return `${Buffer.from(JSON.stringify(body)).toString('base64url')}.${sig.toString('base64url')}`;
}

const pinned = { publicKey: KEY.publicKey, expectedKid: null };
const verify = (tok, opts) => G.verifyExecutionGrant(tok, pinned, opts || {});
const run = (bin, args) => {
  const r = spawnSync(process.execPath, ['-r', TRAP, path.join(ROOT, bin), ...args], { cwd: tmp(), encoding: 'utf8' });
  let json = null;
  try { json = JSON.parse(r.stdout); } catch (_) { /* usage errors print no JSON */ }
  return { code: r.status, stdout: r.stdout, stderr: r.stderr, json };
};

describe('1. environment: an optional signed string in v2', () => {
  it('a non-string or empty environment → MALFORMED bad_environment (never read as "no environment")', () => {
    for (const env of [7, '', null, ['production']]) {
      const r = verify(grant({ environment: env }));
      assert.equal(r.status, 'MALFORMED', JSON.stringify(env));
      assert.equal(r.reason, 'bad_environment', JSON.stringify(env));
    }
  });

  it('--intended-environment different from the grant → GRANT_UNBOUND environment_mismatch', () => {
    const r = verify(grant({ environment: 'production' }), { intended: { environment: 'staging' } });
    assert.deepEqual([r.valid, r.status, r.reason], [false, 'GRANT_UNBOUND', 'environment_mismatch']);
  });

  it('an intended environment on a grant that carries none → environment_mismatch (absent is not a match)', () => {
    assert.equal(verify(grant(), { intended: { environment: 'production' } }).reason, 'environment_mismatch');
  });

  it('an environment that is not signed (edited into the body) → INVALID_SIGNATURE', () => {
    const [b, s] = grant({ environment: 'staging' }).split('.');
    const body = JSON.parse(Buffer.from(b, 'base64url').toString('utf8'));
    const forged = `${Buffer.from(JSON.stringify({ ...body, environment: 'production' })).toString('base64url')}.${s}`;
    assert.equal(verify(forged, { intended: { environment: 'production' } }).status, 'INVALID_SIGNATURE');
  });

  it('the grant with an environment → GRANT_CURRENT; same intended → GRANT_CURRENT; none intended → nothing checked', () => {
    const tok = grant({ environment: 'production' });
    assert.equal(verify(tok).status, 'GRANT_CURRENT');
    assert.equal(verify(tok, { intended: { environment: 'production' } }).status, 'GRANT_CURRENT');
    assert.equal(verify(grant()).status, 'GRANT_CURRENT', 'a grant without environment is unchanged');
  });

  it('a v1 grant cannot carry an environment, so an intended one is environment_mismatch, not silence', () => {
    const v = require('./grant-vectors.json');
    const v1 = v.vectors.find((x) => x.name === 'EG-VALID');
    const ctx = { publicKey: crypto.createPublicKey(v.public_key_pem), expectedKid: v.kid };
    const r = G.verifyExecutionGrant(v1.token, ctx, { intended: { environment: 'production' } });
    assert.deepEqual([r.status, r.reason], ['GRANT_UNBOUND', 'environment_mismatch']);
  });

  it('CLI: --intended-environment wrong → exit 1 environment_mismatch; right → exit 0', () => {
    const tok = grant({ environment: 'production' });
    const bad = run('verify-grant.js', [tok, '--key', PEM_FILE, '--intended-environment', 'staging']);
    assert.equal(bad.code, 1);
    assert.equal(bad.json.reason, 'environment_mismatch');
    const good = run('verify-grant.js', [tok, '--key', PEM_FILE, '--intended-environment', 'production']);
    assert.equal(good.code, 0);
    assert.equal(good.json.status, 'GRANT_CURRENT');
  });

  it('test/grant-vectors.json carries a v2 grant with an environment and its mismatch twin', () => {
    const v = require('./grant-vectors.json').vectors;
    const ok = v.find((x) => x.name === 'EG2-ENVIRONMENT');
    const bad = v.find((x) => x.name === 'EG2-ENVIRONMENT-MISMATCH');
    assert.equal(JSON.parse(Buffer.from(ok.token.split('.')[0], 'base64url').toString('utf8')).environment, 'production');
    assert.equal(ok.expected.status, 'GRANT_CURRENT');
    assert.equal(bad.expected.reason, 'environment_mismatch');
  });
});

describe('2. the grant subcommand', () => {
  it('a grant token on the receipt path → exit 2 naming the grant subcommand, not INVALID_SIGNATURE', () => {
    const r = run('cli.js', [grant(), '--key', PEM_FILE]);
    assert.equal(r.code, 2);
    assert.equal(r.json, null, 'no verdict on stdout');
    assert.match(r.stderr, /cr\.exec\.v2/);
    assert.match(r.stderr, /coderifts-receipt-verifier grant <token>/);
  });

  it('a v1 grant on the receipt path too', () => {
    const tok = require('./grant-vectors.json').vectors.find((x) => x.name === 'EG-VALID').token;
    const r = run('cli.js', [tok, '--key', PEM_FILE]);
    assert.equal(r.code, 2);
    assert.match(r.stderr, /cr\.exec\.v1/);
  });

  it('`grant <token>` gives verify-grant.js\'s verdict and exit code', () => {
    const tok = grant({ environment: 'production' });
    for (const extra of [[], ['--intended-environment', 'staging'], ['--intended-executor', 'other']]) {
      const a = run('cli.js', ['grant', tok, '--key', PEM_FILE, ...extra]);
      const b = run('verify-grant.js', [tok, '--key', PEM_FILE, ...extra]);
      assert.equal(a.code, b.code, extra.join(' '));
      assert.equal(a.stdout, b.stdout, extra.join(' '));
    }
  });

  it('`grant` with no token → exit 2', () => {
    assert.equal(run('cli.js', ['grant', '--key', PEM_FILE]).code, 2);
  });
});

describe('3. --as-of for grants', () => {
  // A window two hours ago → one hour ago: expired now.
  const past = grant({ not_before: iso(NOW - 2 * H), expires_at: iso(NOW - H) });

  it('as_of later than now + 30s → usage error (library throws, CLI exit 2)', () => {
    assert.throws(() => verify(past, { asOf: iso(NOW + H) }), /as_of_in_future/);
    assert.equal(run('verify-grant.js', [past, '--key', PEM_FILE, '--as-of', iso(NOW + H)]).code, 2);
    assert.equal(run('verify-grant.js', [past, '--key', PEM_FILE, '--as-of', 'yesterday']).code, 2);
  });

  it('as_of after expires_at → GRANT_EXPIRED with expired_now', () => {
    const r = verify(past, { asOf: iso(NOW - 0.5 * H) });
    assert.deepEqual([r.valid, r.status, r.valid_at_as_of, r.expired_now], [false, 'GRANT_EXPIRED', false, true]);
  });

  it('as_of before not_before → GRANT_NOT_YET_VALID_AT_AS_OF', () => {
    const r = verify(past, { asOf: iso(NOW - 3 * H) });
    assert.deepEqual([r.valid, r.status, r.valid_at_as_of], [false, 'GRANT_NOT_YET_VALID_AT_AS_OF', false]);
  });

  it('as-of never turns a refusal into a pass: bad signature, wrong executor stay refused', () => {
    const other = crypto.generateKeyPairSync('ed25519');
    assert.equal(verify(grant({ not_before: iso(NOW - 2 * H), expires_at: iso(NOW - H) }, other.privateKey),
      { asOf: iso(NOW - 1.5 * H) }).status, 'INVALID_SIGNATURE');
    const r = verify(past, { asOf: iso(NOW - 1.5 * H), intended: { executor_id: 'other' } });
    assert.deepEqual([r.status, r.reason, r.valid_at_as_of], ['GRANT_UNBOUND', 'executor_mismatch', false]);
  });

  it('a revoked key fails at any as_of (status revoked, or a revoked_at on the entry)', () => {
    for (const extra of [{ status: 'revoked', compromised_at: iso(NOW - 10 * H) }, { status: 'active', revoked_at: iso(NOW - 10 * H) }]) {
      const keyring = new Map([['k-117', { publicKey: KEY.publicKey, retired_at: null, ...extra }]]);
      const r = G.verifyExecutionGrant(past, { keyring, expectedKid: null }, { asOf: iso(NOW - 1.5 * H) });
      assert.equal(r.status, 'UNKNOWN_KEY', JSON.stringify(extra));
      assert.equal(r.valid_at_as_of, false);
    }
  });

  it('a retired key: refused when as_of or not_before is at/after retired_at; without as-of always refused', () => {
    const ring = (retiredAt) => ({ keyring: new Map([['k-117', { publicKey: KEY.publicKey, status: 'retired', retired_at: retiredAt }]]), expectedKid: null });
    assert.equal(G.verifyExecutionGrant(past, ring(iso(NOW - 1.75 * H)), { asOf: iso(NOW - 1.5 * H) }).reason, 'retired_kid', 'as_of after retirement');
    assert.equal(G.verifyExecutionGrant(past, ring(iso(NOW - 3 * H)), { asOf: iso(NOW - 1.5 * H) }).reason, 'retired_kid', 'issued after retirement');
    assert.equal(G.verifyExecutionGrant(past, ring(null), { asOf: iso(NOW - 1.5 * H) }).reason, 'retired_kid', 'no retired_at');
    assert.equal(G.verifyExecutionGrant(past, ring(iso(NOW - 0.5 * H))).reason, 'retired_kid', 'no as-of: unchanged');
    const r = G.verifyExecutionGrant(past, ring(iso(NOW - 0.5 * H)), { asOf: iso(NOW - 1.5 * H) });
    assert.equal(r.status, 'GRANT_CURRENT_AT_AS_OF', 'key still active at as_of and at not_before');
  });

  it('inside the window → GRANT_CURRENT_AT_AS_OF: valid_at_as_of true, valid false (it is not permission now)', () => {
    const r = verify(past, { asOf: iso(NOW - 1.5 * H) });
    assert.equal(r.status, 'GRANT_CURRENT_AT_AS_OF');
    assert.equal(r.valid, false);
    assert.equal(r.valid_at_as_of, true);
    assert.equal(r.expired_now, true);
    assert.equal(r.mode, 'audit');
    assert.deepEqual(r.window, { not_before: iso(NOW - 2 * H), expires_at: iso(NOW - H) });
    assert.match(r.does_not_prove.join(' '), /not permission to execute now/);
  });

  it('the unified call verifyExecutionGrant(token, { ctx, asOf }) takes asOf beside ctx', () => {
    const r = G.verifyExecutionGrant(past, { ctx: pinned, asOf: iso(NOW - 1.5 * H) });
    assert.equal(r.status, 'GRANT_CURRENT_AT_AS_OF');
  });

  it('CLI: exit 0 for GRANT_CURRENT_AT_AS_OF, 1 for GRANT_EXPIRED; the same through `grant`', () => {
    const inside = run('cli.js', ['grant', past, '--key', PEM_FILE, '--as-of', iso(NOW - 1.5 * H)]);
    assert.equal(inside.code, 0);
    assert.equal(inside.json.status, 'GRANT_CURRENT_AT_AS_OF');
    const late = run('cli.js', ['grant', past, '--key', PEM_FILE, '--as-of', iso(NOW - 0.5 * H)]);
    assert.equal(late.code, 1);
    assert.equal(late.json.expired_now, true);
  });
});

describe('4. the grant key default: the pinned snapshot, no network', () => {
  it('--fetch is the opt-in network path (trapped here: it does reach for the network)', () => {
    const r = run('cli.js', ['grant', grant(), '--fetch']);
    assert.match(`${r.stdout}${r.stderr}`, /NETWORK_TRAP/);
  });

  it('no --key / --keys → the vendored snapshot, no network attempt, and the keyring line', () => {
    const r = run('cli.js', ['grant', grant()]);
    assert.doesNotMatch(`${r.stdout}${r.stderr}`, /NETWORK_TRAP/);
    assert.equal(r.code, 1);
    assert.deepEqual([r.json.status, r.json.reason], ['UNKNOWN_KEY', 'unknown_kid'], 'an owner key is not in the CodeRifts snapshot');
    const line = `pinned CodeRifts snapshot ${SNAPSHOT_SHA12} — an owner-signed grant needs --key or --keys`;
    assert.equal(r.json.keyring, line);
    assert.ok(r.stderr.includes(`keyring: ${line}`));
  });

  it('--json keeps the field and drops the stderr note', () => {
    const r = run('cli.js', ['grant', grant(), '--json']);
    assert.equal(r.stderr, '');
    assert.match(r.json.keyring, /^pinned CodeRifts snapshot /);
  });

  it('--key / --keys carry no keyring line', () => {
    const r = run('cli.js', ['grant', grant(), '--key', PEM_FILE]);
    assert.equal(r.json.keyring, undefined);
    assert.doesNotMatch(r.stderr, /keyring:/);
  });
});

describe('5. verified_with.keyring_snapshot_sha256', () => {
  it('a grant verified with --key: verified_with without a snapshot digest', () => {
    const r = run('cli.js', ['grant', grant(), '--key', PEM_FILE]);
    assert.deepEqual(r.json.verified_with, { kid: 'k-117', key_sha256: KEY_SHA256, keyring_source: 'file' });
  });

  it('a receipt verified with --key / --keys: no snapshot digest', () => {
    const v = require('./vectors.json');
    const dir = tmp();
    fs.writeFileSync(path.join(dir, 'pub.pem'), v.public_key_pem);
    const tok = v.vectors.find((x) => x.name === 'valid_v4').token;
    const r = run('cli.js', [tok, '--key', path.join(dir, 'pub.pem')]);
    assert.equal(r.json.verified_with.keyring_snapshot_sha256, undefined);
  });

  it('a receipt verified against the pinned snapshot: keyring_snapshot_sha256 and one text line', () => {
    const tok = fs.readFileSync(path.join(__dirname, 'fixtures-receipt.txt'), 'utf8').trim();
    const r = run('cli.js', [tok]);
    assert.equal(r.code, 0);
    const before = { kid: '2026-07-k1', key_sha256: r.json.verified_with.key_sha256, keyring_source: 'pinned-snapshot' };
    assert.deepEqual(r.json.verified_with, { ...before, keyring_snapshot_sha256: SNAPSHOT_SHA12 });
    assert.equal(r.json.status, 'RETIRED_KEY_VALID_AT_ISSUE', 'the verdict is unchanged');
    const lines = r.stderr.split('\n').filter(Boolean);
    assert.equal(lines.length, 1);
    assert.match(lines[0], new RegExp(`pinned snapshot ${SNAPSHOT_SHA12} \\(the snapshot file carries no date\\)`));
    assert.equal(run('cli.js', [tok, '--json']).stderr, '', '--json: no note');
  });

  it('the snapshot file carries no date field (measured, so the line says so)', () => {
    const doc = JSON.parse(fs.readFileSync(path.join(ROOT, 'keys', 'coderifts-keys.json'), 'utf8'));
    assert.deepEqual(Object.keys(doc), ['keys']);
  });
});

/*
 * Addendum (2026-10-31 23:05) — finding 6 of round 10l, closed before the 1.1.7 tag.
 * MEASURED before (the tree after 10l): a v2 grant under a key with status "suspended" was GRANT_CURRENT (v1:
 * UNKNOWN_KEY / unknown_key_status); an entry with status "active" and a revoked_at verified v2 and v1 grants
 * (only --as-of refused it), and one with status "retired" + revoked_at said retired_kid; a v2 body with a
 * duplicate member, a lone surrogate or 1e400 was read through JSON.parse (duplicate executor_id → the last
 * one, GRANT_CURRENT). Negative first.
 */
describe('addendum: key status and revoked_at on v2 and v1, strict parse of the v2 body', () => {
  const v = require('./grant-vectors.json');
  const v1Tok = v.vectors.find((x) => x.name === 'EG-VALID').token;
  const v1Pub = crypto.createPublicKey(v.public_key_pem);
  const ring = (kid, pub, extra) => ({ keyring: new Map([[kid, { publicKey: pub, retired_at: null, ...extra }]]), expectedKid: null });
  const ago = (h) => iso(NOW - h * H);

  it('(1) v2: an unknown key status → UNKNOWN_KEY / unknown_key_status, as v1', () => {
    for (const status of ['suspended', 'ACTIVE', '']) {
      const a = G.verifyExecutionGrant(grant(), ring('k-117', KEY.publicKey, { status }));
      const b = G.verifyExecutionGrant(v1Tok, ring(v.kid, v1Pub, { status }));
      assert.deepEqual([a.status, a.reason], [b.status, b.reason], status);
      assert.deepEqual([a.status, a.reason], ['UNKNOWN_KEY', 'unknown_key_status'], status);
    }
  });

  it('(2) a revoked_at refuses at every instant, whatever the status, v2 and v1, with and without as-of', () => {
    for (const status of ['active', 'retired', null, 'revoked']) {
      const extra = { status, revoked_at: ago(10), compromised_at: ago(10), retired_at: status === 'retired' ? iso(NOW + 5 * H) : null };
      const now2 = G.verifyExecutionGrant(grant(), ring('k-117', KEY.publicKey, extra));
      const at = G.verifyExecutionGrant(grant({ not_before: ago(2) }), ring('k-117', KEY.publicKey, extra), { asOf: ago(1) });
      const v1r = G.verifyExecutionGrant(v1Tok, ring(v.kid, v1Pub, extra));
      for (const [r, what] of [[now2, 'v2'], [at, 'v2 as-of'], [v1r, 'v1']]) {
        assert.equal(r.status, 'UNKNOWN_KEY', `${status} ${what}`);
        assert.match(r.reason, /^revoked_kid/, `${status} ${what}`);
      }
      assert.equal(now2.reason, 'revoked_kid', `${status}: the same answer as status "revoked"`);
    }
  });

  // Signed over canonicalJson(JSON.parse(text)) — what a JSON.parse verifier reconstructs — so a refusal
  // below is the parser's, not the signature's.
  const fromText = (text) => {
    const sig = crypto.sign(null, Buffer.from(`crexec.v2|${canonicalJson(JSON.parse(text))}`, 'utf8'), KEY.privateKey);
    return `${Buffer.from(text, 'utf8').toString('base64url')}.${sig.toString('base64url')}`;
  };
  const bodyOf = (tok) => Buffer.from(tok.split('.')[0], 'base64url').toString('utf8');

  it('(3) v2 duplicate member, duplicate "v", lone surrogate, 1e400 → MALFORMED with the strict code; no payload echoed', () => {
    const text = bodyOf(grant());
    const cases = [
      ['duplicate_key', text.replace(/}$/, ',"executor_id":"exec-b"}')],
      ['duplicate_key', `{"v":"cr.exec.v1",${text.slice(1)}`],
      ['lone_surrogate', text.replace('"tenant_id":"t1"', '"tenant_id":"t\\ud800"')],
      ['non_finite', text.replace('"max_attempts":1', '"max_attempts":1e400')],
    ];
    for (const [code, t] of cases) {
      assert.notEqual(t, text, 'the mutation applied');
      let tok;
      try { tok = fromText(t); } catch (_) { tok = `${Buffer.from(t).toString('base64url')}.${Buffer.alloc(64).toString('base64url')}`; }
      const r = verify(tok, { intended: { executor_id: 'exec-b' } });
      assert.deepEqual([r.valid, r.status, r.reason], [false, 'MALFORMED', code], t.slice(0, 60));
      assert.equal('payload' in r, false, 'a body with no single reading is not echoed');
    }
  });

  it('(3) text that is not JSON keeps bad_json; a clean v2 body and a v1 body are unchanged', () => {
    const notJson = `${Buffer.from('this is not json').toString('base64url')}.${Buffer.alloc(64).toString('base64url')}`;
    assert.deepEqual([verify(notJson).status, verify(notJson).reason], ['MALFORMED', 'bad_json']);
    assert.equal(verify(fromText(bodyOf(grant()))).status, 'GRANT_CURRENT');
    assert.equal(G.verifyExecutionGrant(v1Tok, { publicKey: v1Pub, expectedKid: v.kid }).status, 'GRANT_CURRENT');
  });
});
