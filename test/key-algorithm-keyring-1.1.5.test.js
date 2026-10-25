'use strict';

/*
 * 1.1.5 (2026-10-25) — the pinned keyring is the live registry; only Ed25519 verifies a receipt; a bad
 * keyring entry is skipped, not fatal; a valid verdict names the key that verified it (verified_with).
 *
 * MEASURED 2026-10-25 on 1.1.4 (Node 24.12), keyring = test/fixtures-keys.json plus one extra entry:
 *   C  an entry with an unparseable PEM      → "could not load public key", exit 2 (the good key unusable)
 *   D  an entry with no public_key_pem       → "registry entry missing kid/public_key_pem", exit 2
 *   E  an ML-DSA-65 key + an ML-DSA-signed receipt → { valid: true, VERIFIED_CURRENT } (JS only;
 *      verify.py threw "public key is not Ed25519" at load)
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'cli.js');
const PY = path.join(ROOT, 'verify.py');
const PIN = path.join(ROOT, 'keys', 'coderifts-keys.json');
const TOKEN = fs.readFileSync(path.join(__dirname, 'fixtures-receipt.txt'), 'utf8').trim();
const FIXTURE_KEYS = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures-keys.json'), 'utf8'));
const ALG = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures-key-alg-1.1.5.json'), 'utf8'));
const { spkiDerFromPem } = require('../verify.js');

const js = (args) => spawnSync(process.execPath, [CLI, ...args, '--json'], { encoding: 'utf8' });
const py = (args) => spawnSync('python3', [PY, ...args], { encoding: 'utf8' });
const out = (r) => JSON.parse(r.stdout);
const derSha = (pem) => crypto.createHash('sha256').update(spkiDerFromPem(pem)).digest('hex');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rv-115-'));
const writeKeys = (name, keys) => { const f = path.join(tmp, name); fs.writeFileSync(f, JSON.stringify({ keys })); return f; };

/** Both ports, same bytes, same exit; returns the parsed verdict. */
function both(args) {
  const a = js(args);
  const b = py(args);
  assert.equal(a.stdout, b.stdout, `js/py differ for ${args.join(' ').slice(0, 80)}\n js: ${a.stdout}\n py: ${b.stdout}`);
  assert.equal(a.status, b.status, 'js/py exit codes differ');
  return { v: out(a), code: a.status };
}

describe('1.1.5 · the pinned keyring is the live registry (2026-10-25)', () => {
  const pin = JSON.parse(fs.readFileSync(PIN, 'utf8'));
  it('2026-10-k1 active, 2026-07-k1 retired at 2026-10-21, valid_from/retired_at carried', () => {
    assert.deepEqual(pin.keys.map((k) => [k.kid, k.status, k.valid_from, k.retired_at]), [
      ['2026-10-k1', 'active', null, null],
      ['2026-07-k1', 'retired', null, '2026-10-21T00:00:00.000Z'],
    ]);
  });
  it('the 2026-07-k1 fixture (signed 2026-08-26) → RETIRED_KEY_VALID_AT_ISSUE, verified_with names the pinned key', () => {
    const { v, code } = both([TOKEN]);
    assert.equal(code, 0);
    assert.equal(v.valid, true);
    assert.equal(v.status, 'RETIRED_KEY_VALID_AT_ISSUE');
    assert.deepEqual(v.verified_with, {
      kid: '2026-07-k1',
      key_sha256: derSha(pin.keys.find((k) => k.kid === '2026-07-k1').public_key_pem),
      keyring_source: 'pinned-snapshot',
    });
  });
  it('a receipt claiming 2026-10-k1 resolves to the active pinned key (a bad signature, not UNKNOWN_KEY)', () => {
    // No 2026-10-k1-signed receipt was available offline (measured 2026-10-25): this proves the kid
    // resolves, not that a real 10-k1 receipt is VERIFIED_CURRENT.
    const forged = `${Buffer.from(JSON.stringify({ v: 2, kid: '2026-10-k1', fp: 'sha256:0', prev: 'null', caller: 'anon', ts: '2026-10-25T00:00:00.000Z', reg: '' })).toString('base64url')}.${Buffer.alloc(64).toString('base64url')}`;
    const { v, code } = both([forged]);
    assert.equal(code, 1);
    assert.equal(v.status, 'INVALID_SIGNATURE');
    assert.equal(v.reason, 'signature_mismatch');
    assert.equal('verified_with' in v, false, 'no key verified it, so nothing is named');
  });
});

describe('1.1.5 · verified_with: kid, key_sha256 (SPKI DER), keyring_source', () => {
  let server;
  let url;
  before(async () => {
    server = http.createServer((_req, res) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(FIXTURE_KEYS)); });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    url = `http://127.0.0.1:${server.address().port}/keys.json`;
  });
  after(() => server.close());

  const key = FIXTURE_KEYS.keys[0];
  it('--keys <file> → file', () => {
    const { v } = both([TOKEN, '--keys', path.join(__dirname, 'fixtures-keys.json')]);
    assert.deepEqual(v.verified_with, { kid: key.kid, key_sha256: derSha(key.public_key_pem), keyring_source: 'file' });
  });
  it('--key <pem> → file', () => {
    const pem = path.join(tmp, 'k.pem');
    fs.writeFileSync(pem, key.public_key_pem);
    const { v } = both([TOKEN, '--key', pem]);
    assert.deepEqual(v.verified_with, { kid: key.kid, key_sha256: derSha(key.public_key_pem), keyring_source: 'file' });
  });
  it('--keys <url> → url', async () => {
    const r = await new Promise((resolve) => {
      const c = require('node:child_process').spawn(process.execPath, [CLI, TOKEN, '--keys', url, '--json']);
      let s = '';
      c.stdout.on('data', (d) => { s += d; });
      c.on('close', (code) => resolve({ s, code }));
    });
    assert.equal(r.code, 0);
    assert.deepEqual(JSON.parse(r.s).verified_with, { kid: key.kid, key_sha256: derSha(key.public_key_pem), keyring_source: 'url' });
  });
  it('the sentence that names what verified_with does not prove is the last does_not_prove line', () => {
    const { v } = both([TOKEN]);
    assert.match(v.does_not_prove.at(-1), /^that the keyring is authentic — verified_with names the key/);
  });
});

describe('1.1.5 · only Ed25519 verifies a receipt (JS and Python alike)', () => {
  it('E: an ML-DSA-65 key and an ML-DSA-signed receipt → invalid, "unsupported key algorithm: ML-DSA-65"', () => {
    const keys = writeKeys('e.json', [{ kid: 'pq-1', alg: 'ML-DSA-65', status: 'active', public_key_pem: ALG.mldsa_public_key_pem }]);
    const { v, code } = both([ALG.mldsa_signed_receipt, '--keys', keys]);
    assert.equal(code, 1);
    assert.equal(v.valid, false);
    assert.equal(v.status, 'INVALID_SIGNATURE');
    assert.equal(v.reason, 'unsupported key algorithm: ML-DSA-65');
  });
  it('E without a declared alg: the algorithm is read from the PEM (ML-DSA-65)', () => {
    const keys = writeKeys('e2.json', [{ kid: 'pq-1', status: 'active', public_key_pem: ALG.mldsa_public_key_pem }]);
    assert.equal(both([ALG.mldsa_signed_receipt, '--keys', keys]).v.reason, 'unsupported key algorithm: ML-DSA-65');
  });
  it('A: an Ed25519 PEM labelled alg ML-DSA-65 is refused too (the declared alg is not trusted)', () => {
    const keys = writeKeys('a.json', FIXTURE_KEYS.keys.map((k) => ({ ...k, alg: 'ML-DSA-65' })));
    const { v } = both([TOKEN, '--keys', keys]);
    assert.equal(v.valid, false);
    assert.equal(v.reason, 'unsupported key algorithm: ML-DSA-65');
  });
  it('a declared alg Ed25519 (or EdDSA) is accepted', () => {
    for (const alg of ['Ed25519', 'EdDSA']) {
      const keys = writeKeys(`ok-${alg}.json`, FIXTURE_KEYS.keys.map((k) => ({ ...k, alg })));
      assert.equal(both([TOKEN, '--keys', keys]).v.valid, true, alg);
    }
  });
  it('--key with a non-Ed25519 PEM → invalid with the reason, not loaded and accepted', () => {
    const pem = path.join(tmp, 'ml.pem');
    fs.writeFileSync(pem, ALG.mldsa_public_key_pem);
    const { v, code } = both([ALG.mldsa_signed_receipt, '--key', pem]);
    assert.equal(code, 1);
    assert.equal(v.reason, 'unsupported key algorithm: ML-DSA-65');
  });
});

describe('1.1.5 · the keyring loads per entry: a bad entry is skipped and named, the rest verify', () => {
  it('C: an unparseable PEM beside the good key → the good key verifies; keyring_warnings names the entry', () => {
    const keys = writeKeys('c.json', [...FIXTURE_KEYS.keys, { kid: 'pq-1', alg: 'ML-DSA-65', status: 'active', public_key_pem: ALG.bad_pem }]);
    const { v, code } = both([TOKEN, '--keys', keys]);
    assert.equal(code, 0);
    assert.equal(v.valid, true);
    assert.deepEqual(v.keyring_warnings, ['registry entry pq-1: unparseable public_key_pem — skipped']);
  });
  it('D: an entry with no public_key_pem → skipped and named; the good key verifies', () => {
    const keys = writeKeys('d.json', [...FIXTURE_KEYS.keys, { kid: 'pq-1', alg: 'ML-DSA-65', status: 'active', public_key_jwk: { kty: 'AKP' } }]);
    const { v, code } = both([TOKEN, '--keys', keys]);
    assert.equal(code, 0);
    assert.deepEqual(v.keyring_warnings, ['registry entry pq-1: missing public_key_pem — skipped']);
  });
  it('entries with no kid or not an object are named by position', () => {
    const keys = writeKeys('pos.json', [{ public_key_pem: ALG.bad_pem }, 'x', ...FIXTURE_KEYS.keys]);
    assert.deepEqual(both([TOKEN, '--keys', keys]).v.keyring_warnings, [
      'registry entry #0: missing kid — skipped',
      'registry entry #1: not an object — skipped',
    ]);
  });
  it('a keyring with no usable key at all is still an error (exit 2), naming why', () => {
    const keys = writeKeys('none.json', [{ kid: 'pq-1', public_key_pem: ALG.bad_pem }]);
    const a = js([TOKEN, '--keys', keys]);
    const b = py([TOKEN, '--keys', keys]);
    assert.equal(a.status, 2);
    assert.equal(b.status, 2);
    assert.match(a.stderr, /no usable keys in registry .*pq-1: unparseable public_key_pem/);
    assert.match(b.stderr, /no usable keys in registry .*pq-1: unparseable public_key_pem/);
  });
  it('a clean keyring prints no keyring_warnings (additive only)', () => {
    assert.equal('keyring_warnings' in both([TOKEN, '--keys', path.join(__dirname, 'fixtures-keys.json')]).v, false);
  });
});
