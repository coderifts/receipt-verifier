'use strict';

/*
 * 1.1.4 (2026-10-18) — the v4 rule moves from the CLI into the core verifyReceipt.
 *
 * MEASURED 2026-10-17: the rule "a receipt used beside an envelope must be v4" lived only in
 * cli.js (1.1.1, P66). Two gateways that vendored the core (v1.0.3) admitted a real, production-signed
 * v2 receipt beside a forged ALLOW envelope, because the core returned valid:true. Now verifyReceipt
 * itself refuses: with opts.envelope present (any object — `{}` included, the CLI's JS truthiness) and a
 * receipt that verifies at v !== 4 → RECEIPT_VERSION_UNSUPPORTED, signature_status = the bare verdict.
 * A bare token with no envelope stays a signature check. verifyChain is unchanged (it never applies
 * an envelope per link; see the 1.1.4 CHANGELOG entry).
 *
 * Fixtures: test/fixtures-receipt.txt is a public production v2 receipt and test/fixtures-keys.json the
 * public key registry entry for its kid (public test fixtures, no private material).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { verifyReceipt, verifyChain, keyringFromDocument } = require('../verify.js');

const TOKEN = fs.readFileSync(path.join(__dirname, 'fixtures-receipt.txt'), 'utf8').trim();
const KEYRING = keyringFromDocument(JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures-keys.json'), 'utf8')), 'fixtures-keys.json');
const VECTORS = require('./vectors.json');
const V4 = VECTORS.vectors.find((v) => v.name === 'valid_v4');
const BIND = VECTORS.bind;
const V4CTX = { publicKey: VECTORS.public_key_pem, expectedKid: VECTORS.kid };
const ctx = { keyring: KEYRING, expectedKid: null };

const FORGED_ALLOW = { decision: 'ALLOW', execution_action: 'CONTINUE', safe_for_agent: true, repository: 'acme/api' };
const REASON = (v) => `receipt version v${v} binds no envelope and carries no expiry; only a v4 receipt is accepted with an envelope or --from-commit`;

describe('1.1.4 · verifyReceipt: an envelope needs a v4 receipt', () => {
  const bare = verifyReceipt(TOKEN, { ctx });

  it('the fixture is a real v2 receipt that verifies bare (the control the rule is measured against)', () => {
    assert.equal(bare.payload.v, 2);
    assert.equal(bare.valid, true, JSON.stringify(bare));
  });

  it('⚠⚠ v2 + a forged ALLOW envelope → RECEIPT_VERSION_UNSUPPORTED; signature_status is the bare verdict (was valid:true in the core)', () => {
    const r = verifyReceipt(TOKEN, { ctx, envelope: FORGED_ALLOW });
    assert.equal(r.valid, false);
    assert.equal(r.status, 'RECEIPT_VERSION_UNSUPPORTED');
    assert.equal(r.signature_status, bare.status);
    assert.equal(r.reason, REASON(2));
    assert.deepEqual(r.payload, bare.payload);
  });

  it('`{}` counts as an envelope (the CLI\'s truthiness)', () => {
    const r = verifyReceipt(TOKEN, { ctx, envelope: {} });
    assert.equal(r.status, 'RECEIPT_VERSION_UNSUPPORTED');
  });

  it('control: v2 with no envelope → unchanged (a signature check)', () => {
    assert.deepEqual(verifyReceipt(TOKEN, { ctx, envelope: null }), bare);
    assert.deepEqual(verifyReceipt(TOKEN, ctx), bare);
  });

  it('control: the valid_v4 vector bare, and the bound v4 + its envelope → unchanged', () => {
    const r = verifyReceipt(V4.token, { ctx: V4CTX });
    assert.equal(r.valid, V4.expected.valid);
    const b = verifyReceipt(BIND.token, { ctx: V4CTX, envelope: BIND.envelope });
    assert.equal(b.valid, true, JSON.stringify(b));
    assert.notEqual(b.status, 'RECEIPT_VERSION_UNSUPPORTED');
  });

  it('a failed signature keeps its own verdict (the rule applies only to a receipt that verifies)', () => {
    const tampered = TOKEN.slice(0, -4) + (TOKEN.endsWith('AAAA') ? 'BBBB' : 'AAAA');
    const r = verifyReceipt(tampered, { ctx, envelope: FORGED_ALLOW });
    assert.notEqual(r.status, 'RECEIPT_VERSION_UNSUPPORTED');
    assert.equal(r.valid, false);
  });

  it('verifyChain is unchanged: a chain checks links, not an envelope per link (A4)', () => {
    const r = verifyChain([TOKEN], { ctx, envelope: FORGED_ALLOW });
    assert.equal(r.chain.links[0].signature_valid, true);
  });
});

describe('1.1.4 · the same verdict from cli.js and verify.py (cross-language)', () => {
  const { spawnSync } = require('node:child_process');
  const os = require('node:os');
  const KEYS = path.join(__dirname, 'fixtures-keys.json');
  const ENV = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'rv-v4rule-')), 'env.json');
  fs.writeFileSync(ENV, JSON.stringify(FORGED_ALLOW));
  const py = spawnSync('python3', ['--version'], { encoding: 'utf8' });
  it(py.status === 0 ? 'v2 + an envelope: both refuse with RECEIPT_VERSION_UNSUPPORTED, exit 1, same JSON' : 'SKIPPED (named): no python3 here', (t) => {
    if (py.status !== 0) return t.skip('no python3');
    const js = spawnSync(process.execPath, [path.join(__dirname, '..', 'cli.js'), TOKEN, '--keys', KEYS, '--envelope', ENV, '--json'], { encoding: 'utf8' });
    const pyr = spawnSync('python3', [path.join(__dirname, '..', 'verify.py'), TOKEN, '--keys', KEYS, '--envelope', ENV], { encoding: 'utf8' });
    assert.equal(js.status, 1, js.stderr);
    assert.equal(pyr.status, 1, pyr.stderr);
    const a = JSON.parse(js.stdout);
    const b = JSON.parse(pyr.stdout);
    assert.equal(a.status, 'RECEIPT_VERSION_UNSUPPORTED');
    assert.equal(b.status, 'RECEIPT_VERSION_UNSUPPORTED');
    assert.equal(a.reason, b.reason);
    assert.equal(a.signature_status, b.signature_status);
  });
});
