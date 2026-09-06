'use strict';

/**
 * cr.exec.v2 rejects a field it does not know — and `environment` is one of them (1429).
 *
 * ── THE BOUNDARY, MEASURED 2026-09-06 ───────────────────────────────────────────────────────
 *
 * The v2 issuer CAN write an `environment` key into the signed body
 * (coderifts-app src/verdict-core/execution-grant-v2.js, 1325: `...(environment === null ? {} : { environment })`).
 * This verifier's allowed set is `[...V2_REQUIRED_STRINGS, 'max_attempts']` and does NOT include
 * it, so such a grant would be refused MALFORMED / unknown_field — by us, about a token we issued.
 *
 * It is LATENT, not broken. The only caller of the issuer is the authorize handler
 * (coderifts-app src/change-set.js:1336) and it does not pass `environment`; the write is
 * unreachable as wired. Measured by reading, not assumed.
 *
 * ── WHY THE SET IS NOT SIMPLY OPENED ────────────────────────────────────────────────────────
 *
 * Everything in a v2 body is signed — the preimage is the canonical JSON of the whole object — so
 * a forged field cannot be added without breaking the signature. The closed set is therefore not
 * protecting against injection. It protects against SEMANTIC DRIFT: a future field that RESTRICTS
 * use (a constraint, an audience narrowing, a single-use marker) must not be silently ignored by
 * an older verifier that then says GRANT_CURRENT. Refusing what we do not understand is the
 * fail-closed answer to a field whose meaning we cannot see.
 *
 * ── WHAT TO DO WHEN THE ISSUER IS WIRED ─────────────────────────────────────────────────────
 *
 * Add `environment` to V2_OPTIONAL_STRINGS in verify-grant.js — explicitly, by name, NOT by
 * opening the set — and re-vendor into every consumer that pins this file (agent-guard,
 * conformance, contract-gate). This test then flips from "is refused" to "is accepted", which is
 * the moment to notice that the vendored copies are behind.
 *
 * Until then this test PINS the boundary, so nobody discovers it as a production refusal.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const { verifyExecutionGrant } = require('../verify-grant.js');

const sha = (v) => `sha256:${crypto.createHash('sha256').update(String(v), 'utf8').digest('hex')}`;

function canonicalJson(value) {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'boolean' || t === 'string' || t === 'number') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

/** A genuinely signed v2 grant, optionally carrying extra keys. */
function mint(extra = {}) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const kid = 'TEST-ISSUER';
  const now = Date.now();
  const body = {
    v: 'cr.exec.v2',
    kid,
    grant_id: '11111111-2222-4333-8444-555555555555',
    receipt_hash: sha('receipt'),
    tenant_id: 'default',
    executor_id: 'demo-deployment',
    adapter_id: 'postgres.atomic',
    operation: 'publish',
    target_uri: 'db://demo-deployment/articles',
    expected_state_token: sha('state'),
    after_payload_hash: sha('body'),
    nonce_hash: sha('nonce'),
    policy_hash: sha(''),
    audience_hash: sha(''),
    not_before: new Date(now - 1000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
    expires_at: new Date(now + 300000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
    max_attempts: 1,
    ...extra,
  };
  const sig = crypto.sign(null, Buffer.from(`crexec.v2|${canonicalJson(body)}`, 'utf8'), privateKey);
  return {
    token: `${Buffer.from(JSON.stringify(body), 'utf8').toString('base64url')}.${sig.toString('base64url')}`,
    ctx: { publicKey, expectedKid: null },
    now: now + 1,
  };
}

describe('cr.exec.v2 — the unknown-field boundary', () => {
  it('a grant with no extra fields verifies (so every refusal below is about the extra field)', () => {
    const g = mint();
    const r = verifyExecutionGrant(g.token, { ctx: g.ctx, now: g.now });
    assert.equal(r.valid, true, `${r.status}/${r.reason}`);
  });

  it('THE BOUNDARY: a CORRECTLY SIGNED grant carrying `environment` is refused unknown_field', () => {
    // Not a forgery: the signature verifies. It is refused for its VOCABULARY, which is the
    // fail-closed answer to a field this verifier cannot interpret.
    const g = mint({ environment: 'production' });
    const r = verifyExecutionGrant(g.token, { ctx: g.ctx, now: g.now });
    assert.equal(r.valid, false);
    assert.equal(r.status, 'MALFORMED');
    assert.equal(r.reason, 'unknown_field');
  });

  it('the same is true of any other unknown key — the rule is general, not about `environment`', () => {
    for (const k of ['constraints', 'single_use', 'audience', 'anything_at_all']) {
      const g = mint({ [k]: 'x' });
      const r = verifyExecutionGrant(g.token, { ctx: g.ctx, now: g.now });
      assert.equal(r.reason, 'unknown_field', `${k} was accepted`);
    }
  });

  it('a FORGED extra field is refused by the signature, not only by the vocabulary', () => {
    // Proves the closed set is not what stands between us and injection: everything is signed.
    const g = mint();
    const [payload, sigPart] = g.token.split('.');
    const body = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    body.environment = 'production';
    const forged = `${Buffer.from(JSON.stringify(body), 'utf8').toString('base64url')}.${sigPart}`;
    const r = verifyExecutionGrant(forged, { ctx: g.ctx, now: g.now });
    assert.equal(r.valid, false);
    // unknown_field is reported first (structure before signature); either way it never verifies.
    assert.ok(['unknown_field', 'signature_mismatch'].includes(r.reason), r.reason);
  });
});
