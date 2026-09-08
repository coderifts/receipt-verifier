'use strict';

/**
 * The attestation must bind the SAME EXECUTION as the grant (1464).
 *
 * ── REPRODUCED ──────────────────────────────────────────────────────────────────────────────
 *
 * A correctly-signed grant issued against receipt R1, and a correctly-signed attestation from a
 * trusted executor committing receipt R2, sharing a grant_jti and a scope_hash — R1 != R2 — read
 * AUTHORIZED_AND_COMMITTED. Both signatures real, both parties trusted, and the two documents
 * describe DIFFERENT executions.
 *
 * `jti` and `scope_hash` were the only fields compared, and they are the two an assembler controls
 * most cheaply: they are copied FROM the grant INTO the attestation. Comparing them is comparing a
 * value with its own copy. What actually binds is the receipt each side was issued against.
 *
 * These tests live in the core because all five consumers quote it — the hole was one function
 * deep and five products wide.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const { verifiedExecutionBinding } = require('../verified-execution-binding.js');

const sha = (v) => `sha256:${crypto.createHash('sha256').update(String(v), 'utf8').digest('hex')}`;
const b64 = (o) => Buffer.from(JSON.stringify(o), 'utf8').toString('base64url');

const issuer = crypto.generateKeyPairSync('ed25519');
const executor = crypto.generateKeyPairSync('ed25519');
const IK = 'ISS';
const EK = 'EXEC';
const JTI = 'jti-1';
const SCOPE = sha('cs');
const R1 = sha('receipt-ONE');
const R2 = sha('receipt-TWO');

const RING = new Map([[IK, {
  publicKey: issuer.publicKey, status: 'active', retired_at: null, compromised_at: null,
}]]);
const REGISTRY = {
  keys: [{
    kid: EK, public_key_pem: executor.publicKey.export({ type: 'spki', format: 'pem' }),
    status: 'active', valid_from: null, retired_at: null,
  }],
};

const ATTEST_V = 'cr.exec.attest.v1';

/** The SDK's own signing-input builder, and its verifier — both loaded from the sibling package. */
function sdkModule() {
  try {
    // eslint-disable-next-line global-require, import/no-dynamic-require
    return require(require('node:path').join(process.env.HOME || '', 'sdk', 'dist', 'cjs', 'index.js'));
  } catch (_) { return null; }
}
const SDK = sdkModule();
const SIGNING_INPUT = SDK ? SDK.attestSigningInput : null;

function grant(over = {}) {
  const b = {
    v: 'cr.exec.v1', kid: IK, receipt_digest: R1, scope_hash: SCOPE, audience: 'v:x',
    operation: 'merge', target_id: 't', jti: JTI,
    iat: '2026-01-01T00:00:00Z', exp: '2099-01-01T00:00:00Z', ...over,
  };
  const p = ['crexec.v1', b.kid, b.receipt_digest, b.scope_hash, b.audience, b.operation,
    b.target_id, b.jti, b.iat, b.exp];
  // THE ATOMIC SLOT. cr.exec.v1 appends state_nonce to the signing input only when it is
  // non-empty, so a helper that omits it produces an invalid signature the moment a test uses one
  // — and the case then fails as UNAUTHORIZED, one authority before the one it meant to exercise.
  if (b.state_nonce) p.push(b.state_nonce);
  return `${b64(b)}.${crypto.sign(null, Buffer.from(p.join('|'), 'utf8'), issuer.privateKey).toString('base64url')}`;
}

/** Signed exactly as the SDK signs, so these are real attestations and not shaped objects. */
function attest(over = {}) {
  const b = {
    v: ATTEST_V, executor_kid: EK, grant_jti: JTI, receipt_digest: R1, scope_hash: SCOPE,
    committed_at: new Date(Date.now() - 1000).toISOString(), ...over,
  };
  for (const k of Object.keys(b)) if (b[k] === undefined) delete b[k];
  // THE SDK'S OWN SIGNING INPUT, not a reconstruction. A first attempt rebuilt the field join by
  // hand and omitted a trailing slot, so every attestation failed its signature and the positive
  // control failed for a reason that had nothing to do with binding. The core takes the same
  // position: it holds no attestation format knowledge of its own.
  return [ATTEST_V, EK, b64(b),
    crypto.sign(null, Buffer.from(SIGNING_INPUT(b), 'utf8'), executor.privateKey).toString('base64url'),
  ].join('|');
}

const VERIFY = SDK ? SDK.verifyExecutionAttestation : null;

/** RFC 8785-shaped canonical JSON — v2 signs the whole body under it. */
function canonicalJson(v) {
  if (v === null) return 'null';
  if (typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(',')}}`;
}

/** A genuinely signed cr.exec.v2 grant — the path on which a state token IS carried. */
function grantV2(over = {}) {
  const now = Date.now();
  const b = {
    v: 'cr.exec.v2', kid: IK, grant_id: JTI, receipt_hash: R1, tenant_id: 'd', executor_id: 'e',
    adapter_id: 'a', operation: 'merge', target_uri: 'db://d/a',
    expected_state_token: sha(''), after_payload_hash: SCOPE, nonce_hash: sha('n'),
    policy_hash: sha(''), audience_hash: sha(''),
    not_before: new Date(now - 1000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
    expires_at: new Date(now + 300000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
    max_attempts: 1, ...over,
  };
  return `${b64(b)}.${crypto.sign(null, Buffer.from(`crexec.v2|${canonicalJson(b)}`, 'utf8'), issuer.privateKey).toString('base64url')}`;
}

/**
 * This file asks a CUSTOM question — does the grant bind to the attestation — and not "is this run
 * authorized and committed". Since 1465 those have different answers by design: a custom authority
 * set can be satisfied, and a satisfied custom set is NOT the global success token. The assertions
 * below therefore read `requirements_satisfied`, which is what this file was ever measuring.
 */
function ask(grantToken, attestToken) {
  return verifiedExecutionBinding({
    receipt: { verified: true },
    grant: { token: grantToken, keyring: RING, expectedKid: null, now: Date.now() + 1 },
    attestation: { token: attestToken, registry: REGISTRY, verify: VERIFY },
    committed: true,
    required: ['issuer_grant', 'executor_attestation'],
  });
}
const SATISFIED = 'CUSTOM_REQUIREMENTS_SATISFIED';

describe('cross-execution binding', { skip: VERIFY ? false : 'the SDK attestation verifier is not beside this repo' }, () => {
  it('POSITIVE CONTROL: same receipt, matching fields → AUTHORIZED_AND_COMMITTED', () => {
    // Without this the refusals below would be indistinguishable from refusing everything.
    const r = ask(grant(), attest());
    assert.equal(r.state, SATISFIED, r.shortfalls.join('; '));
  });

  it('REPRODUCED THEN CLOSED: a grant and an attestation from DIFFERENT receipts do not pair', () => {
    const r = ask(grant({ receipt_digest: R1 }), attest({ receipt_digest: R2 }));
    assert.notEqual(r.state, SATISFIED);
    // COMMIT_UNPROVEN, not UNAUTHORIZED: the issuer grant is fine, and it is the attestation that
    // fails to bind. Naming the wrong authority would send a reader to the wrong fix.
    assert.equal(r.state, 'COMMIT_UNPROVEN');
    assert.ok(r.shortfalls.some((s) => /two different executions/.test(s)), r.shortfalls.join('; '));
  });

  it('an attestation naming NO receipt is a mismatch — unstated is not "the same"', () => {
    const r = ask(grant(), attest({ receipt_digest: '' }));
    assert.equal(r.state, 'COMMIT_UNPROVEN');
  });

  it('a STALE state token is a mismatch when both sides state one (v2)', () => {
    // ON THE v2 PATH, and that is a measurement, not a preference. This core's cr.exec.v1 allowed
    // set is `['v', ...SIGNED_FIELDS]` and refuses `state_nonce` as unknown_field, so a v1 ATOMIC
    // grant cannot reach this check at all — see the finding pinned below.
    assert.equal(ask(grantV2({ expected_state_token: 'nonce-A' }), attest({ state_nonce: 'nonce-B' })).state,
      'COMMIT_UNPROVEN');
    assert.equal(ask(grantV2({ expected_state_token: 'nonce-A' }), attest({ state_nonce: 'nonce-A' })).state,
      SATISFIED);
  });

  it('a field only ONE side states is not a mismatch — an omission is not a disagreement', () => {
    // Demanding a field the other side never carries would refuse honest pairs. This is the line
    // between binding and brittleness.
    const r = ask(grantV2({ expected_state_token: 'nonce-A' }), attest());
    assert.equal(r.state, SATISFIED, r.shortfalls.join('; '));
  });

  it('CLOSED (1470): this core now ACCEPTS the v1 ATOMIC grant the demo executor issues', () => {
    // THIS ASSERTION WAS INVERTED, and the inversion is the record.
    //
    // It was written to PIN a divergence: capability-demo's middleware carries
    // OPTIONAL_SIGNED_FIELDS = ['state_nonce', 'deployment_id'], this core's allowed set was
    // ['v', ...SIGNED_FIELDS], so a v1 ATOMIC grant read MALFORMED / unknown_field — fail-closed
    // and wrong, in five consumers at once. The comment said the fix must be a decision rather
    // than a discovery; 1470 made that decision, and this test failing is how it announced itself.
    //
    // The widening is BY NAME and the closed set still closes — both halves are pinned in
    // test/v1-atomic-optional-fields.test.js.
    const r = ask(grant({ state_nonce: 'nonce-A' }), attest({ state_nonce: 'nonce-A' }));
    assert.equal(r.state, SATISFIED, r.shortfalls.join('; '));
  });

  it('THE FORMAT BOUNDS THE CHECK: cr.exec.attest.v1 is a CLOSED field set', () => {
    // MEASURED, and it is why target / operation / tenant / audience / policy are NOT cross-checked
    // and are named in does_not_prove instead. An attestation carrying any other key — including a
    // grant-token digest, which would be the tightest possible join — is refused by its own
    // verifier before this core ever sees it. Binding the grant BYTES needs a format change, not a
    // comparison here.
    const bad = attest({ grant_token_digest: sha('some other grant') });
    const v = VERIFY(bad, { registry: REGISTRY });
    assert.equal(v.valid, false);
    assert.equal(v.reason, 'unknown_field');
  });

  it('the grant jti and scope are STILL checked — the new checks are additive', () => {
    assert.equal(ask(grant(), attest({ grant_jti: 'other' })).state, 'COMMIT_UNPROVEN');
    assert.equal(ask(grant(), attest({ scope_hash: sha('other') })).state, 'COMMIT_UNPROVEN');
  });
});
