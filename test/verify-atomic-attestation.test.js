'use strict';

/**
 * The public verifier for the executor seal.
 *
 * The vectors are minted by the PRODUCER (capability-demo demo/src/atomic.js), not by an encoder
 * written here — two implementations of one format drift while both suites stay green, and the
 * only defence is to test against the real one.
 *
 * The load-bearing property is that each bound field gets its OWN refusal. A verifier that
 * answered "unbound" to every mismatch would be correct and useless: an operator holding a seal
 * for the right grant but the wrong target could not tell that from a seal for the wrong grant.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const {
  verifyAtomicExecutionAttestation, parseAtomicAttestToken, STATUSES, ATOMIC_ATTEST_V,
} = require('../verify-atomic-attestation.js');

const V = JSON.parse(fs.readFileSync(path.join(__dirname, 'atomic-attest-vectors.json'), 'utf8'));
const byName = Object.fromEntries(V.vectors.map((v) => [v.name, v]));
const registry = () => ({ keys: [{ kid: V.kid, public_key_pem: V.public_key_pem, status: 'active' }] });

describe('atomic seal — the recorded vectors', () => {
  for (const v of V.vectors) {
    it(`${v.name} → ${v.expected.status}`, () => {
      const r = verifyAtomicExecutionAttestation(v.token, { registry: registry(), intended: v.intended });
      assert.equal(r.valid, v.expected.valid);
      assert.equal(r.status, v.expected.status);
      if (v.expected.reason) assert.equal(r.reason, v.expected.reason);
    });
  }

  it('the vectors were minted by the real producer, and say so', () => {
    assert.match(V.minted_by, /capability-demo demo\/src\/atomic\.js/);
    assert.equal(V.generated_by, 'test/gen-atomic-attest-vectors.js');
  });
});

describe('each bound field has its own refusal', () => {
  it('four distinct reasons, one per field', () => {
    const reasons = ['ATOMIC-UNBOUND-JTI', 'ATOMIC-UNBOUND-DEPLOYMENT',
      'ATOMIC-UNBOUND-DIGEST', 'ATOMIC-UNBOUND-TARGET']
      .map((n) => byName[n].expected.reason);
    assert.deepEqual(new Set(reasons).size, 4, `collapsed reasons: ${reasons.join(', ')}`);
    assert.deepEqual(reasons, [
      'grant_jti_mismatch', 'deployment_id_mismatch', 'mutation_digest_mismatch', 'target_id_mismatch',
    ]);
  });

  it('a mismatch reports what was expected and what was observed', () => {
    const v = byName['ATOMIC-UNBOUND-TARGET'];
    const r = verifyAtomicExecutionAttestation(v.token, { registry: registry(), intended: v.intended });
    assert.equal(r.expected, '/articles/7');
    assert.equal(r.observed, '/articles/9');
  });

  it('an UNSUPPLIED expectation is not checked — and not silently passed either', () => {
    // Verifying with no intended target still verifies the signature; it simply makes no claim
    // about the target. The result carries the field so a caller can compare it themselves.
    const v = byName['ATOMIC-UNBOUND-TARGET'];
    const r = verifyAtomicExecutionAttestation(v.token, { registry: registry() });
    assert.equal(r.valid, true);
    assert.equal(r.payload.fields.target_id, '/articles/9');
  });
});

describe('the key must be in force', () => {
  it('a revoked kid never passes, whatever the signature says', () => {
    const v = byName['ATOMIC-VALID'];
    const revoked = { keys: [{ kid: V.kid, public_key_pem: V.public_key_pem, status: 'revoked' }] };
    const r = verifyAtomicExecutionAttestation(v.token, { registry: revoked, intended: v.intended });
    assert.equal(r.valid, false);
    assert.equal(r.status, STATUSES.ATOMIC_ATTEST_KEY_NOT_IN_FORCE);
  });

  it('an unrecognised status fails closed', () => {
    const v = byName['ATOMIC-VALID'];
    const odd = { keys: [{ kid: V.kid, public_key_pem: V.public_key_pem, status: 'suspended' }] };
    assert.equal(verifyAtomicExecutionAttestation(v.token, { registry: odd }).valid, false);
  });

  it('a pinned PEM works for the air-gapped case', () => {
    const v = byName['ATOMIC-VALID'];
    const r = verifyAtomicExecutionAttestation(v.token, { pinnedKeyPem: V.public_key_pem, intended: v.intended });
    assert.equal(r.valid, true);
  });

  it('no key material at all → UNKNOWN_KEY, never a pass', () => {
    assert.equal(verifyAtomicExecutionAttestation(byName['ATOMIC-VALID'].token, {}).status,
      STATUSES.ATOMIC_ATTEST_UNKNOWN_KEY);
  });
});

describe('envelope discipline', () => {
  it('a cr.exec.attest.v1 token does NOT verify here — different envelope, different library', () => {
    const r = verifyAtomicExecutionAttestation(byName['ATOMIC-WRONG-ENVELOPE'].token, { registry: registry() });
    assert.equal(r.valid, false);
    assert.equal(r.status, STATUSES.ATOMIC_ATTEST_MALFORMED);
  });

  it('a preimage that is not a gate preimage is refused before any signature work', () => {
    const notGate = [ATOMIC_ATTEST_V, 'k', Buffer.from('hello', 'utf8').toString('base64url'), 'sig'].join('|');
    const p = parseAtomicAttestToken(notGate);
    assert.equal(p.ok, false);
    assert.equal(p.reason, 'not_a_gate_preimage');
  });

  it('the result carries what a valid seal does NOT prove', () => {
    const v = byName['ATOMIC-VALID'];
    const r = verifyAtomicExecutionAttestation(v.token, { registry: registry(), intended: v.intended });
    assert.match(r.does_not_prove, /transaction committed/);
  });
});

describe('the vendored core is untouched by this library', () => {
  it('verify.js is not required, directly or transitively', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'verify-atomic-attestation.js'), 'utf8');
    assert.ok(!/require\(['"]\.\/verify(\.js)?['"]\)/.test(src));
    // Only node builtins.
    const requires = [...src.matchAll(/require\(['"]([^'"]+)['"]\)/g)].map((m) => m[1]);
    assert.deepEqual(requires, ['node:crypto']);
  });
});
