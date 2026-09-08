'use strict';

/**
 * 1465 — CLOSED ASSURANCE PROFILES, and the hole they close.
 *
 * ── THE REPRODUCTION, RUN BEFORE THE FIX ────────────────────────────────────────────────────
 *
 *   valid grant + committed + NO attestation + NO root, required: ['issuer_grant']
 *     -> AUTHORIZED_AND_COMMITTED, authorized_and_committed: true
 *
 * Nothing forged. `required[]` was a strictness dial that ALSO chose the name of success, so
 * asking for less produced the strongest word the vocabulary has. Every consumer reads
 * `authorized_and_committed` as the answer, and it was reachable by a caller that demanded one
 * authority out of four.
 *
 * A caller may still aggregate its own set — that is a legitimate question and several consumers
 * ask it. What it may not do is call the answer by the global name.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const {
  verifiedExecutionBinding, STATE, AUTHORITY, PROFILE, PROFILE_NAMES,
} = require('../verified-execution-binding.js');

/** A real, verifying grant — from the vendored capture when it is beside us, else minted here. */
function grantCase() {
  const capture = path.join(__dirname, '..', '..', 'coderifts-conformance',
    'fixtures', 'recorded', 'end-to-end', 'transcript.json');
  if (fs.existsSync(capture)) {
    const a = JSON.parse(fs.readFileSync(capture, 'utf8'));
    const keys = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'keys', 'coderifts-keys.json'), 'utf8'));
    return {
      token: a.issuance.execution_grant,
      keyring: new Map(keys.keys.map((k) => [k.kid, {
        publicKey: crypto.createPublicKey(k.public_key_pem), status: null,
      }])),
      now: Date.parse(a.issuance.grant.not_before) + 1000,
    };
  }
  // MINTED, so this file proves the same property in a bare checkout rather than skipping. The
  // grant is the input to the property under test, not the evidence of a run.
  const kid = 'PROFILE-TEST-KEY';
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const now = Date.now();
  const sha = (v) => `sha256:${crypto.createHash('sha256').update(String(v)).digest('hex')}`;
  const body = {
    v: 'cr.exec.v2', kid, grant_id: 'g-1', receipt_hash: sha('r'), tenant_id: 't',
    executor_id: 'e', adapter_id: 'a', operation: 'publish', target_uri: 'db://x/y',
    expected_state_token: 's', after_payload_hash: sha('p'), nonce_hash: sha('n'),
    policy_hash: sha('pol'), audience_hash: sha('aud'),
    not_before: new Date(now - 1000).toISOString(), expires_at: new Date(now + 600000).toISOString(),
    max_attempts: 1,
  };
  const canon = (v) => (v === null ? 'null' : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(',')}}`
      : JSON.stringify(v));
  const sig = crypto.sign(null, Buffer.from(`crexec.v2|${canon(body)}`, 'utf8'), privateKey);
  return {
    token: `${Buffer.from(JSON.stringify(body), 'utf8').toString('base64url')}.${sig.toString('base64url')}`,
    keyring: new Map([[kid, { publicKey, status: null }]]),
    now: now + 1,
  };
}

const G = grantCase();
const base = () => ({
  receipt: { verified: true },
  grant: { token: G.token, keyring: G.keyring, expectedKid: null, now: G.now },
  committed: true,
});

describe('a shorter required[] can no longer reach the global success token', () => {
  it('THE REPRODUCTION: required:[issuer_grant], no attestation, no root', () => {
    const r = verifiedExecutionBinding({ ...base(), required: [AUTHORITY.ISSUER_GRANT] });
    // The custom set really is met — the grant verifies — and that is said plainly.
    assert.equal(r.requirements_satisfied, true, r.shortfalls.join('; '));
    // …and it is NOT the global claim. This is the whole fix.
    assert.equal(r.state, STATE.CUSTOM_REQUIREMENTS_SATISFIED);
    assert.equal(r.authorized_and_committed, false);
    assert.equal(r.profile, null);
  });

  it('NO custom set can produce AUTHORIZED_AND_COMMITTED — checked over the powerset', () => {
    // Every subset, not a sample. A single reachable combination would restore the hole, and
    // "we tried a few" is how it survived the first time.
    const all = Object.values(AUTHORITY);
    for (let mask = 0; mask < (1 << all.length); mask += 1) {
      const required = all.filter((_, i) => mask & (1 << i));
      if (required.length === 0) continue;
      const r = verifiedExecutionBinding({ ...base(), required });
      assert.notEqual(r.state, STATE.AUTHORIZED_AND_COMMITTED,
        `required ${JSON.stringify(required)} reached the global success token`);
      assert.equal(r.authorized_and_committed, false);
    }
  });

  it('the DEFAULT set is a caller choice too, and lands in the same lane', () => {
    const r = verifiedExecutionBinding(base());
    assert.equal(r.profile, null);
    assert.notEqual(r.state, STATE.AUTHORIZED_AND_COMMITTED);
  });
});

describe('the closed profile', () => {
  it('TRUSTED_EXECUTOR_INTEGRITY_V1 demands receipt + grant + attestation + root', () => {
    // Read from the profile rather than restated: a set typed out twice drifts in one place.
    assert.deepEqual([...PROFILE.TRUSTED_EXECUTOR_INTEGRITY_V1.authorities].sort(),
      [AUTHORITY.EXECUTOR_ATTESTATION, AUTHORITY.ISSUER_GRANT, AUTHORITY.ONE_RUN_ROOT].sort());
  });

  it('grant + committed but NO attestation and NO root is COMMIT_UNPROVEN, not success', () => {
    const r = verifiedExecutionBinding({ ...base(), profile: 'TRUSTED_EXECUTOR_INTEGRITY_V1' });
    assert.equal(r.state, STATE.COMMIT_UNPROVEN);
    assert.equal(r.authorized_and_committed, false);
    assert.equal(r.profile, 'TRUSTED_EXECUTOR_INTEGRITY_V1');
    assert.ok(r.shortfalls.some((x) => x.startsWith('executor_attestation:')), r.shortfalls.join('; '));
  });

  it('the profile\'s authority set is NOT editable — asking for both is refused', () => {
    // Not resolved by precedence. A caller naming a profile AND listing authorities is asking two
    // questions, and answering one silently is how it comes to believe it got the other.
    const r = verifiedExecutionBinding({
      ...base(), profile: 'TRUSTED_EXECUTOR_INTEGRITY_V1', required: [AUTHORITY.ISSUER_GRANT],
    });
    assert.equal(r.authorized_and_committed, false);
    assert.ok(r.shortfalls[0].includes('not editable'), r.shortfalls.join('; '));
  });

  it('an UNKNOWN profile fails closed rather than falling back to a default', () => {
    const r = verifiedExecutionBinding({ ...base(), profile: 'TOTALLY_SECURE_V9' });
    assert.equal(r.state, STATE.UNAUTHORIZED);
    assert.ok(r.shortfalls[0].includes('unknown assurance profile'), r.shortfalls.join('; '));
    // The known set is named, so a caller written against a future version learns why.
    for (const n of PROFILE_NAMES) assert.ok(r.shortfalls[0].includes(n));
  });

  it('the profile states its own scope, and it is not an external witness', () => {
    const r = verifiedExecutionBinding({ ...base(), profile: 'TRUSTED_EXECUTOR_INTEGRITY_V1' });
    assert.equal(r.proof_scope, 'TRUSTED_EXECUTOR');
    assert.equal(r.externally_witnessed, false);
  });

  it('EXTERNALLY_WITNESSED_EXECUTION_V1 is NOT declared — an empty promise is worse than none', () => {
    // No signed-witness format exists, so a profile named for one could only ever be unsatisfiable.
    // Declaring it would put a name in the vocabulary that a reader would plan around.
    assert.ok(!PROFILE_NAMES.includes('EXTERNALLY_WITNESSED_EXECUTION_V1'));
  });
});
