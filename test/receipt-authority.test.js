'use strict';

/**
 * THE DECISION RECEIPT IS VERIFIED, NOT ASSERTED — the fourth caller-boolean, closed.
 *
 * ── THE REPRODUCTION ────────────────────────────────────────────────────────────────────────
 *
 *   receipt: { verified: true }   // no token, no keyring, nothing checked anywhere
 *   + a real grant + committed + profile TRUSTED_EXECUTOR_INTEGRITY_V1
 *     -> AUTHORIZED_AND_COMMITTED
 *
 * Nothing forged. A caller set a flag and the core believed it, because the core had no way not
 * to: it was never given the receipt. `receipt_caller_asserted: true` was reported — honest, and
 * not a gate, because nothing branched on it.
 *
 * The published 7/7 capture never relied on this (the conformance measure checks the chain receipt
 * separately), so no shipped claim was wrong. The CORE's contract was, and the core is what five
 * consumers share.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const {
  verifiedExecutionBinding, STATE, AUTHORITY,
} = require('../verified-execution-binding.js');

const KID = 'RECEIPT-AUTH-KEY';
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const RING = new Map([[KID, { publicKey, status: null }]]);
const NOW = Date.now();
const sha = (v) => `sha256:${crypto.createHash('sha256').update(String(v)).digest('hex')}`;
const canon = (v) => {
  if (v === null) return 'null';
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`;
  if (typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(',')}}`;
  }
  return JSON.stringify(v);
};

const GRANT = (() => {
  const b = {
    v: 'cr.exec.v2', kid: KID, grant_id: 'g-1', receipt_hash: sha('r'), tenant_id: 't',
    executor_id: 'e', adapter_id: 'a', operation: 'publish', target_uri: 'db://x/y',
    expected_state_token: 's', after_payload_hash: sha('p'), nonce_hash: sha('n'),
    policy_hash: sha('pol'), audience_hash: sha('aud'),
    not_before: new Date(NOW - 1000).toISOString(),
    expires_at: new Date(NOW + 600000).toISOString(), max_attempts: 1,
  };
  const sig = crypto.sign(null, Buffer.from(`crexec.v2|${canon(b)}`, 'utf8'), privateKey);
  return `${Buffer.from(JSON.stringify(b), 'utf8').toString('base64url')}.${sig.toString('base64url')}`;
})();

const base = (receipt) => ({
  receipt,
  grant: { token: GRANT, keyring: RING, expectedKid: null, now: NOW + 1 },
  committed: true,
});

describe('a caller-asserted receipt never reaches the global claim', () => {
  it('THE REPRODUCTION: verified:true, no token, no keyring, closed profile', () => {
    const r = verifiedExecutionBinding({
      ...base({ verified: true }), profile: 'TRUSTED_EXECUTOR_INTEGRITY_V1',
    });
    assert.equal(r.authorized_and_committed, false,
      'a receipt nobody verified reached AUTHORIZED_AND_COMMITTED');
    assert.notEqual(r.state, STATE.AUTHORIZED_AND_COMMITTED);
    assert.equal(r.receipt_caller_asserted, true);
  });

  it('and the shortfall SAYS what was not checked, rather than only flagging it', () => {
    const r = verifiedExecutionBinding({
      ...base({ verified: true }), required: [AUTHORITY.ISSUER_GRANT],
    });
    assert.ok(r.shortfalls.some((s) => s.startsWith('decision_receipt:')), r.shortfalls.join('; '));
  });

  it('a CUSTOM aggregation may still own that determination — it just is not the global name', () => {
    // Not a downgrade to failure. A caller that has verified the receipt elsewhere is entitled to
    // say so; what it may not do is have the core call the result by the word every consumer reads
    // as the answer.
    const r = verifiedExecutionBinding({
      ...base({ verified: true }), required: [AUTHORITY.ISSUER_GRANT],
    });
    assert.equal(r.state, STATE.CUSTOM_REQUIREMENTS_SATISFIED);
    assert.equal(r.authorized_and_committed, false);
  });
});

describe('when the receipt CAN be checked, the core checks it', () => {
  it('a malformed token is refused — not accepted because `verified: true` was also set', () => {
    // The direction that matters: a caller supplying BOTH a flag and a broken token must not have
    // the flag win. The token is the evidence; the flag is an opinion.
    const r = verifiedExecutionBinding({
      ...base({ verified: true, token: 'not-a-receipt', keyring: RING }),
      profile: 'TRUSTED_EXECUTOR_INTEGRITY_V1',
    });
    assert.equal(r.authorized_and_committed, false);
    assert.ok(r.shortfalls.some((s) => /receipt: the decision receipt did not verify \(/.test(s)),
      r.shortfalls.join('; '));
    // …and it is NOT reported as caller-asserted: something WAS checked, and it failed.
    assert.equal(r.receipt_caller_asserted, false);
  });

  it('a token with no key source is refused, and says which half is missing', () => {
    const r = verifiedExecutionBinding({ ...base({ token: 'x.y' }) });
    assert.equal(r.authorized_and_committed, false);
    assert.ok(r.shortfalls.some((s) => s.includes('without a keyring or public key')),
      r.shortfalls.join('; '));
  });

  it('no receipt at all is refused, and says so plainly', () => {
    const r = verifiedExecutionBinding({ ...base({}) });
    assert.ok(r.shortfalls.some((s) => s.includes('no decision receipt was supplied')),
      r.shortfalls.join('; '));
  });
});

describe('the reporting field is kept honest', () => {
  it('receipt_caller_asserted is true ONLY when nothing was checked here', () => {
    const asserted = verifiedExecutionBinding({ ...base({ verified: true }) });
    const attempted = verifiedExecutionBinding({ ...base({ verified: true, token: 'bad', keyring: RING }) });
    assert.equal(asserted.receipt_caller_asserted, true);
    assert.equal(attempted.receipt_caller_asserted, false);
  });
});
