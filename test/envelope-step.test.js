'use strict';

/**
 * The decision's next step is readable only when the envelope binding verifies.
 *
 * WHY THIS MATTERS MORE THAN AN ORDINARY VECTOR. `next_agent_step` is guidance an agent ACTS on —
 * revert, re-preflight, escalate. It travels inside the decision envelope, and the envelope is
 * bound to the receipt by `bh`. Swap the step after signing and the envelope stops hashing to `bh`.
 * A consumer that read the step off an envelope it had not verified would be taking instructions
 * from whoever last edited the JSON, which is the entire attack this binding exists to refuse.
 *
 * `step_readable` is a CONSUMER rule, not a verifier output: no verifier surfaces the step. The
 * `readStep` helper below is that rule, written once and driven by every vector, so "must not be
 * surfaced" is executable rather than a sentence in a comment.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const core = require('../verify.js');

const VECTORS = JSON.parse(fs.readFileSync(path.join(__dirname, 'envelope-step-vectors.json'), 'utf8'));
const byName = Object.fromEntries(VECTORS.vectors.map((v) => [v.name, v]));

function keyring() {
  return new Map([[VECTORS.kid, {
    publicKey: core.keyFromPem(VECTORS.public_key_pem),
    status: 'active', retired_at: null, revoked_at: null, compromised_at: null,
  }]]);
}

/**
 * THE CONSUMER RULE, in one place: verify first, and read the step only from an envelope that
 * verified. A null return is "you may not read this", not "there was no step".
 */
function readStep(vector) {
  const r = core.verifyReceipt(vector.token, {
    ctx: { keyring: keyring(), expectedKid: null },
    envelope: vector.envelope,
  });
  if (!r.valid) return { verdict: r, step: null, refused: true };
  const env = vector.envelope || {};
  return { verdict: r, step: env.next_agent_step ?? null, refused: false };
}

describe('envelope-step vectors — the reference verdicts', () => {
  for (const v of VECTORS.vectors) {
    it(`${v.name} → ${v.js.valid ? 'verifies' : 'fails'} ${v.js.status}`, () => {
      const r = core.verifyReceipt(v.token, {
        ctx: { keyring: keyring(), expectedKid: null }, envelope: v.envelope,
      });
      assert.equal(r.valid, v.js.valid);
      assert.equal(r.status, v.js.status);
      if (v.js.reason) assert.equal(r.reason, v.js.reason);
    });
  }
});

describe('the step is readable only when the binding verifies', () => {
  it('(a) bound: the step is readable and byte-equal to what was signed', () => {
    const v = byName['ENVSTEP-BLOCK-BOUND'];
    const out = readStep(v);
    assert.equal(out.refused, false);
    assert.deepEqual(out.step, v.expected_step);
    assert.equal(out.step.action, 'revert');
  });

  it('(b) TAMPERED: verification fails and the step is NOT surfaced', () => {
    const v = byName['ENVSTEP-BLOCK-TAMPERED'];
    const out = readStep(v);
    assert.equal(out.verdict.valid, false);
    assert.equal(out.verdict.reason, 'body_hash_mismatch');
    assert.equal(out.refused, true);
    assert.equal(out.step, null, 'a step from an unverified envelope must never be surfaced');
  });

  it('(b) and the swapped step IS present in the envelope — it is withheld, not absent', () => {
    // Without this the previous test could pass on an envelope that simply had no step, which
    // would prove nothing about withholding.
    const v = byName['ENVSTEP-BLOCK-TAMPERED'];
    assert.equal(v.envelope.next_agent_step.action, 're_preflight');
    assert.notEqual(v.envelope.next_agent_step.action, byName['ENVSTEP-BLOCK-BOUND'].envelope.next_agent_step.action);
  });

  it('(c) allow-class: verifies, and the step is null', () => {
    const out = readStep(byName['ENVSTEP-ALLOW-NULL']);
    assert.equal(out.refused, false);
    assert.equal(out.step, null);
  });

  it('the two BLOCK vectors share one receipt — only the envelope differs', () => {
    // The tampered case is the same signed bytes with a different envelope handed alongside.
    assert.equal(byName['ENVSTEP-BLOCK-TAMPERED'].token, byName['ENVSTEP-BLOCK-BOUND'].token);
  });

  it('withholding is not vacuous: the same receipt WITH its own envelope verifies', () => {
    assert.equal(readStep(byName['ENVSTEP-BLOCK-BOUND']).verdict.valid, true);
  });
});
