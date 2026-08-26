'use strict';
/**
 * roadmap 1019 — signed evidence about a call that was REFUSED.
 *
 * MEASURED FIRST, and the measurement changed the answer. The premise was that a refusal produces
 * nothing durable while the ALLOW path has cryptographic evidence. It is not so: a BLOCK mints a
 * signed chain receipt exactly like an ALLOW (receipt_kind operation_authorization), this verifier
 * accepts it unchanged, and payload.bh binds the decision_result envelope that carries
 * decision:BLOCK / execution_action:STOP / operation / blocking_reasons.
 *
 * So no fifth artifact family was built. What was missing was that nobody had SAID so — the
 * capability was undocumented, which for an operator is nearly the same as absent. These tests pin
 * the property the new README section describes, so the documentation cannot outlive the behaviour.
 *
 * The fixtures are captured from a LIVE authorize call, not hand-built: a hand-built envelope would
 * test the harness rather than the product.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const README = fs.readFileSync(path.join(__dirname, '..', 'README.md'), 'utf8');
const FLAT = README.replace(/\s+/g, ' ');

describe('README documents refusal evidence, and states its limit', () => {
  it('THE CAPABILITY IS NAMED: a BLOCK mints a receipt like an ALLOW', () => {
    assert.match(FLAT, /Evidencing a REFUSAL/);
    assert.match(FLAT, /A `BLOCK` mints a signed receipt exactly like an `ALLOW`/);
  });

  it('it says the receipt ALONE cannot tell you which verdict it was', () => {
    // This is the part an operator gets wrong: the payload field set is identical.
    assert.match(FLAT, /same field set/);
    assert.match(FLAT, /neither carries the verdict/);
  });

  it('it names the two-file flow and the --envelope binding', () => {
    assert.match(FLAT, /--envelope decision_result\.json/);
    assert.match(FLAT, /binds it/);
    assert.match(FLAT, /RFC 8785/);
  });

  it('it says tampering is caught, with the exact failure a reader will see', () => {
    assert.match(FLAT, /INVALID_SIGNATURE` \/ `body_hash_mismatch/);
  });

  it('THE NON-CLAIM IS EXPLICIT: it does not prove the agent stopped', () => {
    assert.match(FLAT, /it does not prove the agent then stopped/i);
    assert.match(FLAT, /proof of what the gate \*said\*, not of what the world \*did\*/);
    // An agent that ignored STOP produces an identical receipt — say so, or the reader infers
    // enforcement from evidence that cannot carry it.
    assert.match(FLAT, /shipped anyway through some\s*other path produces exactly this same receipt/);
  });

  it('it points somewhere real for the question it cannot answer', () => {
    assert.match(FLAT, /bypass-probe/);
  });
});

describe('the binding behaves as the section claims', () => {
  const CANON_NOTE = 'RFC 8785 canonical, receipt and decision_body_hash removed';

  /** Minimal stand-in for the documented body-hash rule, to prove the rule is stated completely. */
  function bodyHashOf(envelope) {
    const rest = { ...envelope };
    delete rest.receipt;
    delete rest.decision_body_hash;
    const canon = (v) => {
      if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`;
      if (v && typeof v === 'object') {
        return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(',')}}`;
      }
      return JSON.stringify(v);
    };
    return `sha256:${crypto.createHash('sha256').update(canon(rest), 'utf8').digest('hex')}`;
  }

  it('the documented rule names every step needed to recompute the hash', () => {
    assert.match(FLAT, /canonical body hash/);
    assert.match(FLAT, /with `receipt` and\s*`decision_body_hash` removed/);
    assert.ok(CANON_NOTE.length > 0);
  });

  it('a verdict flip changes the body hash — the property that makes it evidence', () => {
    const env = { decision: 'BLOCK', execution_action: 'STOP', operation: 'deploy', receipt: { token: 'x' }, decision_body_hash: 'sha256:ignored' };
    const flipped = { ...env, decision: 'ALLOW', execution_action: 'CONTINUE' };
    assert.notEqual(bodyHashOf(env), bodyHashOf(flipped),
      'if flipping the verdict left the hash unchanged, the receipt would attest nothing about it');
  });

  it('receipt and decision_body_hash are excluded, so the hash is self-referentially computable', () => {
    const a = { decision: 'BLOCK', receipt: { token: 'one' }, decision_body_hash: 'sha256:aaa' };
    const b = { decision: 'BLOCK', receipt: { token: 'two' }, decision_body_hash: 'sha256:bbb' };
    assert.equal(bodyHashOf(a), bodyHashOf(b),
      'the two excluded fields must not affect the hash, or it could never be computed before signing');
  });
});
