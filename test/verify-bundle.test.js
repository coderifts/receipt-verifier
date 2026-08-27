'use strict';

/**
 * cr.bundle.v1 — the proof bundle, verified by COMPOSITION.
 *
 * These tests use the repository's OWN signed vectors rather than hand-built shapes, so a passing
 * bundle here is a real Ed25519 verification through the same public verifiers a third party runs.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  verifyBundle, assertNoGreenEmpty, BUNDLE_VERSION, SLOT, BUNDLE, SLOTS, CEILING,
} = require('../verify-bundle.js');
const grantVectors = require('../test/grant-vectors.json');

const receiptVectors = require('../test/vectors.json');

const GRANT_OK = grantVectors.vectors.find((v) => v.name === 'EG-VALID').token;
const GRANT_EXPIRED = grantVectors.vectors.find((v) => v.name === 'EG-EXPIRED').token;
/**
 * 1125 — the grant vectors now bind a REAL receipt. Until 2026-08-27 they bound the literal string
 * 'receipt.token', so this bundle held two genuinely signed artifacts about different things.
 */
const REAL_RECEIPT = receiptVectors.vectors.find((v) => v.name === 'valid_v4').token;
/** Deliberately non-matching: binds a different real receipt. Never "fix" it — see its `note`. */
const GRANT_MISMATCH = grantVectors.vectors
  .find((v) => v.name === 'EG-MISMATCH-FOREIGN-RECEIPT').token;

const intendedFor = (name) => {
  const f = grantVectors.vectors.find((v) => v.name === name).flags || {};
  return {
    operation: f['intended-operation'] || grantVectors.operation,
    target_id: f['intended-target'] || grantVectors.target_id,
    audience: f['intended-audience'] || grantVectors.audience,
    after_payload: f.after_payload != null ? f.after_payload : grantVectors.after_payload,
    receipt_token: f.receipt || grantVectors.receipt,
  };
};
const grantIntended = intendedFor('EG-VALID');

/**
 * PER-SLOT MATERIAL, because a receipt and a grant here are signed by DIFFERENT keys. A single
 * shared context cannot verify a real bundle — which is why the verifier takes per-slot overrides.
 */
const ctx = {};
const REG = {
  perSlot: {
    receipt: {
      ctx: { publicKey: receiptVectors.public_key_pem, expectedKid: receiptVectors.kid },
      opts: {},
    },
    execution_grant: {
      ctx: { publicKey: grantVectors.public_key_pem, expectedKid: grantVectors.kid },
      opts: { intended: grantIntended },
    },
  },
};
const RECEIPT = REAL_RECEIPT;

/** Per-slot material for a named grant vector, so each case verifies against its own intent. */
const regFor = (name) => ({
  perSlot: {
    receipt: { ctx: { publicKey: receiptVectors.public_key_pem, expectedKid: receiptVectors.kid }, opts: {} },
    execution_grant: {
      ctx: { publicKey: grantVectors.public_key_pem, expectedKid: grantVectors.kid },
      opts: { intended: intendedFor(name) },
    },
  },
});

const bundleOf = (slots) => ({ v: BUNDLE_VERSION, slots });

describe('an ALL-ABSENT bundle is EMPTY, never green', () => {
  it('zero slots present → EMPTY, and it is not a failure either', () => {
    const r = verifyBundle(bundleOf({}), ctx, REG);
    assert.equal(r.bundle, BUNDLE.EMPTY);
    assert.equal(r.verified_count, 0);
    assert.equal(r.invalid_count, 0, 'an empty bundle has failed nothing');
    assert.equal(r.absent_count, SLOTS.length);
  });

  it('THE GUARD BITES: a hand-forged green empty result is refused, not returned', () => {
    // A convention would have been enough right up until the moment it was not.
    assert.throws(
      () => assertNoGreenEmpty({
        bundle: BUNDLE.VERIFIED,
        verified_count: 0,
        slots: SLOTS.map((s) => ({ slot: s.key, state: SLOT.ABSENT })),
      }),
      /refusing to return/,
    );
  });

  it('every absent slot says WHICH KIND of absence it is', () => {
    const r = verifyBundle(bundleOf({}), ctx, REG);
    for (const s of r.slots) {
      assert.equal(s.state, SLOT.ABSENT);
      assert.ok(['requires_executor', 'not_supplied'].includes(s.absent_class));
      assert.ok(s.note && s.note.length > 20, 'an absence without its reason is just a gap');
    }
    // The distinction that matters: an executor slot's absence is EXPECTED, not a defect.
    const commit = r.slots.find((s) => s.slot === 'commit_attestation');
    assert.equal(commit.absent_class, 'requires_executor');
    assert.match(commit.note, /expected, not a defect/);
  });

  it('AN ABSENT COMMIT ATTESTATION IS NOT A FAILED ONE — the states are distinct', () => {
    const absent = verifyBundle(bundleOf({}), ctx, REG)
      .slots.find((s) => s.slot === 'commit_attestation');
    const failed = verifyBundle(bundleOf({ commit_attestation: 'garbage' }), ctx, REG)
      .slots.find((s) => s.slot === 'commit_attestation');
    assert.equal(absent.state, SLOT.ABSENT);
    assert.equal(failed.state, SLOT.INVALID);
    assert.notEqual(absent.state, failed.state);
  });
});

describe('COMPOSITION: real signed vectors verify through the existing verifiers', () => {
  it('a real signed RECEIPT verifies through verify.js with no new cryptography', () => {
    const r = verifyBundle(bundleOf({ receipt: RECEIPT }), ctx, REG);
    assert.equal(r.bundle, BUNDLE.VERIFIED, JSON.stringify(r.slots));
    assert.equal(r.verified_count, 1);
    assert.equal(r.slots.find((s) => s.slot === 'receipt').status, 'VERIFIED_CURRENT');
  });

  it('a real signed GRANT verifies through verify-grant.js with no new cryptography', () => {
    const r = verifyBundle(bundleOf({ execution_grant: GRANT_OK }), ctx, REG);
    assert.equal(r.bundle, BUNDLE.VERIFIED, JSON.stringify(r.slots));
    assert.equal(r.slots.find((s) => s.slot === 'execution_grant').status, 'GRANT_CURRENT');
  });

  it('a VERIFIED bundle still names everything it does NOT contain', () => {
    const r = verifyBundle(bundleOf({ receipt: RECEIPT }), ctx, REG);
    assert.ok(r.absent_count >= 5, 'the bundle must not go quiet about the rest of the chain');
    assert.ok(r.slots.some((s) => s.slot === 'commit_attestation' && s.state === SLOT.ABSENT));
  });

  it('an INVALID slot makes the whole bundle INVALID', () => {
    const r = verifyBundle(bundleOf({ receipt: RECEIPT, execution_grant: GRANT_EXPIRED }), ctx, REG);
    assert.equal(r.bundle, BUNDLE.INVALID);
    const g = r.slots.find((s) => s.slot === 'execution_grant');
    assert.equal(g.state, SLOT.INVALID);
    assert.equal(g.status, 'GRANT_EXPIRED');
  });

  it('a verifier that THROWS becomes INVALID, never a silent pass', () => {
    const r = verifyBundle(bundleOf({ receipt: null, execution_grant: {} }), ctx, REG);
    const g = r.slots.find((s) => s.slot === 'execution_grant');
    assert.notEqual(g.state, SLOT.VERIFIED);
  });
});

describe('LINKAGE: the bundle is more than a container', () => {
  it('THE FIXED PAIR: a grant binding the REAL receipt is VERIFIED, and the link holds', () => {
    // 1125. Until the vectors were regenerated, this exact bundle was INVALID — the grant bound
    // the placeholder string 'receipt.token'. The assertion below used to pin that, correctly for
    // the data and wrongly for what the data taught. It is re-pointed, not deleted: the mismatch
    // case it protected now lives in the test underneath, on a vector that is non-matching ON
    // PURPOSE and says so in its own `note`.
    const r = verifyBundle(
      bundleOf({ receipt: RECEIPT, execution_grant: GRANT_OK }), ctx, regFor('EG-VALID'),
    );
    assert.equal(r.bundle, BUNDLE.VERIFIED, JSON.stringify(r.slots));
    assert.equal(r.verified_count, 2);
    const link = r.linkage.find((l) => l.link === 'grant_binds_receipt');
    assert.ok(link, 'both halves verified → the link must be checked');
    assert.equal(link.ok, true, 'the grant must bind the receipt in this bundle');
  });

  it('TWO VALID DOCUMENTS ABOUT DIFFERENT THINGS is INVALID, not VERIFIED', () => {
    // THE CASE A CONTAINER ALONE WOULD PASS. EG-MISMATCH-FOREIGN-RECEIPT binds a DIFFERENT real
    // receipt: both artifacts are genuinely signed, and they are not the same chain.
    const r = verifyBundle(
      bundleOf({ receipt: RECEIPT, execution_grant: GRANT_MISMATCH }),
      ctx,
      regFor('EG-MISMATCH-FOREIGN-RECEIPT'),
    );
    assert.equal(r.bundle, BUNDLE.INVALID, 'a foreign binding must never grade VERIFIED');
    const grantSlot = r.slots.find((s) => s.slot === 'execution_grant');
    assert.equal(grantSlot.state, SLOT.INVALID);
    assert.equal(grantSlot.status, 'GRANT_UNBOUND');
    assert.equal(grantSlot.reason, 'receipt_digest_mismatch');
  });

  it('the mismatch vector is marked INTENTIONAL, so nobody "fixes" it later', () => {
    const v = grantVectors.vectors.find((x) => x.name === 'EG-MISMATCH-FOREIGN-RECEIPT');
    assert.ok(v, 'the negative case must survive the positive fix');
    assert.match(v.note, /INTENTIONALLY NON-MATCHING/);
    assert.match(v.note, /never be "fixed" to match/);
  });

  it('the link is only checked when BOTH halves verified — never asserted over a failure', () => {
    const r = verifyBundle(bundleOf({ receipt: RECEIPT, execution_grant: GRANT_EXPIRED }), ctx, REG);
    assert.equal(r.linkage.length, 0,
      'an expired grant is a grant failure; claiming a linkage failure too would double-count it');
  });
});

describe('the format refuses what it cannot fully grade', () => {
  it('an unknown bundle version is UNSUPPORTED, not forged', () => {
    const r = verifyBundle({ v: 'cr.bundle.v2', slots: {} }, ctx, REG);
    assert.equal(r.bundle, BUNDLE.INVALID);
    assert.equal(r.reason, 'unsupported_version');
    assert.equal(r.declared, 'cr.bundle.v2');
  });

  it('an UNKNOWN SLOT is refused — a slot we never read must not present as complete', () => {
    const r = verifyBundle({ v: BUNDLE_VERSION, slots: { made_up: 'x' } }, ctx, REG);
    assert.equal(r.bundle, BUNDLE.INVALID);
    assert.equal(r.reason, 'unknown_slot');
    assert.deepEqual(r.unknown, ['made_up']);
  });

  it('a slot with no public verifier cannot be counted as verified', () => {
    const r = verifyBundle(bundleOf({ merge_evidence: 'anything' }), ctx, REG);
    const s = r.slots.find((x) => x.slot === 'merge_evidence');
    assert.equal(s.state, SLOT.INVALID);
    assert.equal(s.status, 'NO_VERIFIER');
  });
});

describe('the honest line travels with every result', () => {
  it('the ceiling is on the result, not only in the docs', () => {
    for (const b of [bundleOf({}), bundleOf({ receipt: RECEIPT, execution_grant: GRANT_OK })]) {
      const r = verifyBundle(b, ctx, REG);
      assert.equal(r.ceiling, CEILING);
    }
  });

  it('it says what a complete bundle does NOT prove', () => {
    assert.match(CEILING, /does not prove the world changed/);
    assert.match(CEILING, /no\s+other path wrote to the target/);
  });

  it('this module defines no signing input, digest or key handling of its own', () => {
    // Composition, not new cryptography — asserted so a future edit has to break it deliberately.
    const src = require('node:fs').readFileSync(
      require('node:path').join(__dirname, '..', 'verify-bundle.js'), 'utf8',
    );
    const code = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    // The first version of this list missed `require('node:crypto')` itself, so importing crypto
    // passed while calling it failed — a guard with a hole exactly where the defect would enter.
    for (const banned of ['createHash', 'createVerify', 'crypto.', 'SIGNING_PREFIX',
      "require('crypto')", "require('node:crypto')"]) {
      assert.equal(code.includes(banned), false,
        `verify-bundle.js contains ${banned} — it must compose the existing verifiers, not re-implement them`);
    }
  });
});
