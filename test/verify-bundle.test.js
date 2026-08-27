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
/** The grant vectors bind this exact string as their receipt — it is what the digest covers. */
const RECEIPT_FOR_GRANT = grantVectors.receipt;
/** A REAL signed receipt, from this repository's receipt vectors — a different key entirely. */
const REAL_RECEIPT = receiptVectors.vectors.find((v) => v.name === 'valid_v4').token;

const GRANT_FLAGS = grantVectors.vectors.find((v) => v.name === 'EG-VALID').flags || {};
const grantIntended = {
  operation: GRANT_FLAGS['intended-operation'],
  target_id: GRANT_FLAGS['intended-target'],
  audience: GRANT_FLAGS['intended-audience'],
  after_payload: GRANT_FLAGS.after_payload,
  receipt_token: GRANT_FLAGS.receipt || RECEIPT_FOR_GRANT,
};

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
  it('TWO VALID DOCUMENTS ABOUT DIFFERENT THINGS is INVALID, not VERIFIED', () => {
    // THE CASE A CONTAINER ALONE WOULD PASS, and this repository's own vectors produce it: the
    // receipt vector is a real signed receipt, and the grant vector binds the placeholder string
    // "receipt.token". BOTH verify individually. A bundle that reported VERIFIED here would be
    // asserting a chain that does not exist, which is precisely what the linkage check is for.
    const r = verifyBundle(bundleOf({ receipt: RECEIPT, execution_grant: GRANT_OK }), ctx, REG);
    assert.equal(r.verified_count, 2, 'each half verifies on its own');
    assert.equal(r.bundle, BUNDLE.INVALID, 'but they are not the same chain');
    const link = r.linkage.find((l) => l.link === 'grant_binds_receipt');
    assert.ok(link, 'both present and verified → the link must be checked');
    assert.equal(link.ok, false);
    assert.match(link.reason, /does not bind the receipt in this bundle/);
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
