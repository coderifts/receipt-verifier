'use strict';

/**
 * cr.bundle.v1 — the end of the chain in one file, verifiable offline with one command.
 *
 * WHAT THIS IS. A container holding what a consumer already holds at the end of a run: a receipt,
 * an execution grant, and — when they exist — a commit attestation, a toolset declaration, and
 * provider evidence. It asserts what is IN it and NAMES what is not.
 *
 * COMPOSITION, NOT NEW CRYPTOGRAPHY, and this was measured rather than assumed. All four public
 * verifiers already share one contract — `(token, ctx, opts) → { valid, status, reason }`:
 *   verify.js          verifyReceipt
 *   verify-grant.js    verifyExecutionGrant
 *   verify-attest.js   verifyExecutionAttestation
 *   verify-toolset.js  verifyToolsetAttestation
 * This module calls them and checks the LINKAGE between what they returned. It defines no new
 * signing input, no new digest and no new key handling, so nothing already issued moves.
 *
 * ── HOW ABSENCE RENDERS, AND THE ALTERNATIVES REJECTED ──────────────────────────────────────
 *
 * Three slot states, never two:
 *   VERIFIED  present, and its own verifier said valid
 *   INVALID   present, and its own verifier said invalid — a real failure
 *   ABSENT    not in the bundle — a statement about SCOPE, not about validity
 *
 * REJECTED (a): absent counts as pass. Then an all-absent bundle is green, which is exactly the
 * `0/0` shape — a ratio that reads identically to a suite that ran and found nothing wrong. It is
 * the most dangerous option because it is also the most convenient one.
 *
 * REJECTED (b): absent counts as failure. Then an absent commit attestation is indistinguishable
 * from one that FAILED to verify, and a holder who never ran an executor reads a red bundle as
 * evidence something is broken. "We did not look" must never render as "we looked and it is wrong"
 * — the same rule this repository applies to a retired key and an unread registry.
 *
 * A GREEN ALL-ABSENT BUNDLE IS IMPOSSIBLE IN CODE, not by convention: `EMPTY` is a distinct
 * bundle verdict returned whenever no slot is present, and `assertNoGreenEmpty` throws rather than
 * letting a caller construct one. A convention would have been enough right up until the moment
 * it was not.
 *
 * ── THE HONEST LINE, which travels inside every result ──────────────────────────────────────
 * A complete bundle proves THE CHAIN WE MINTED IS INTERNALLY CONSISTENT AND INDEPENDENTLY
 * CHECKABLE. It does not prove the world changed, and it does not prove no other path wrote to
 * the target.
 */

const { verifyReceipt } = require('./verify.js');
const { verifyExecutionGrant, receiptDigest } = require('./verify-grant.js');
const { verifyExecutionAttestation } = require('./verify-attest.js');
const { verifyToolsetAttestation } = require('./verify-toolset.js');

const BUNDLE_VERSION = 'cr.bundle.v1';

const SLOT = Object.freeze({
  VERIFIED: 'VERIFIED',
  INVALID: 'INVALID',
  ABSENT: 'ABSENT',
});

const BUNDLE = Object.freeze({
  VERIFIED: 'VERIFIED',
  INVALID: 'INVALID',
  /** Zero slots present. Never green — see the rejected alternatives above. */
  EMPTY: 'EMPTY',
});

const CEILING = 'A complete bundle proves the chain we minted is internally consistent and '
  + 'independently checkable. It does not prove the world changed, and it does not prove that no '
  + 'other path wrote to the target.';

/**
 * The slots, in chain order. Each names the verifier that owns it, so a reader can see that this
 * module decides nothing about validity itself.
 *
 * `executor: true` marks a slot no in-process holder can produce today. Its absence is EXPECTED
 * rather than a gap in the holder's setup, and the result says which kind of absence it is.
 */
const SLOTS = Object.freeze([
  { key: 'receipt', verify: verifyReceipt, executor: false },
  { key: 'execution_grant', verify: verifyExecutionGrant, executor: false },
  { key: 'toolset_declaration', verify: verifyToolsetAttestation, executor: false },
  { key: 'commit_attestation', verify: verifyExecutionAttestation, executor: true },
  { key: 'nonce_commitment', verify: null, executor: true },
  { key: 'merge_evidence', verify: null, executor: true },
  { key: 'deploy_attestation', verify: null, executor: true },
  { key: 'provider_evidence', verify: null, executor: true },
]);

const SLOT_KEYS = Object.freeze(SLOTS.map((s) => s.key));

/** Guard invoked before any result is returned. A green empty bundle is refused, not printed. */
function assertNoGreenEmpty(result) {
  const present = result.slots.filter((s) => s.state !== SLOT.ABSENT).length;
  if (present === 0 && result.bundle !== BUNDLE.EMPTY) {
    throw new Error(
      `verify-bundle: ${present} slots present but bundle is ${result.bundle} — refusing to return `
      + 'a verdict an empty bundle cannot support',
    );
  }
  if (result.bundle === BUNDLE.VERIFIED && result.verified_count === 0) {
    throw new Error('verify-bundle: VERIFIED with zero verified slots — refusing to return');
  }
  return result;
}

function slotResult(key, state, extra = {}) {
  return { slot: key, state, ...extra };
}

/**
 * @param {object} bundle  a cr.bundle.v1 document
 * @param {object} ctx     default verification context, forwarded to each slot verifier unchanged
 * @param {object} opts    default opts, forwarded unchanged — no key handling happens here
 *
 * PER-SLOT VERIFICATION MATERIAL, and this was a measurement rather than a guess. Building a
 * bundle from this repository's own vectors showed a receipt and a grant signed under DIFFERENT
 * kids with different registries — so one shared context cannot verify a real bundle. Pass
 * `opts.perSlot = { receipt: { ctx, opts }, execution_grant: { ctx, opts } }` to override per slot;
 * anything not overridden falls back to the defaults above.
 *
 * THE KEYS NEVER COME FROM THE BUNDLE. A bundle carrying its own verification key would be
 * self-certifying, which is not verification. The caller supplies the material, exactly as every
 * other verifier in this repository requires.
 */
function verifyBundle(bundle, ctx = {}, opts = {}) {
  const perSlot = (opts && opts.perSlot) || {};
  if (!bundle || typeof bundle !== 'object') {
    return { bundle: BUNDLE.INVALID, reason: 'not_an_object', slots: [], verified_count: 0, ceiling: CEILING };
  }
  if (bundle.v !== BUNDLE_VERSION) {
    // Same discipline the grant verifier uses: an unknown version is UNSUPPORTED, not forged.
    return {
      bundle: BUNDLE.INVALID,
      reason: 'unsupported_version',
      declared: bundle.v == null ? null : String(bundle.v),
      slots: [],
      verified_count: 0,
      ceiling: CEILING,
    };
  }

  const given = (bundle.slots && typeof bundle.slots === 'object') ? bundle.slots : {};
  const unknown = Object.keys(given).filter((k) => !SLOT_KEYS.includes(k));
  if (unknown.length > 0) {
    // An unknown slot is a bundle we cannot fully grade. Ignoring it would let a holder attach a
    // slot this verifier never reads and present the result as complete.
    return {
      bundle: BUNDLE.INVALID,
      reason: 'unknown_slot',
      unknown,
      slots: [],
      verified_count: 0,
      ceiling: CEILING,
    };
  }

  const slots = [];
  for (const def of SLOTS) {
    const entry = given[def.key];
    const token = entry && typeof entry === 'object' ? entry.token : entry;
    if (token == null || token === '') {
      slots.push(slotResult(def.key, SLOT.ABSENT, {
        absent_class: def.executor ? 'requires_executor' : 'not_supplied',
        // Stated per slot so an absent commit attestation cannot be read as a failed one.
        note: def.executor
          ? 'no in-process holder can produce this today; its absence is expected, not a defect'
          : 'not supplied by the holder',
      }));
      continue;
    }
    if (typeof def.verify !== 'function') {
      slots.push(slotResult(def.key, SLOT.INVALID, {
        status: 'NO_VERIFIER',
        reason: 'this slot has no public verifier yet; a token here cannot be checked offline',
      }));
      continue;
    }
    let r;
    const over = perSlot[def.key] || {};
    try {
      r = def.verify(token, over.ctx || ctx, over.opts || opts);
    } catch (err) {
      r = { valid: false, status: 'VERIFIER_THREW', reason: String(err && err.message).slice(0, 120) };
    }
    slots.push(slotResult(def.key, r && r.valid === true ? SLOT.VERIFIED : SLOT.INVALID, {
      status: r && r.status,
      ...(r && r.reason ? { reason: r.reason } : {}),
    }));
  }

  // ── LINKAGE: the bundle is more than a container ──
  // A grant binds `receipt_digest`. If both are present and verified, the grant must bind THIS
  // receipt — otherwise the bundle holds two valid documents about different things.
  const linkage = [];
  const rec = given.receipt && (given.receipt.token || given.receipt);
  const grant = given.execution_grant && (given.execution_grant.token || given.execution_grant);
  const recOk = slots.find((s) => s.slot === 'receipt')?.state === SLOT.VERIFIED;
  const grantOk = slots.find((s) => s.slot === 'execution_grant')?.state === SLOT.VERIFIED;
  if (recOk && grantOk) {
    let bound = false;
    try {
      const payload = JSON.parse(Buffer.from(String(grant).split('.')[0], 'base64url').toString('utf8'));
      bound = payload.receipt_digest === receiptDigest(rec);
    } catch { bound = false; }
    linkage.push({
      link: 'grant_binds_receipt',
      ok: bound,
      ...(bound ? {} : { reason: 'the grant in this bundle does not bind the receipt in this bundle' }),
    });
  }

  const verified = slots.filter((s) => s.state === SLOT.VERIFIED).length;
  const invalid = slots.filter((s) => s.state === SLOT.INVALID).length;
  const brokenLink = linkage.some((l) => l.ok === false);

  let verdict;
  if (verified === 0) verdict = BUNDLE.EMPTY;
  else if (invalid > 0 || brokenLink) verdict = BUNDLE.INVALID;
  else verdict = BUNDLE.VERIFIED;

  return assertNoGreenEmpty({
    bundle: verdict,
    verified_count: verified,
    invalid_count: invalid,
    absent_count: slots.filter((s) => s.state === SLOT.ABSENT).length,
    slots,
    linkage,
    ceiling: CEILING,
  });
}

module.exports = {
  verifyBundle, assertNoGreenEmpty, BUNDLE_VERSION, SLOT, BUNDLE, SLOTS, SLOT_KEYS, CEILING,
};
