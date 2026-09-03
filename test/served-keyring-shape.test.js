'use strict';

/**
 * 1306(a) — the library path accepts the shape this project SERVES.
 *
 * MEASURED black-box 2026-09-02: `.well-known/coderifts-keys.json` serves `{keys:[...]}`, and
 * `verifyReceipt(token, {ctx:{keyring}})` threw `TypeError: ctx.keyring.get is not a function`.
 * The CLI's `--keys <url>` worked because it converts first — so the published document was
 * rejected by the published library, and only the CLI knew the trick.
 *
 * Driven by test/vectors.json (the repo's own signed corpus), not by a locally minted token: a
 * hand-rolled preimage would test my reconstruction of the format rather than the format.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { verifyReceipt, keyringFromDocument } = require('../verify.js');
const CORPUS = require('./vectors.json');

/** The served registry shape, built from the corpus's own key. */
const SERVED = {
  keys: [{ kid: CORPUS.kid, status: 'active', public_key_pem: CORPUS.public_key_pem }],
};
const VALID = CORPUS.vectors.filter((v) => v.expected && v.expected.valid === true);

describe('1306(a) — a served {keys:[...]} document is accepted directly', () => {
  it('the corpus has a valid vector to drive this — not a vacuous pass', () => {
    assert.ok(VALID.length > 0, 'no valid vector in test/vectors.json');
  });

  it('the SERVED shape verifies without the caller converting it', () => {
    for (const v of VALID) {
      const r = verifyReceipt(v.token, { ctx: { keyring: SERVED, expectedKid: null } });
      assert.equal(r.valid, true, `${v.name}: served shape rejected — ${r.status}/${r.reason}`);
    }
  });

  it('a bare array of keys is accepted too', () => {
    const r = verifyReceipt(VALID[0].token, { ctx: { keyring: SERVED.keys, expectedKid: null } });
    assert.equal(r.valid, true, `bare array rejected: ${r.status}`);
  });

  it('a Map still works — the old path is unchanged', () => {
    const map = keyringFromDocument(SERVED, 'test');
    assert.equal(typeof map.get, 'function');
    const r = verifyReceipt(VALID[0].token, { ctx: { keyring: map, expectedKid: null } });
    assert.equal(r.valid, true);
  });

  it('an unknown kid is still UNKNOWN_KEY — the coercion does not invent a match', () => {
    const other = { keys: [{ ...SERVED.keys[0], kid: 'not-the-signing-kid' }] };
    const r = verifyReceipt(VALID[0].token, { ctx: { keyring: other, expectedKid: null } });
    assert.equal(r.valid, false);
    assert.equal(r.status, 'UNKNOWN_KEY');
  });

  it('expectedKid is NOT papered over — omitting it still gates, by design', () => {
    // Deliberate: silently defaulting a kid gate would be a worse behaviour than the TypeError
    // this change removes. verify.js documents expectedKid as string|null, and it stays required.
    const r = verifyReceipt(VALID[0].token, { ctx: { keyring: SERVED } });
    assert.equal(r.valid, false);
    assert.equal(r.status, 'UNKNOWN_KEY');
  });
});
