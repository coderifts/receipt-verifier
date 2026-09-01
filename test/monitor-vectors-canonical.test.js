'use strict';

/**
 * The MON-A-* cases this repository is the landing place for.
 *
 * MEASURED 2026-09-01: the app-side conformance file carried seven `MON-A-*` cases and this
 * repository already carried all seven under byte-identical ids, plus one of its own
 * (`MON-A-MISMATCH-RECEIPT`). Nothing had to be staged — the copies already agreed.
 *
 * This test exists for what happens next. Once the app-side copy is removed, the list below is the
 * only remaining record of which monitoring-attestation cases were agreed and what each was
 * expected to return. A vector quietly dropped after that point would take its case with it, and
 * nothing else would notice.
 *
 * The ids are frozen here deliberately: `test/monitor-vectors.json` is regenerated with ephemeral
 * keys, so its BYTES change every run and its bytes cannot be pinned. Its ids and expected verdicts
 * can be, and those are the part that carries meaning.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

/**
 * The seven ids measured in the app's adapter-acceptance cases, with the verdict each expects.
 * Adding a case is an edit here as well as in the vector file — that is the point.
 */
const CANONICAL = Object.freeze({
  'MON-A-VALID': { valid: true, status: 'MON_ATTEST_VALID' },
  'MON-A-BAD-SIG': { valid: false, status: 'MON_ATTEST_INVALID_SIGNATURE' },
  'MON-A-UNKNOWN-KID': { valid: false, status: 'MON_ATTEST_UNKNOWN_KEY' },
  'MON-A-RETIRED-KEY-VALID-AT-ISSUE': { valid: true, status: 'MON_ATTEST_RETIRED_KEY_VALID_AT_ISSUE' },
  'MON-A-MALFORMED': { valid: false, status: 'MON_ATTEST_MALFORMED' },
  'MON-A-UNBOUND': { valid: false, status: 'MON_ATTEST_UNBOUND' },
  'MON-A-NOT-DELIVERED': { valid: true, status: 'MON_ATTEST_VALID' },
});

const VECTORS = JSON.parse(fs.readFileSync(path.join(__dirname, 'monitor-vectors.json'), 'utf8'));
const byName = new Map((VECTORS.vectors || VECTORS).map((v) => [v.name, v]));

describe('MON-A vectors — the canonical set is carried here', () => {
  for (const [id, expected] of Object.entries(CANONICAL)) {
    it(`${id} is present and expects ${expected.status}`, () => {
      const v = byName.get(id);
      assert.ok(v, `${id} is missing — this repository is the landing place for it`);
      assert.equal(v.expected.valid, expected.valid, `${id}: valid`);
      assert.equal(v.expected.status, expected.status, `${id}: status`);
    });
  }

  it('every canonical id is carried — none dropped', () => {
    const missing = Object.keys(CANONICAL).filter((id) => !byName.has(id));
    assert.deepEqual(missing, []);
  });

  it('the file may carry MORE than the canonical set, and does', () => {
    // MON-A-MISMATCH-RECEIPT is this repository's own; a superset is fine, a subset is not.
    assert.ok(byName.size >= Object.keys(CANONICAL).length);
    assert.ok(byName.has('MON-A-MISMATCH-RECEIPT'));
  });

  it('the expected verdicts cover a pass and several distinct failure modes', () => {
    const statuses = new Set(Object.values(CANONICAL).map((e) => e.status));
    assert.ok(statuses.has('MON_ATTEST_VALID'));
    assert.ok(statuses.size >= 4, `only ${statuses.size} distinct statuses`);
  });
});
