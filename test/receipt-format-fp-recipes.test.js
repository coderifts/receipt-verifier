'use strict';
/**
 * RECEIPT_FORMAT.md §2 said `fp` was an OPAQUE BINDING requiring the verdict-core canonical
 * encoder. That was wrong twice over: the encoder is not on the path that produces a receipt's
 * `fp`, and the recipe that IS is recomputable from what a caller already holds.
 *
 * These tests keep §2.0 honest — including the half that is still NOT recomputable, which is the
 * part most likely to be quietly dropped later.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const DOC = fs.readFileSync(path.join(__dirname, '..', 'RECEIPT_FORMAT.md'), 'utf8');
const FLAT = DOC.replace(/\s+/g, ' ');

const NUL = '\x1f';
const sha = (x) => crypto.createHash('sha256').update(String(x), 'utf8').digest('hex');
const specStr = (v) => (v == null ? '' : (typeof v === 'string' ? v : JSON.stringify(v)));
const scalar = (v) => (v == null ? '' : String(v));

/** crbundle.v1, implemented ONLY from the prose in §2.0 — no import from any of our packages. */
function fromTheDocument(artifacts, context) {
  const sorted = artifacts.slice().sort((x, y) => {
    const kx = `${x.type}${NUL}${x.id}`; const ky = `${y.type}${NUL}${y.id}`;
    return kx < ky ? -1 : (kx > ky ? 1 : 0);
  });
  const parts = ['crbundle.v1', String(artifacts.length)];
  for (const a of sorted) {
    parts.push([a.type, a.id, sha(specStr(a.before)), sha(specStr(a.after))].join(NUL));
  }
  const c = context || {};
  parts.push([scalar(c.operation), scalar(c.environment), scalar(c.repository),
    scalar(c.branch), scalar(c.pull_request), scalar(c.policy_profile)].join(NUL));
  return `sha256:${sha(parts.join(NUL))}`;
}

const BEFORE = '{"openapi":"3.0.0","info":{"title":"t","version":"1.0.0"},"paths":{"/u":{"get":{"responses":{"200":{"description":"ok"}}}}}}';
const AFTER = '{"openapi":"3.0.0","info":{"title":"t","version":"1.0.0"},"paths":{}}';
const VECTOR_FP = 'sha256:049650f2d0496f39ad0ec09e57fa1841e9636255f031e99751435b1bc70443df';

describe('§2.0 — the crbundle.v1 recipe is reproducible FROM THE DOCUMENT', () => {
  it('THE VECTOR REPRODUCES: prose alone is enough to recompute the published fp', () => {
    const got = fromTheDocument(
      [{ id: 'openapi.yaml', type: 'openapi', before: BEFORE, after: AFTER }],
      { operation: 'merge' },
    );
    assert.equal(got, VECTOR_FP,
      'a third party following only §2.0 must land on the documented value — that is the whole claim');
  });

  it('the document carries that vector verbatim', () => {
    assert.ok(DOC.includes(VECTOR_FP), 'the cross-check vector must be IN the document');
    assert.match(FLAT, /crbundle\.v1/);
    assert.match(FLAT, /artifactCount/);
  });

  it('all six context fields are named in the preimage', () => {
    for (const f of ['operation', 'environment', 'repository', 'branch', 'pull_request', 'policy_profile']) {
      assert.match(DOC, new RegExp(f), `§2.0 omits ${f} — a reader would compute the wrong digest`);
    }
  });

  it('the encoding rules a reader needs are all stated', () => {
    assert.match(FLAT, /sorted by `\(type, id\)`|sorted by \(type, id\)/);
    assert.match(FLAT, /raw UTF-8/);
    assert.match(FLAT, /absent side is the empty string/);
    assert.match(FLAT, /time-free/);
  });
});

describe('§2.0 — the honest half', () => {
  it('THE OLD CLAIM IS RETRACTED, not quietly deleted', () => {
    assert.match(FLAT, /an earlier version of this document said it was/);
    assert.equal(/`fp` is verified as an opaque binding/.test(DOC), false,
      'the superseded sentence must be gone');
  });

  it('it says the verdict-core encoder is NOT the producer', () => {
    assert.match(FLAT, /not on the path that produces a receipt's `fp`/);
  });

  it('THE SINGLE-SPEC PATH IS MARKED NOT RECOMPUTABLE, with the reason', () => {
    assert.match(FLAT, /NOT recomputable from that route's response today/);
    assert.match(FLAT, /signed into the fingerprint but not returned by the single-spec route/);
    assert.match(FLAT, /not withheld on purpose/,
      'a reader must not read this as a secret being kept');
  });

  it('the 10.0.0 defect is disclosed to anyone who pinned a value from it', () => {
    assert.match(FLAT, /up to and including 10\.0\.0 did not/);
    assert.match(FLAT, /recompute rather than migrate/);
  });

  it('THE BOUNDARY LINE SURVIVES: a matching fp is not proof of mediation', () => {
    assert.match(FLAT, /does \*\*not\*\* prove that any particular agent call went through the gate/);
    assert.match(FLAT, /never about traffic it never saw/);
  });

  it('MOAT: no scoring dimension name appears in the published preimage', () => {
    const section = DOC.slice(DOC.indexOf('### 2.0'), DOC.indexOf('### 2.1'));
    for (const dim of ['migration_risk', 'ensemble_independence_risk', 'evidence_quality_risk',
      'posterior_evidence_risk', 'staleness_risk', 'budget_risk', 'provenance_risk',
      'tool_capability_risk', 'memory_boundary_risk', 'source_risk', 'layer05_perturbation']) {
      assert.equal(section.includes(dim), false, `§2.0 discloses the scoring dimension ${dim}`);
    }
  });
});
