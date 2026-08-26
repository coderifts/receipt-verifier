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

/** Single-spec fp, implemented ONLY from §2.0's prose. No import from any CodeRifts package. */
const sortDeep = (v) => {
  if (Array.isArray(v)) return v.map(sortDeep);
  if (v && typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = sortDeep(v[k]);
    return out;
  }
  return v;
};
const normalizeSpec = (x) => {
  if (x == null) return '';
  const str = String(x).trim();
  if (!str) return '';
  try {
    const p = (str.startsWith('{') || str.startsWith('[')) ? JSON.parse(str) : null;
    if (p && typeof p === 'object') return JSON.stringify(sortDeep(p));
  } catch (_) { /* fall through to raw text */ }
  return str;
};
const normalizePolicy = (p) => (!p || typeof p !== 'object' ? '{}' : JSON.stringify(sortDeep(p)));
const SINGLE_SPEC_NUL = '\x00';

function singleSpecFromTheDocument(before, after, policy, scorerVersion) {
  const material = [normalizeSpec(before), normalizeSpec(after), normalizePolicy(policy), scorerVersion]
    .join(SINGLE_SPEC_NUL);
  return `sha256:${sha(material)}`;
}

const SS_SCORER = '59ed151:active';
const SS_FP = 'sha256:b4faaacad943012438d784c8da34594538b9e5883adc341aa10b7bbfca9d921c';

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

  it('THE SINGLE-SPEC PATH IS NOW DOCUMENTED AS RECOMPUTABLE', () => {
    assert.match(FLAT, /Single-spec path .* — RECOMPUTABLE/);
    assert.equal(/NOT recomputable from that route's response today/.test(DOC), false,
      'the superseded paragraph must be gone, not merely contradicted elsewhere');
    assert.match(FLAT, /scorer_version`?: \*\*returned in the response\*\*|scorer_version.*returned in the response/);
  });

  it('BOTH SEPARATORS ARE NAMED, and the difference is called out', () => {
    assert.match(FLAT, /Separator: `\\x1f` \(US, U\+001F\)/);
    assert.match(FLAT, /Separator: `\\x00` \(NUL, U\+0000\)/);
    assert.match(FLAT, /This is NOT the `\\x1f` used above/);
  });

  it('THE SEPARATOR ERROR IS RECORDED, not silently repaired', () => {
    assert.match(FLAT, /gave `\\x1f` as the separator for \*\*both\*\* recipes/);
    assert.match(FLAT, /wrong for the single-spec path/);
    assert.match(FLAT, /computed a wrong digest/);
    // The cause, so the next reader does not repeat it.
    assert.match(FLAT, /both constants are \*named\* `NUL`, and only one of them actually is/);
    assert.match(FLAT, /A name is not a measurement/);
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

// ───────────────────────────────────────────────────────────────────────────
describe('§2.0 — the SINGLE-SPEC recipe is reproducible FROM THE DOCUMENT too', () => {
  /**
   * THIS TEST IS THE ONE THAT WAS MISSING. The crbundle recipe had a prose-only reimplementation
   * from the day it was written; the single-spec recipe did not, and that is exactly why a wrong
   * separator shipped in it. A recipe with no prose-only test is a recipe nobody has checked.
   */
  it('THE VECTOR REPRODUCES: prose alone recomputes the live single-spec fp', () => {
    assert.equal(singleSpecFromTheDocument(BEFORE, AFTER, {}, SS_SCORER), SS_FP,
      'a third party following only §2.0 must land on the documented value');
  });

  it('THE SEPARATOR IS LOAD-BEARING: \\x1f produces a DIFFERENT digest', () => {
    const wrong = `sha256:${sha([normalizeSpec(BEFORE), normalizeSpec(AFTER), normalizePolicy({}), SS_SCORER].join('\x1f'))}`;
    assert.notEqual(wrong, SS_FP,
      'if both separators agreed, the shipped error would have been harmless — it was not');
  });

  it('the two recipes are genuinely different — same inputs, different digests', () => {
    const bundle = fromTheDocument(
      [{ id: 'openapi.yaml', type: 'openapi', before: BEFORE, after: AFTER }], { operation: 'merge' },
    );
    assert.notEqual(bundle, SS_FP, 'one recipe cannot stand in for the other');
  });

  it('scorer_version is load-bearing: a different value changes the digest', () => {
    assert.notEqual(singleSpecFromTheDocument(BEFORE, AFTER, {}, 'other:mode'), SS_FP);
  });

  it('the document carries the single-spec vector and its scorer_version verbatim', () => {
    assert.ok(DOC.includes(SS_FP), 'the cross-check vector must be IN the document');
    assert.ok(DOC.includes(SS_SCORER), 'the scorer_version it was computed with must be there too');
  });

  it('normalizeSpec key-sorting is stated, and reordering keys does not change the digest', () => {
    assert.match(FLAT, /object keys sorted at every depth/);
    const reordered = '{"paths":{"/u":{"get":{"responses":{"200":{"description":"ok"}}}}},"info":{"version":"1.0.0","title":"t"},"openapi":"3.0.0"}';
    assert.equal(singleSpecFromTheDocument(reordered, AFTER, {}, SS_SCORER), SS_FP,
      'key order must not matter — if it does, the prose is missing a rule');
  });

  it('an absent policy normalises to {} exactly as documented', () => {
    assert.match(FLAT, /a non-object → the literal `\{\}`|non-object → the literal/);
    for (const p of [undefined, null, 'nope', 42]) {
      assert.equal(singleSpecFromTheDocument(BEFORE, AFTER, p, SS_SCORER), SS_FP,
        `policy=${JSON.stringify(p)} must normalise to {}`);
    }
  });
});
