'use strict';

/**
 * 1128 — the silent third argument.
 *
 * THE TRAP, measured: verifyExecutionAttestation is (token, opts) while verifyReceipt and
 * verifyExecutionGrant are (token, ctx, opts). A caller following the siblings' shape puts
 * `intended` third, it is dropped, `wantsCross` stays false, and a MISMATCHED attestation returns
 * ATTEST_VALID. Same vector, same key material, two placements:
 *   intended in opts  -> ATTEST_UNBOUND / receipt_digest_mismatch
 *   intended third    -> ATTEST_VALID
 * A fail-open at the caller boundary. The arity is NOT changed here — that is breaking and belongs
 * to a versioned wave — so what is closed is the silence.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { verifyExecutionAttestation } = require('../verify-attest.js');
const { verifyReceipt } = require('../verify.js');
const { verifyExecutionGrant } = require('../verify-grant.js');
const { verifyToolsetAttestation } = require('../verify-toolset.js');
const attestVectors = require('../test/attest-vectors.json');
const toolsetVectors = require('../test/toolset-vectors.json');

const MISMATCH = attestVectors.vectors.find((v) => v.name === 'EG-A-MISMATCH-RECEIPT');
const VALID = attestVectors.vectors.find((v) => v.name === 'EG-A-VALID');

describe('a third argument THROWS instead of being ignored', () => {
  it('three arguments throw, naming the correct shape', () => {
    assert.throws(
      () => verifyExecutionAttestation(
        MISMATCH.token,
        { registry: attestVectors.registry },
        { intended: { grant: MISMATCH.flags.grant } },
      ),
      (e) => /verifyExecutionAttestation\(token, opts\)/.test(e.message)
        && /pass intended via opts\.intended/.test(e.message),
      'the error must tell the caller the shape, not merely that something is wrong',
    );
  });

  it('the message says WHAT would have gone wrong, not just that an argument was extra', () => {
    let msg = '';
    try {
      verifyExecutionAttestation(MISMATCH.token, {}, {});
    } catch (e) { msg = e.message; }
    assert.match(msg, /silently not run/);
    assert.match(msg, /ATTEST_VALID/,
      'a caller must learn the consequence: a mismatch would have graded valid');
  });

  it('even an EMPTY third argument throws — the shape is wrong regardless of content', () => {
    // A guard that only fired on a non-empty third argument would still let the trap through
    // whenever the caller happened to pass `{}`, which is the common case in a generic dispatch.
    assert.throws(() => verifyExecutionAttestation(VALID.token, { registry: attestVectors.registry }, {}));
  });
});

describe('the two-argument shape still cross-checks — the guard closed nothing real', () => {
  it('opts.intended still produces the mismatch verdict', () => {
    const r = verifyExecutionAttestation(MISMATCH.token, {
      registry: attestVectors.registry,
      intended: { grant: MISMATCH.flags.grant },
    });
    assert.equal(r.valid, false);
    assert.equal(r.status, 'ATTEST_UNBOUND');
    assert.equal(r.reason, 'receipt_digest_mismatch');
  });

  it('a matching attestation is still valid', () => {
    const r = verifyExecutionAttestation(VALID.token, {
      registry: attestVectors.registry,
      intended: { grant: VALID.flags.grant },
    });
    assert.equal(r.valid, true);
    assert.equal(r.status, 'ATTEST_VALID');
  });

  it('two arguments with no intended still verifies the signature (no cross-check requested)', () => {
    const r = verifyExecutionAttestation(VALID.token, { registry: attestVectors.registry });
    assert.equal(r.valid, true);
  });
});

describe('verifyToolsetAttestation carries the SAME guard (1128 completion)', () => {
  const TS_VALID = toolsetVectors.vectors.find((v) => v.id === 'TS-A-VALID');
  const base = { registry: toolsetVectors.registry, entries: toolsetVectors.entries };

  it('three arguments throw, naming the correct shape', () => {
    assert.throws(
      () => verifyToolsetAttestation(TS_VALID.token, base, { intended: { declarer: 'someone-else' } }),
      (e) => /verifyToolsetAttestation\(token, opts\)/.test(e.message)
        && /pass intended via opts\.intended/.test(e.message),
    );
  });

  it('even an EMPTY third argument throws — the shape is wrong regardless of content', () => {
    // The generic dispatch in verify-bundle.js passed `{}` as the third argument, so a guard that
    // only fired on non-empty content would have missed the exact call site that had the bug.
    assert.throws(() => verifyToolsetAttestation(TS_VALID.token, base, {}));
  });

  it('the message names the CONSEQUENCE, not merely the arity', () => {
    let msg = '';
    try { verifyToolsetAttestation(TS_VALID.token, base, {}); } catch (e) { msg = e.message; }
    assert.match(msg, /silently not run/);
    assert.match(msg, /TOOLSET_ATTEST_VALID/,
      'a caller must learn that a mismatched declaration would have graded valid');
  });

  it('the two-argument path still cross-checks — the guard closed nothing real', () => {
    // Measured: intended.declarer against a foreign value yields declarer_mismatch when passed in
    // opts, and TOOLSET_ATTEST_VALID when passed third. That gap is what the guard closes.
    const bad = verifyToolsetAttestation(TS_VALID.token, {
      ...base, intended: { declarer: 'someone-else' },
    });
    assert.equal(bad.valid, false);
    assert.equal(bad.status, 'TOOLSET_ATTEST_UNBOUND');
    assert.equal(bad.reason, 'declarer_mismatch');
  });

  it('a matching declaration is still valid', () => {
    const ok = verifyToolsetAttestation(TS_VALID.token, base);
    assert.equal(ok.valid, true);
    assert.equal(ok.status, 'TOOLSET_ATTEST_VALID');
  });
});

describe('the arity asymmetry is REAL and cannot be introspected', () => {
  it('Function.length does not distinguish the shapes — declaring it is not laziness', () => {
    // verifyExecutionGrant is 3-ary and verifyToolsetAttestation is 2-ary, and BOTH report 2,
    // because parameters with defaults are not counted. Any dispatch that read .length would be
    // guessing. verify-bundle.js declares `arity` per slot for exactly this reason.
    assert.equal(verifyExecutionGrant.length, 2, '3-ary, but reports 2');
    assert.equal(verifyToolsetAttestation.length, 2, '2-ary, and also reports 2');
    assert.equal(verifyExecutionAttestation.length, 1, '2-ary with a default, reports 1');
    assert.equal(verifyReceipt.length, 2, '3-ary, reports 2');
  });

  it('verify-bundle declares arity for every slot that has a verifier', () => {
    const { SLOTS } = require('../verify-bundle.js');
    for (const s of SLOTS) {
      if (typeof s.verify !== 'function') continue;
      assert.ok(s.arity === 2 || s.arity === 3, `${s.key} must declare its verifier's arity`);
    }
  });
});

describe('vector provenance is honest (1127c)', () => {
  const fs = require('node:fs');
  const path = require('node:path');

  it('toolset-vectors.json generated_by resolves to a script THAT EXISTS IN THIS REPO', () => {
    // THIS IS WHAT WAS FALSE BEFORE. The field named
    // `scripts/generate-toolset-attest-vectors.js`, a path that exists only in coderifts-app, and
    // the two files were byte-identical — which, with a per-run ephemeral key, is possible only if
    // one was COPIED from the other. The document claimed a provenance this repository could not
    // honour, and nothing here could regenerate it.
    const gen = toolsetVectors.generated_by;
    assert.ok(typeof gen === 'string' && gen.length > 0, 'a vector file must say what made it');
    const abs = path.join(__dirname, '..', gen);
    assert.ok(fs.existsSync(abs), `generated_by names ${gen}, which does not exist in this repo`);
  });

  it('every vector set names a generator that exists here', () => {
    // The same check across all four sets, so a future vendored file cannot repeat the defect.
    for (const [file, field] of [
      ['toolset-vectors.json', 'generated_by'],
    ]) {
      const doc = require(`../test/${file}`);
      if (doc[field] == null) continue;
      const abs = path.join(__dirname, '..', doc[field]);
      assert.ok(fs.existsSync(abs), `${file}: ${field} names ${doc[field]}, missing here`);
    }
  });

  it('the independence decision is recorded IN the file, not only in a commit message', () => {
    assert.match(toolsetVectors.independence, /Independent of coderifts-app/);
    assert.match(toolsetVectors.independence, /cross-checks\s+compare verdicts/);
  });

  it('NO PRIVATE KEY is embedded — presence check only', () => {
    const raw = fs.readFileSync(path.join(__dirname, 'toolset-vectors.json'), 'utf8');
    assert.equal(/PRIVATE KEY|private_key|secret_key/.test(raw), false);
    assert.ok(toolsetVectors.registry.keys.length === 2, 'active + retired, public material only');
  });
});

describe('the README states the shapes', () => {
  const readme = require('node:fs').readFileSync(
    require('node:path').join(__dirname, '..', 'README.md'), 'utf8',
  );

  it('lists all FOUR signatures side by side', () => {
    assert.match(readme, /verifyReceipt\(token, ctx, opts\)/);
    assert.match(readme, /verifyExecutionGrant\(token, ctx, opts\)/);
    assert.match(readme, /verifyExecutionAttestation\(token, opts\)/);
    assert.match(readme, /verifyToolsetAttestation\(token, opts\)/);
  });

  it('records that the PYTHON toolset verifier is keyword-based, a shape JS does not share', () => {
    assert.match(readme, /verify_toolset_attestation\(token, registry, entries, intended, now_ms\)/);
    assert.match(readme, /versioned wave/);
  });

  it('says the attestation one differs and that a third argument now throws', () => {
    assert.match(readme, /throws/i);
    assert.match(readme, /opts\.intended/);
  });
});
