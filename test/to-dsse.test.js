'use strict';

/**
 * DSSE / in-toto export (roadmap 1224, Phase 1 — the format half).
 *
 * The load-bearing property is NEGATIVE: wrapping must not change what is
 * proven. So the tests that matter compare `verify(fromDSSE(toDSSE(t)))`
 * against `verify(t)` and require them identical, and check that a tampered
 * envelope cannot make a failing artifact pass or a passing one say more.
 *
 * Driven by the SHIPPED vectors rather than tokens minted here: a wrapper
 * tested only against artifacts the test itself created would not have shown it
 * handles the real ones.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const {
  toDSSE, fromDSSE, DsseError, PAYLOAD_TYPE, STATEMENT_TYPE, PREDICATE_TYPE, FORM,
} = require('../to-dsse.js');
const { verifyExecutionAttestation } = require('../verify-attest.js');

const attestVectors = require('./attest-vectors.json');
const VALID = attestVectors.vectors.find((v) => v.expected && v.expected.valid === true);
const REGISTRY = attestVectors.registry;

const decodeStatement = (env) => JSON.parse(Buffer.from(env.payload, 'base64').toString('utf8'));
const reencode = (env, statement) => ({
  ...env,
  payload: Buffer.from(JSON.stringify(statement), 'utf8').toString('base64'),
});

// ── THE ENVELOPE ─────────────────────────────────────────────────────────────
describe('toDSSE — a well-formed DSSE envelope around a compact artifact', () => {
  it('carries the in-toto payloadType, statement type and the CodeRifts predicateType', () => {
    const env = toDSSE(VALID.token);
    assert.equal(env.payloadType, PAYLOAD_TYPE);
    assert.equal(PAYLOAD_TYPE, 'application/vnd.in-toto+json');
    const st = decodeStatement(env);
    assert.equal(st._type, STATEMENT_TYPE);
    assert.equal(st.predicateType, PREDICATE_TYPE);
    assert.match(PREDICATE_TYPE, /^https:\/\/coderifts\.com\/attestations\/.+\/v1$/);
  });

  it('the signature is the ARTIFACT\'S OWN — nothing is re-signed here', () => {
    const env = toDSSE(VALID.token);
    assert.equal(env.signatures.length, 1);
    assert.equal(env.signatures[0].sig, VALID.token.split('|')[3],
      'the envelope carries a signature the compact token does not');
    assert.equal(env.signatures[0].keyid, VALID.token.split('|')[1]);
  });

  it('the subject pins the compact token by digest', () => {
    const st = decodeStatement(toDSSE(VALID.token));
    const expected = crypto.createHash('sha256').update(VALID.token, 'utf8').digest('hex');
    assert.equal(st.subject[0].digest.sha256, expected);
  });

  it('the predicate carries the payload\'s OWN fields, verbatim', () => {
    // Not a curated list: a curated list is where a field gets silently
    // dropped and the export describes a document it does not contain.
    const st = decodeStatement(toDSSE(VALID.token));
    const signed = JSON.parse(
      Buffer.from(VALID.token.split('|')[2], 'base64url').toString('utf8'),
    );
    assert.deepEqual(st.predicate.fields, signed);
  });

  it('the predicate invents no field beyond the signed payload', () => {
    const st = decodeStatement(toDSSE(VALID.token));
    const signed = JSON.parse(
      Buffer.from(VALID.token.split('|')[2], 'base64url').toString('utf8'),
    );
    assert.deepEqual(Object.keys(st.predicate.fields).sort(), Object.keys(signed).sort());
  });

  it('the predicate states what it does NOT prove', () => {
    const st = decodeStatement(toDSSE(VALID.token));
    assert.match(st.predicate.proves, /exactly what the compact CodeRifts artifact proves/);
    assert.ok(st.predicate.does_not_prove.some((d) => /no signature is checked/.test(d)));
    assert.ok(st.predicate.does_not_prove.some((d) => /does not strengthen a claim/.test(d)));
  });
});

// ── THE ROUND-TRIP ───────────────────────────────────────────────────────────
describe('fromDSSE — byte-exact, and the verdict is unchanged', () => {
  it('fromDSSE(toDSSE(token)) === token', () => {
    assert.equal(fromDSSE(toDSSE(VALID.token)), VALID.token);
  });

  it('every shipped vector round-trips byte-exactly', () => {
    for (const v of attestVectors.vectors) {
      if (typeof v.token !== 'string' || v.token.split('|').length !== 4) continue;
      assert.equal(fromDSSE(toDSSE(v.token)), v.token, `${v.name} did not round-trip`);
    }
  });

  it('THE PROPERTY: verify(round-tripped) is identical to verify(original)', () => {
    // Including the vectors that FAIL. A wrapper that quietly repaired a bad
    // artifact would be worse than one that broke a good one.
    for (const v of attestVectors.vectors) {
      if (typeof v.token !== 'string' || v.token.split('|').length !== 4) continue;
      const before = verifyExecutionAttestation(v.token, { registry: REGISTRY });
      const after = verifyExecutionAttestation(fromDSSE(toDSSE(v.token)), { registry: REGISTRY });
      assert.deepEqual(after, before, `${v.name}: the DSSE trip changed the verdict`);
    }
  });
});

// ── TAMPERING ────────────────────────────────────────────────────────────────
/**
 * The predicate carries the payload twice — preserved bytes and decoded fields.
 * Both directions of tampering must be caught, and by different mechanisms:
 * the readable half by fromDSSE, the signed half by the signature.
 */
describe('a tampered envelope cannot manufacture a claim', () => {
  it('editing a DECODED predicate field is refused by fromDSSE', () => {
    const env = toDSSE(VALID.token);
    const st = decodeStatement(env);
    st.predicate.fields.operation = 'delete-everything';
    assert.throws(
      () => fromDSSE(reencode(env, st)),
      (e) => e instanceof DsseError && e.code === 'PREDICATE_MISMATCH',
      'a predicate that disagrees with the signed bytes was accepted',
    );
  });

  it('editing the PRESERVED payload segment survives fromDSSE but FAILS verify', () => {
    // This is the honest split: fromDSSE is not a verifier, so it hands the
    // bytes back and the signature refuses them.
    const env = toDSSE(VALID.token);
    const st = decodeStatement(env);
    const forged = { ...st.predicate.fields, operation: 'delete-everything' };
    const encoded = Buffer.from(JSON.stringify(forged), 'utf8').toString('base64url');
    st.predicate.compact.encoded_payload = encoded;
    st.predicate.fields = forged;              // keep the two halves consistent

    const token = fromDSSE(reencode(env, st));
    assert.notEqual(token, VALID.token);
    const r = verifyExecutionAttestation(token, { registry: REGISTRY });
    assert.equal(r.valid, false, 'a forged payload verified');
  });

  it('swapping the signature for another artifact\'s FAILS verify', () => {
    const other = attestVectors.vectors.find(
      (v) => v.name !== VALID.name && typeof v.token === 'string' && v.token.split('|').length === 4,
    );
    if (!other) return;
    const env = toDSSE(VALID.token);
    env.signatures[0].sig = other.token.split('|')[3];
    const r = verifyExecutionAttestation(fromDSSE(env), { registry: REGISTRY });
    assert.equal(r.valid, false);
  });

  it('an envelope with no signature is refused, not defaulted', () => {
    const env = toDSSE(VALID.token);
    for (const bad of [[], [{}], [{ keyid: 'k' }], [{ sig: '' }], undefined]) {
      assert.throws(() => fromDSSE({ ...env, signatures: bad }),
        (e) => e instanceof DsseError && e.code === 'MALFORMED');
    }
  });

  it('two signatures are refused — the compact form carries exactly one', () => {
    const env = toDSSE(VALID.token);
    env.signatures.push({ keyid: 'k2', sig: 'AAAA' });
    assert.throws(() => fromDSSE(env), (e) => e.code === 'MALFORMED');
  });
});

// ── REFUSALS ─────────────────────────────────────────────────────────────────
describe('the module refuses what it cannot package or read', () => {
  it('a non-CodeRifts string is refused by toDSSE', () => {
    for (const bad of ['', 'not-a-token', 'a.b.c', 'x|y|z', null, 42, {}]) {
      assert.throws(() => toDSSE(bad), (e) => e instanceof DsseError);
    }
  });

  it('an unknown envelope tag is refused rather than wrapped', () => {
    const seg = VALID.token.split('|');
    assert.throws(
      () => toDSSE(['cr.something.else.v9', seg[1], seg[2], seg[3]].join('|')),
      (e) => e.code === 'UNSUPPORTED',
    );
  });

  it('a foreign payloadType or predicateType is refused by fromDSSE', () => {
    const env = toDSSE(VALID.token);
    assert.throws(() => fromDSSE({ ...env, payloadType: 'application/json' }),
      (e) => e.code === 'UNSUPPORTED');
    const st = decodeStatement(env);
    st.predicateType = 'https://slsa.dev/provenance/v1';
    assert.throws(() => fromDSSE(reencode(env, st)), (e) => e.code === 'UNSUPPORTED');
  });

  it('toDSSE does NOT verify — a known-invalid vector still wraps', () => {
    // Deliberate: if wrapping validated, a caller would read a successful
    // toDSSE as evidence the artifact is good. Verification is verify-attest's.
    const bad = attestVectors.vectors.find((v) => v.expected && v.expected.valid === false
      && typeof v.token === 'string' && v.token.split('|').length === 4);
    if (!bad) return;
    const env = toDSSE(bad.token);
    assert.equal(fromDSSE(env), bad.token);
    assert.equal(verifyExecutionAttestation(bad.token, { registry: REGISTRY }).valid, false);
  });
});

// ── THE RECEIPT FORM ─────────────────────────────────────────────────────────
describe('the 2-segment receipt form', () => {
  it('round-trips byte-exactly', () => {
    // MEASURED: verify.js takes `<payload_b64url>.<sig_b64url>` — two dot
    // segments, not four. The shape is exercised here directly because the
    // shipped vectors in this file are the 4-segment attestation form.
    const payload = Buffer.from(JSON.stringify({ kid: 'k1', fp: 'f', prev: '', caller: 'c', ts: '2026-08-31T00:00:00Z' }), 'utf8')
      .toString('base64url');
    const token = `${payload}.SIGNATURE`;
    const env = toDSSE(token);
    const st = decodeStatement(env);
    assert.equal(st.predicate.compact.form, FORM.RECEIPT);
    assert.equal(env.signatures[0].keyid, 'k1', 'the receipt form takes its kid from the payload');
    assert.equal(fromDSSE(env), token);
  });
});

// ── THE PRESERVED BYTES ARE LOAD-BEARING ─────────────────────────────────────
/**
 * MEASURED while building this: replacing the preserved payload segment with a
 * re-encoding of the decoded fields left every other test green — because the
 * shipped vectors happen to be minted with the same key order and no spacing,
 * so `JSON.stringify(JSON.parse(x))` reproduced them byte-for-byte.
 *
 * That is luck. A signature is over bytes, and any payload whose encoding is
 * not canonical-by-accident would fail to verify after such a round-trip. These
 * cases carry non-canonical encodings on purpose, so the preservation is tested
 * rather than coincidentally satisfied.
 */
describe('the ORIGINAL payload bytes are preserved, not re-encoded', () => {
  const tokenWithPayload = (jsonText) =>
    `${Buffer.from(jsonText, 'utf8').toString('base64url')}.SIGNATURE`;

  const NON_CANONICAL = [
    ['whitespace', '{ "kid": "k1", "fp": "f", "prev": "", "caller": "c", "ts": "t" }'],
    ['reversed key order', '{"ts":"t","caller":"c","prev":"","fp":"f","kid":"k1"}'],
    ['newlines', '{\n  "kid": "k1",\n  "fp": "f"\n}'],
  ];

  for (const [label, jsonText] of NON_CANONICAL) {
    it(`round-trips a payload with ${label} byte-exactly`, () => {
      const token = tokenWithPayload(jsonText);
      const back = fromDSSE(toDSSE(token));
      assert.equal(back, token,
        're-encoding changed the signed bytes — the signature would no longer verify');
      // …and the preserved segment really is the original, not a re-serialisation.
      const st = decodeStatement(toDSSE(token));
      assert.equal(
        Buffer.from(st.predicate.compact.encoded_payload, 'base64url').toString('utf8'),
        jsonText,
      );
    });
  }

  it('the decoded fields are still readable alongside the preserved bytes', () => {
    const token = tokenWithPayload('{ "kid": "k1", "fp": "f" }');
    const st = decodeStatement(toDSSE(token));
    assert.deepEqual(st.predicate.fields, { kid: 'k1', fp: 'f' });
    // The consistency check compares MEANING, so non-canonical spacing in the
    // preserved half is not itself a mismatch.
    assert.doesNotThrow(() => fromDSSE(toDSSE(token)));
  });
});
