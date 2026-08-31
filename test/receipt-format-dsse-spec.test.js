'use strict';

/**
 * DOC/CODE DRIFT-GATE for the DSSE section of RECEIPT_FORMAT.md (roadmap 1224 Phase 2a).
 *
 * RECEIPT_FORMAT.md is what the agent-discovery document's `format_spec` points
 * at, so an external implementer reads it and writes a verifier against it. A
 * doc that drifted from to-dsse.js would not be a stale comment — it would be an
 * interoperability bug someone else ships.
 *
 * to-dsse.js is the SOURCE. Every identifier asserted here is read from the
 * module at runtime and searched for in the prose, so changing the code without
 * the doc fails here rather than in someone else's integration.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  toDSSE, fromDSSE, PAYLOAD_TYPE, STATEMENT_TYPE, PREDICATE_TYPE, FORM,
} = require('../to-dsse.js');

const DOC = fs.readFileSync(path.join(__dirname, '..', 'RECEIPT_FORMAT.md'), 'utf8');
const attestVectors = require('./attest-vectors.json');
const VALID = attestVectors.vectors.find((v) => v.expected && v.expected.valid === true);

describe('RECEIPT_FORMAT.md documents the DSSE export the code actually ships', () => {
  it('the section exists at all', () => {
    assert.match(DOC, /##\s*9\.\s*DSSE\s*\/\s*in-toto export/,
      'the well-known advertises a format_spec that does not describe the DSSE export');
  });

  it('THE STABLE IDENTIFIERS match to-dsse.js exactly', () => {
    // These are what an external system keys on. A doc/code mismatch here is
    // the one that breaks someone else's verifier.
    assert.ok(DOC.includes(PREDICATE_TYPE), `doc does not carry PREDICATE_TYPE ${PREDICATE_TYPE}`);
    assert.ok(DOC.includes(PAYLOAD_TYPE), `doc does not carry PAYLOAD_TYPE ${PAYLOAD_TYPE}`);
    assert.ok(DOC.includes(STATEMENT_TYPE), `doc does not carry STATEMENT_TYPE ${STATEMENT_TYPE}`);
  });

  it('both compact forms are named', () => {
    for (const form of Object.values(FORM)) {
      assert.ok(DOC.includes(form), `doc does not name the compact form ${form}`);
    }
  });

  it('every predicate key the code emits is documented', () => {
    // Read the SHAPE from a real envelope rather than from the module's source
    // text: what a consumer receives is the thing the doc has to describe.
    const st = JSON.parse(Buffer.from(toDSSE(VALID.token).payload, 'base64').toString('utf8'));
    for (const key of Object.keys(st.predicate)) {
      assert.ok(DOC.includes(key), `predicate key "${key}" is emitted but undocumented`);
    }
    for (const key of Object.keys(st.predicate.compact)) {
      assert.ok(DOC.includes(key), `predicate.compact key "${key}" is emitted but undocumented`);
    }
    for (const key of Object.keys(st)) {
      assert.ok(DOC.includes(key), `statement key "${key}" is emitted but undocumented`);
    }
  });

  it('every DsseError code the module can throw is documented', () => {
    // An implementer branches on these. One that exists and is undocumented is
    // a branch they will not write.
    // Scan a WINDOW after each construction rather than trying to balance
    // parentheses: several of these span multiple lines with template literals
    // inside, and a `[^)]*?` regex stops at the first `)` it meets — it found
    // one code out of three while looking like it worked.
    const src = fs.readFileSync(path.join(__dirname, '..', 'to-dsse.js'), 'utf8');
    const codes = new Set();
    for (const m of src.matchAll(/new DsseError\(/g)) {
      const window = src.slice(m.index, m.index + 400);
      const args = [...window.matchAll(/'([A-Z][A-Z_]{3,})'/g)].map((x) => x[1]);
      if (args.length > 0) codes.add(args[args.length - 1]);
    }
    assert.ok(codes.size >= 3, `expected the module to define error codes, found ${codes.size}`);
    for (const code of codes) {
      assert.ok(DOC.includes(code), `DsseError code "${code}" is thrown but undocumented`);
    }
  });

  it('the honesty language is carried, not paraphrased away', () => {
    assert.match(DOC, /exactly what the compact CodeRifts artifact proves/);
    assert.match(DOC, /no signature is checked/i);
    assert.match(DOC, /does not strengthen a claim/i);
    assert.match(DOC, /does \*\*not\*\* verify|deliberately does \*\*not\*\* verify/i);
  });

  it('the round-trip property is stated as the code implements it', () => {
    assert.match(DOC, /fromDSSE\(toDSSE\(token\)\)\s*===\s*token/);
    assert.match(DOC, /byte-exact/i);
    // …and it is true, measured here rather than only asserted in prose.
    assert.equal(fromDSSE(toDSSE(VALID.token)), VALID.token);
  });

  it('the reassembly formulas in the doc are the ones the code uses', () => {
    const parts = VALID.token.split('|');
    assert.equal([parts[0], parts[1], parts[2], parts[3]].join('|'), fromDSSE(toDSSE(VALID.token)));
    assert.match(DOC, /\$\{tag\}\|\$\{kid\}\|\$\{encoded_payload\}\|\$\{sig\}/);
    assert.match(DOC, /\$\{encoded_payload\}\.\$\{sig\}/);
  });

  it('the doc does NOT claim the envelope verifies anything', () => {
    // The failure mode this whole section guards against: a spec that reads as
    // if holding a DSSE envelope were evidence.
    const dsseSection = DOC.slice(DOC.indexOf('## 9. DSSE'));
    for (const overclaim of [
      /\bthe envelope (proves|verifies|guarantees) (authenticity|the signature)\b/i,
      /\bDSSE (proves|guarantees) (more|stronger)\b/i,
      /\bself-verifying envelope\b/i,
    ]) {
      assert.doesNotMatch(dsseSection, overclaim, `the spec overclaims: ${overclaim}`);
    }
  });

  it('the scope note names the phases that are NOT shipped', () => {
    assert.match(DOC, /not\*\* shipped|are \*\*not\*\* shipped/i);
    // Whitespace-normalised: the doc is prose and wraps, so "tool\nregistry" is
    // the same statement as "tool registry" and a raw substring check would
    // report a missing phase that is plainly there.
    const flat = DOC.toLowerCase().replace(/\s+/g, ' ');
    for (const later of ['multi-language', 'admission', 'gateway', 'tool registry']) {
      assert.ok(flat.includes(later), `the scope note does not name the deferred phase: ${later}`);
    }
  });
});
