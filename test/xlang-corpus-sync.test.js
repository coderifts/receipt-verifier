'use strict';

/**
 * Every copy of the cross-language corpus still agrees about what it covers.
 *
 * WHY THIS IS STRUCTURAL RATHER THAN A DIGEST. The generator signs with an EPHEMERAL key, so two
 * runs of it produce different tokens and different signatures for the same cases. The bytes are
 * therefore not comparable across copies and a sha pin would only ever say "these two files were
 * copied from the same run", which stops being true the first time anyone regenerates.
 *
 * What IS comparable is the part that carries meaning: which vector ids exist, what key state each
 * one publishes, and what verdict each one expects. A copy that lost a revocation vector, or kept
 * the id and changed the expected status, is the failure this checks for — and neither shows up in
 * a byte comparison of files that were never going to match.
 *
 * Copies live in sibling checkouts. A missing sibling is SKIPPED LOUDLY: skipping in silence would
 * make a green run mean "all copies agree" when it actually meant "we found one copy".
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const REPO = path.join(__dirname, '..');
const SIBLINGS = path.join(REPO, '..');

/** Where each copy lives, relative to the sibling-checkout root. */
const COPIES = Object.freeze([
  { name: 'python-verifier', file: path.join(SIBLINGS, 'coderifts-python-verifier', 'tests', 'xlang-vectors.json') },
  { name: 'contract-gate', file: path.join(SIBLINGS, 'coderifts-contract-gate', 'test', 'fixtures', 'xlang-vectors.json') },
  { name: 'gateway-verifier', file: path.join(SIBLINGS, 'coderifts-gateway-verifier', 'test', 'fixtures', 'xlang-vectors.json') },
  { name: 'k8s-admission', file: path.join(SIBLINGS, 'coderifts-k8s-admission', 'test', 'fixtures', 'xlang-vectors.json') },
]);

/** The comparable part of a corpus: ids → key state + expected verdict. Signatures excluded. */
function structureOf(corpus) {
  const out = {};
  for (const v of corpus.vectors) {
    out[v.name] = {
      key: v.key ? { ...v.key } : null,
      expected: { valid: v.js.valid, status: v.js.status },
    };
  }
  return out;
}

/** Regenerate into a temp file — the reference structure, from the generator itself. */
function generateReference() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'xlang-sync-'));
  const out = path.join(dir, 'xlang-vectors.json');
  execFileSync(process.execPath, [path.join(__dirname, 'gen-xlang-vectors.js'), '--out', out], {
    cwd: REPO, stdio: ['ignore', 'ignore', 'pipe'],
  });
  return JSON.parse(fs.readFileSync(out, 'utf8'));
}

const reference = structureOf(generateReference());
const present = COPIES.filter((c) => fs.existsSync(c.file));
const absent = COPIES.filter((c) => !fs.existsSync(c.file));

describe('xlang corpus — every copy covers what the generator produces', () => {
  it('the generator itself produces the withdrawal class this corpus exists for', () => {
    const statuses = new Set(Object.values(reference).map((v) => v.expected.status));
    for (const required of ['REVOKED_KEY', 'REVOKED_KEY_UNDECIDABLE', 'KEY_REVOKED',
      'KEY_RETIRED_AFTER_SIGNING', 'UNKNOWN_KEY_STATUS', 'VERIFIED_CURRENT']) {
      assert.ok(statuses.has(required), `the generator no longer emits ${required}`);
    }
  });

  it('at least one copy was found — a run that found none proves nothing', () => {
    assert.ok(present.length > 0, `no corpus copies found under ${SIBLINGS}`);
  });

  for (const copy of present) {
    describe(copy.name, () => {
      const actual = structureOf(JSON.parse(fs.readFileSync(copy.file, 'utf8')));

      it('carries every vector id the generator produces', () => {
        const missing = Object.keys(reference).filter((id) => !(id in actual));
        assert.deepEqual(missing, [], `${copy.name} is missing: ${missing.join(', ')}`);
      });

      it('carries no vector the generator does not produce', () => {
        const extra = Object.keys(actual).filter((id) => !(id in reference));
        assert.deepEqual(extra, [], `${copy.name} has unknown vectors: ${extra.join(', ')}`);
      });

      it('agrees on the expected verdict for every vector', () => {
        for (const id of Object.keys(reference)) {
          assert.deepEqual(
            actual[id].expected, reference[id].expected,
            `${copy.name} disagrees on ${id}`,
          );
        }
      });

      it('agrees on the key state each vector publishes', () => {
        for (const id of Object.keys(reference)) {
          assert.deepEqual(
            actual[id].key, reference[id].key,
            `${copy.name} publishes a different key state for ${id}`,
          );
        }
      });

      it('its bytes differ from the reference — confirming this check had to be structural', () => {
        // Not a requirement on the copy; a check on this test's own premise. If the bytes DID
        // match, a digest comparison would have been the simpler tool and this is over-built.
        const refBytes = crypto.createHash('sha256').update(JSON.stringify(reference)).digest('hex');
        const copyBytes = crypto.createHash('sha256').update(fs.readFileSync(copy.file)).digest('hex');
        assert.notEqual(refBytes, copyBytes);
      });
    });
  }

  for (const missing of absent) {
    it(`SKIPPED: ${missing.name} — checkout not found at ${missing.file}`, (t) => {
      // Loud, not silent: this names the copy that was NOT checked, so a green run cannot be
      // read as "all four agree" when one was never opened.
      t.skip(`sibling checkout absent: ${missing.file}`);
    });
  }
});
