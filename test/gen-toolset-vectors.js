#!/usr/bin/env node
/**
 * Generate test/toolset-vectors.json with an EPHEMERAL Ed25519 key (never the prod key).
 *
 * INDEPENDENT OF coderifts-app/test/toolset-attest-vectors.json BY DECISION (1127c). The ids and
 * scenarios are kept aligned BY INTENT; the bytes are not, and are not meant to be. Cross-checks
 * compare VERDICTS, not bytes.
 *
 * WHY THIS EXISTS. This file used to have no generator here. Its `generated_by` field named
 * `scripts/generate-toolset-attest-vectors.js`, a path that exists only in coderifts-app — and the
 * two files were byte-identical, which with a per-run ephemeral key is only possible if one was
 * COPIED from the other. So the document claimed a provenance this repository could not honour,
 * and nothing could regenerate it here.
 *
 * WHAT THE INDEPENDENCE CLAIM NOW RESTS ON, measured rather than asserted:
 *   test/run.sh:450            reads THIS file; verify-toolset.js == verify_toolset.py
 *   test/cross-check-toolset.js reads THIS file; verify-toolset.js == the app kernel module
 * Neither reads the app's vector file. Two implementations agreeing on the same tokens is the
 * claim; a copied file never was one.
 *
 * NO PRIVATE KEY IS WRITTEN. The keypair lives in memory for the length of this run; only the
 * public PEM is embedded, in the registry the vectors verify against.
 *
 *   node test/gen-toolset-vectors.js
 */
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const {
  ATTEST_VERSION,
  ENVELOPE_TAG,
  STATEMENTS,
  computeSetDigest,
  signingInput,
} = require('../verify-toolset.js');

const OUT = path.join(__dirname, 'toolset-vectors.json');

/** The declared set. Three tools, two mutating — the shape set_digest is computed over. */
const ENTRIES = [
  { name: 'patch_spec', mutation_class: 'mutating', input_schema_digest: 'sha256:bbb' },
  { name: 'read_file', mutation_class: 'readonly' },
  { name: 'write_file', mutation_class: 'mutating', input_schema_digest: 'sha256:aaa' },
];

const KID = 'vec-declarer-k1';
const RETIRED_KID = 'vec-declarer-k0';

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function main() {
  const kp = crypto.generateKeyPairSync('ed25519');
  const pem = kp.publicKey.export({ type: 'spki', format: 'pem' });

  const d = computeSetDigest(ENTRIES);
  if (!d.ok) throw new Error(`gen-toolset-vectors: computeSetDigest failed: ${d.reason || 'unknown'}`);

  const base = {
    v: ATTEST_VERSION,
    kid: KID,
    declarer: 'vectors-declarer',
    statement: STATEMENTS[0],
    set_digest: d.digest,
    declared_at: '2026-03-01T00:00:00.000Z',
    guard_version: '9.6.0',
    framework: 'langgraph',
    framework_version: '0.2.1',
    tool_count: d.tool_count,
    mutating_count: d.mutating_count,
  };

  const issue = (over = {}) => {
    const body = { ...base, ...over };
    const sig = crypto.sign(null, Buffer.from(signingInput(body), 'utf8'), kp.privateKey);
    return [ENVELOPE_TAG, body.kid, b64url(Buffer.from(JSON.stringify(body), 'utf8')), b64url(sig)]
      .join('|');
  };

  const valid = issue();
  const seg = valid.split('|');
  const reseal = (mutate) => {
    const payload = JSON.parse(Buffer.from(seg[2], 'base64url').toString('utf8'));
    mutate(payload);
    return [seg[0], seg[1], b64url(Buffer.from(JSON.stringify(payload), 'utf8')), seg[3]].join('|');
  };

  // BAD-SIG: re-encode a changed payload while keeping the ORIGINAL signature.
  const badSig = reseal((p) => { p.declarer = 'not-the-declarer'; });
  // UNKNOWN-FIELD: an additive field is REFUSED rather than ignored.
  const unknownField = reseal((p) => { p.signed_off_by = 'legal'; });

  const retiredValid = issue({ kid: RETIRED_KID });
  const retiredOut = issue({ kid: RETIRED_KID, declared_at: '2026-07-01T00:00:00.000Z' });

  const doc = {
    spec: ATTEST_VERSION,
    note: 'Ephemeral key, regenerated per run. Never a production key. Entries are the declared set.',
    generated_by: 'test/gen-toolset-vectors.js',
    independence: 'Independent of coderifts-app/test/toolset-attest-vectors.json by decision '
      + '(1127c); ids and scenarios are kept aligned by intent, bytes are not, cross-checks '
      + 'compare verdicts.',
    registry: {
      keys: [
        { kid: KID, public_key_pem: pem, status: 'active' },
        {
          kid: RETIRED_KID,
          public_key_pem: pem,
          status: 'retired',
          valid_from: '2026-01-01T00:00:00.000Z',
          retired_at: '2026-06-01T00:00:00.000Z',
        },
      ],
    },
    entries: ENTRIES,
    vectors: [
      { id: 'TS-A-VALID', token: valid, expect: { valid: true, status: 'TOOLSET_ATTEST_VALID' } },
      { id: 'TS-A-BAD-SIG', token: badSig, expect: { valid: false, status: 'TOOLSET_ATTEST_INVALID_SIGNATURE' } },
      { id: 'TS-A-UNKNOWN-KID', token: valid, registry_override: { keys: [] }, expect: { valid: false, status: 'TOOLSET_ATTEST_UNKNOWN_KEY' } },
      { id: 'TS-A-RETIRED-KEY-VALID-AT-ISSUE', token: retiredValid, expect: { valid: true, status: 'TOOLSET_ATTEST_RETIRED_KEY_VALID_AT_ISSUE' } },
      { id: 'TS-A-RETIRED-OUT-OF-WINDOW', token: retiredOut, expect: { valid: false, status: 'TOOLSET_ATTEST_UNKNOWN_KEY' } },
      { id: 'TS-A-MALFORMED', token: 'cr.toolset.attest.v1|k|only-three', expect: { valid: false, status: 'TOOLSET_ATTEST_MALFORMED' } },
      { id: 'TS-A-UNKNOWN-FIELD', token: unknownField, expect: { valid: false, status: 'TOOLSET_ATTEST_MALFORMED' } },
      { id: 'TS-A-UNBOUND-DROPPED', token: valid, entries_override: ENTRIES.slice(0, 2), expect: { valid: false, status: 'TOOLSET_ATTEST_UNBOUND' } },
      { id: 'TS-A-UNBOUND-ADDED', token: valid, entries_override: ENTRIES.concat([{ name: 'exec_shell', mutation_class: 'mutating' }]), expect: { valid: false, status: 'TOOLSET_ATTEST_UNBOUND' } },
    ],
  };

  fs.writeFileSync(OUT, `${JSON.stringify(doc, null, 2)}\n`);
  process.stdout.write(`wrote ${OUT} (${doc.vectors.length} vectors, kid=${KID})\n`);
}

main();
