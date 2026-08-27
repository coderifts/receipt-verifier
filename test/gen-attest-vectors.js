#!/usr/bin/env node
'use strict';

/*
 * Generate test/attest-vectors.json with an EPHEMERAL Ed25519 executor key.
 * EG-A-* classes from coderifts-app/test/adapter-acceptance/cases.v1.json.
 *
 * Tokens are cr.exec.attest.v1|{kid}|{payload_b64}|{sig_b64} signed with
 * crexecattest.v1|… pipe input (docs/cr-exec-attest-v1.md).
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const {
  signingInput,
  ATTEST_VERSION,
  ENVELOPE_TAG,
} = require('../verify-attest.js');

const KID = 'exec-test-k1';
const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const publicPem = publicKey.export({ type: 'spki', format: 'pem' });

const COMMITTED = '2026-06-15T12:00:00Z';
/**
 * THE GRANT THESE ATTESTATIONS BIND (roadmap 1126).
 *
 * These three were filler: SCOPE = 'ab'x32, RD = 'cd'x32, JTI = 'jti-1'. None resolved to anything
 * in this repository, so our own vectors taught that the attestation->grant link need not hold —
 * the same defect 1125 fixed one layer down.
 *
 * WHAT THE VERIFIER ACTUALLY CHECKS, measured at verify-attest.js:346-357: given an intended grant
 * it compares, by string equality, grant_jti / scope_hash / state_nonce / receipt_digest against
 * the grant's own payload fields. It does NOT re-derive scope_hash from operation+target+
 * after_payload — so a "real" scope_hash is meaningful only because the GRANT's scope_hash is
 * itself computed by computeScopeHash in gen-grant-vectors.js. Binding to the real grant makes the
 * whole chain genuine; inventing a plausible-looking hash here would have been theatre.
 *
 * ORDERING, load-bearing: vectors.json -> grant-vectors.json -> attest-vectors.json. Each link
 * binds the one above it, so regenerate in that order.
 */
const GRANT_VECTORS = require('./grant-vectors.json');
const REAL_GRANT = GRANT_VECTORS.vectors.find((v) => v.name === 'EG-VALID');
if (!REAL_GRANT || typeof REAL_GRANT.token !== 'string') {
  throw new Error(
    'gen-attest-vectors: test/grant-vectors.json has no `EG-VALID` grant to bind. Run '
    + 'node test/gen-vectors.js && node test/gen-grant-vectors.js first — an attestation bound to '
    + 'a grant that does not exist is the defect this generator was changed to remove (1126).',
  );
}
const REAL_GRANT_TOKEN = REAL_GRANT.token;
const REAL_GRANT_BODY = JSON.parse(
  Buffer.from(REAL_GRANT_TOKEN.split('.')[0], 'base64url').toString('utf8'),
);
/** All three now come from the real grant, so the chain receipt -> grant -> attest resolves. */
const SCOPE = REAL_GRANT_BODY.scope_hash;
const RD = REAL_GRANT_BODY.receipt_digest;
const JTI = REAL_GRANT_BODY.jti;
for (const [n, val] of [['scope_hash', SCOPE], ['receipt_digest', RD], ['jti', JTI]]) {
  if (typeof val !== 'string' || val.length === 0) {
    throw new Error(`gen-attest-vectors: EG-VALID grant carries no ${n} to bind`);
  }
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function issue(over = {}) {
  const body = {
    v: ATTEST_VERSION,
    executor_kid: KID,
    grant_jti: over.grant_jti || JTI,
    receipt_digest: over.receipt_digest || RD,
    scope_hash: over.scope_hash || SCOPE,
    committed_at: over.committed_at || COMMITTED,
  };
  if (over.state_nonce) body.state_nonce = over.state_nonce;
  const sig = crypto.sign(null, Buffer.from(signingInput(body), 'utf8'), privateKey);
  return [ENVELOPE_TAG, body.executor_kid, b64url(Buffer.from(JSON.stringify(body), 'utf8')), b64url(sig)].join('|');
}

function fakeGrant(jti, extra = {}) {
  const body = {
    v: 'cr.exec.v1',
    kid: 'grant-k1',
    receipt_digest: extra.receipt_digest || RD,
    scope_hash: extra.scope_hash || SCOPE,
    audience: 'v:deadbeefdead',
    operation: 'merge',
    target_id: 'sha256:tgt',
    jti,
    iat: '2026-06-15T12:00:00Z',
    exp: '2099-01-01T00:00:00Z',
  };
  if (extra.state_nonce) body.state_nonce = extra.state_nonce;
  return `${b64url(Buffer.from(JSON.stringify(body), 'utf8'))}.${b64url(Buffer.from('x'))}`;
}

const registry = {
  keys: [{
    kid: KID,
    public_key_pem: publicPem,
    status: 'active',
    valid_from: '2026-01-01T00:00:00Z',
    retired_at: null,
  }],
};

const retiredRegistry = {
  keys: [{
    kid: KID,
    public_key_pem: publicPem,
    status: 'retired',
    valid_from: '2026-01-01T00:00:00Z',
    retired_at: '2026-12-01T00:00:00Z',
  }],
};

const validTok = issue();
const parts = validTok.split('|');
const sigBuf = Buffer.from(parts[3], 'base64url');
sigBuf[0] ^= 0xff;
const badSigTok = [...parts.slice(0, 3), sigBuf.toString('base64url')].join('|');
const nonceTok = issue({ state_nonce: 'nonce-A' });

const vectors = [
  {
    // 1126 — flags.grant is now the REAL grant token, so the cross-check actually FIRES.
    // Measured before the fix: 5 of 7 vectors carried no grant flag, so verify-attest.js:339
    // `wantsCross` was false and the three bindings were never compared. EG-A-VALID passed with
    // valid:true having checked nothing about them.
    name: 'EG-A-VALID',
    token: validTok,
    expected: { valid: true, status: 'ATTEST_VALID' },
    keys: 'registry',
    flags: { grant: REAL_GRANT_TOKEN },
  },
  {
    name: 'EG-A-BAD-SIG',
    token: badSigTok,
    expected: { valid: false, status: 'ATTEST_INVALID_SIGNATURE', reason: 'signature_mismatch' },
    keys: 'registry',
  },
  {
    name: 'EG-A-UNKNOWN-KID',
    token: validTok,
    expected: { valid: false, status: 'ATTEST_UNKNOWN_KEY', reason: 'unknown_kid' },
    keys: 'empty',
  },
  {
    // The other vector expecting valid:true while checking no binding — same fix.
    name: 'EG-A-RETIRED-KEY-VALID-AT-ISSUE',
    token: validTok,
    expected: { valid: true, status: 'ATTEST_RETIRED_KEY_VALID_AT_ISSUE' },
    keys: 'retired_registry',
    flags: { grant: REAL_GRANT_TOKEN },
  },
  {
    name: 'EG-A-MALFORMED',
    token: 'not-an-attest',
    expected: { valid: false, status: 'ATTEST_MALFORMED', reason: 'malformed_structure' },
    keys: 'registry',
  },
  {
    name: 'EG-A-UNBOUND-JTI',
    token: validTok,
    expected: { valid: false, status: 'ATTEST_UNBOUND', reason: 'grant_jti_mismatch' },
    keys: 'registry',
    flags: { grant: fakeGrant('other-jti') },
  },
  {
    name: 'EG-A-STATE-NONCE-MISMATCH',
    token: nonceTok,
    expected: { valid: false, status: 'ATTEST_UNBOUND', reason: 'state_nonce_mismatch' },
    keys: 'registry',
    flags: { grant: fakeGrant(JTI, { state_nonce: 'nonce-B' }) },
  },
  {
    // 1126 — receipt_digest has a CHECKED comparison (verify-attest.js:355) and had no negative
    // vector. Without one, a regression that stopped comparing it would go unnoticed.
    name: 'EG-A-MISMATCH-RECEIPT',
    note: 'INTENTIONALLY NON-MATCHING: the intended grant carries a different receipt_digest than '
      + 'this attestation binds. It must never be "fixed" to match — it exists to prove the '
      + 'attestation->receipt binding is actually checked.',
    token: validTok,
    expected: { valid: false, status: 'ATTEST_UNBOUND', reason: 'receipt_digest_mismatch' },
    keys: 'registry',
    flags: { grant: fakeGrant(JTI, { receipt_digest: `sha256:${'11'.repeat(32)}` }) },
  },
  {
    // Same reasoning for scope_hash (verify-attest.js:349).
    name: 'EG-A-MISMATCH-SCOPE',
    note: 'INTENTIONALLY NON-MATCHING: the intended grant carries a different scope_hash than this '
      + 'attestation binds. It must never be "fixed" to match — it exists to prove the '
      + 'attestation->scope binding is actually checked.',
    token: validTok,
    expected: { valid: false, status: 'ATTEST_UNBOUND', reason: 'scope_hash_mismatch' },
    keys: 'registry',
    flags: { grant: fakeGrant(JTI, { scope_hash: `sha256:${'22'.repeat(32)}` }) },
  },
];

const out = {
  // 1132 — see the note in test/gen-vectors.js. Asserted to resolve in this repository.
  generated_by: 'test/gen-attest-vectors.js',
  kid: KID,
  public_key_pem: publicPem,
  registry,
  retired_registry: retiredRegistry,
  empty_registry: { keys: [] },
  vectors,
};

const dest = path.join(__dirname, 'attest-vectors.json');
fs.writeFileSync(dest, JSON.stringify(out, null, 2) + '\n');
process.stdout.write(`wrote ${dest} (${vectors.length} EG-A-* vectors)\n`);
