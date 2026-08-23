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
const SCOPE = 'sha256:' + 'ab'.repeat(32);
const RD = 'sha256:' + 'cd'.repeat(32);
const JTI = 'jti-1';

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
    name: 'EG-A-VALID',
    token: validTok,
    expected: { valid: true, status: 'ATTEST_VALID' },
    keys: 'registry',
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
    name: 'EG-A-RETIRED-KEY-VALID-AT-ISSUE',
    token: validTok,
    expected: { valid: true, status: 'ATTEST_RETIRED_KEY_VALID_AT_ISSUE' },
    keys: 'retired_registry',
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
];

const out = {
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
