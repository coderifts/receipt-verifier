#!/usr/bin/env node
'use strict';

/*
 * Generate the CROSS-LANGUAGE vector corpus with an EPHEMERAL Ed25519 key
 * (never a production key).
 *
 * Every vector is a real token signed here and then verified by verify.js in
 * this same run: the expected verdict recorded in the file is the one the
 * reference implementation actually produced, not one a human asserted. A
 * generator that wrote down what it BELIEVED the verifier would say would pin
 * the belief rather than the behaviour.
 *
 * Vectors carry a per-vector `key` block (registry status, retired_at,
 * revoked_at, compromised_at). A consumer builds the keyring from that block, so
 * key WITHDRAWAL — the class where implementations have actually diverged — is
 * covered, not just signature and kid resolution.
 *
 * Usage:
 *   node test/gen-xlang-vectors.js > xlang-vectors.json
 *   node test/gen-xlang-vectors.js --out <path>
 *
 * This repository does NOT commit xlang-vectors.json (ephemeral key → bytes are a
 * run artifact). Sibling copies live under test/fixtures/ (contract-gate,
 * gateway-verifier, k8s-admission) and coderifts-python-verifier/tests/.
 * Hashing a missing path here as empty is sha256("") = e3b0c442… — not a pin.
 *
 * The `dsse` block is REGENERATED from this run's VALID token, not carried
 * forward: the key is ephemeral, so a carried envelope would wrap a token signed
 * by a key this corpus no longer publishes, and every consumer asserting
 * fromDSSE(envelope) === VALID.token would fail on a stale artifact.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const { verifyReceipt, keyFromPem } = require('../verify.js');
const { toDSSE } = require('../to-dsse.js');

const SIGNING_PREFIX = 'crchain.v1';
const KID = 'xlang-k1';
const FP = `sha256:${'a'.repeat(64)}`;
const BOUNDARY = '2026-06-01T00:00:00Z';
const SIGNED_BEFORE = '2026-01-01T00:00:00Z';
const SIGNED_AFTER = '2026-09-01T00:00:00Z';

const b64url = (b) => Buffer.from(b).toString('base64url');

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const PUBLIC_PEM = publicKey.export({ type: 'spki', format: 'pem' });

function mint({ kid = KID, ts = SIGNED_AFTER, sign = true }) {
  const body = { v: 1, kid, fp: FP, prev: '', caller: 'svc', ts };
  const input = `${SIGNING_PREFIX}|${body.kid}|${body.fp}|${body.prev}|${body.caller}|${body.ts}`;
  const sig = sign
    ? crypto.sign(null, Buffer.from(input, 'utf8'), privateKey)
    : crypto.randomBytes(64);
  return `${b64url(JSON.stringify(body))}.${b64url(sig)}`;
}

/**
 * name, the key entry the registry publishes, and the token.
 * `key: null` means the receipt names a kid the registry does not carry.
 */
const CASES = [
  ['VALID', { status: 'active' }, mint({})],
  ['BAD_SIGNATURE', { status: 'active' }, mint({ sign: false })],
  ['UNKNOWN_KID', { status: 'active' }, mint({ kid: 'nobody-knows-me' })],

  // Planned rotation.
  ['RETIRED_SIGNED_BEFORE', { status: 'retired', retired_at: BOUNDARY }, mint({ ts: SIGNED_BEFORE })],
  ['RETIRED_SIGNED_AFTER', { status: 'retired', retired_at: BOUNDARY }, mint({ ts: SIGNED_AFTER })],
  ['RETIRED_NO_TIMESTAMP', { status: 'retired' }, mint({ ts: SIGNED_AFTER })],

  // Compromise. The attacker chooses ts, so no timestamp rehabilitates the key.
  ['REVOKED_SIGNED_AFTER', { status: 'revoked', compromised_at: BOUNDARY }, mint({ ts: SIGNED_AFTER })],
  ['REVOKED_SIGNED_BEFORE', { status: 'revoked', compromised_at: BOUNDARY }, mint({ ts: SIGNED_BEFORE })],
  ['REVOKED_NO_COMPROMISED_AT', { status: 'revoked' }, mint({ ts: SIGNED_AFTER })],
  ['REVOKED_AT_ON_ACTIVE_ENTRY', { status: 'active', revoked_at: BOUNDARY }, mint({ ts: SIGNED_BEFORE })],

  // A status the verifier does not recognise must fail closed, not open.
  ['UNKNOWN_KEY_STATUS', { status: 'suspended' }, mint({ ts: SIGNED_AFTER })],
];

function referenceVerdict(keyEntry, token) {
  const keyring = new Map([[KID, {
    publicKey: keyFromPem(PUBLIC_PEM),
    status: keyEntry.status ?? null,
    retired_at: keyEntry.retired_at ?? null,
    revoked_at: keyEntry.revoked_at ?? null,
    compromised_at: keyEntry.compromised_at ?? null,
  }]]);
  const r = verifyReceipt(token, { ctx: { keyring, expectedKid: null } });
  return { valid: r.valid, status: r.status };
}

const args = process.argv.slice(2);
const outIdx = args.indexOf('--out');

const corpus = {
  kid: KID,
  public_key_pem: PUBLIC_PEM,
  vectors: CASES.map(([name, key, token]) => ({
    name,
    token,
    // What the registry publishes for this vector's kid. A consumer builds its
    // keyring from exactly this, so both implementations judge the same input.
    key,
    js: referenceVerdict(key, token),
  })),
};

// DSSE, from THIS run's tokens: a valid envelope and one whose wrapped receipt
// does not verify. Unwrapping is not verification, and the second vector is what
// proves a consumer did not confuse the two.
corpus.dsse = {
  valid: toDSSE(corpus.vectors.find((v) => v.name === 'VALID').token),
  bad_signature: toDSSE(corpus.vectors.find((v) => v.name === 'BAD_SIGNATURE').token),
};

const json = `${JSON.stringify(corpus, null, 1)}\n`;
if (outIdx !== -1 && args[outIdx + 1]) {
  fs.writeFileSync(args[outIdx + 1], json);
  process.stderr.write(`wrote ${corpus.vectors.length} vectors to ${args[outIdx + 1]}\n`);
} else {
  process.stdout.write(json);
}
