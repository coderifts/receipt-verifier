#!/usr/bin/env node
'use strict';

/*
 * Generate test/vectors.json with an EPHEMERAL Ed25519 key (never the prod key).
 *
 * Reproduces the CodeRifts chain-receipt format exactly (see ../RECEIPT_FORMAT.md):
 *   token       = base64url(JSON(body)) '.' base64url(sig)
 *   signed bytes= 'crchain.v1|kid|fp|prev|caller|ts'  (+ '|reg' when body.v === 2)
 *   signature   = raw Ed25519 over those UTF-8 bytes
 *   prev        = 'sha256:' + sha256hex(entire previous token string) | 'null' at genesis
 *
 * Output embeds the ephemeral PUBLIC pem + every token + the expected {valid, reason}.
 * Deterministic except for the freshly generated key: fixed ts/fp/reg keep diffs minimal.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const SIGNING_PREFIX = 'crchain.v1';
const KID = 'test-k1';

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}
function sha256hex(str) {
  return crypto.createHash('sha256').update(String(str), 'utf8').digest('hex');
}
function signingInput({ kid, fp, prev, caller, ts, reg, v }) {
  const base = `${SIGNING_PREFIX}|${kid}|${fp}|${prev}|${caller}|${ts}`;
  return v === 2 ? `${base}|${reg}` : base;
}

// Ephemeral keypair -- generated fresh every run, never persisted as a private key.
const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const publicPem = publicKey.export({ type: 'spki', format: 'pem' });

function issue({ fp, prev, caller, ts, reg }) {
  const v = typeof reg === 'string' && reg.length > 0 ? 2 : 1;
  const body = v === 2
    ? { v: 2, kid: KID, fp, prev, caller, ts, reg }
    : { v: 1, kid: KID, fp, prev, caller, ts };
  const input = signingInput({ kid: KID, fp, prev, caller, ts, reg, v });
  const sig = crypto.sign(null, Buffer.from(input, 'utf8'), privateKey);
  return `${b64url(Buffer.from(JSON.stringify(body), 'utf8'))}.${b64url(sig)}`;
}

// Fixed field values so a token only changes when the ephemeral key changes.
const TS = '2026-07-15T00:00:00.000Z';
const FP1 = 'sha256:1111111111111111111111111111111111111111111111111111111111111111';
const FP2 = 'sha256:2222222222222222222222222222222222222222222222222222222222222222';
const FP3 = 'sha256:3333333333333333333333333333333333333333333333333333333333333333';
const REG = '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945';

// --- Standalone vectors ---
const validV1 = issue({ fp: FP1, prev: 'null', caller: 'api', ts: TS });
const validV2 = issue({ fp: FP1, prev: 'null', caller: 'anon', ts: TS, reg: REG });

// tampered-fp: mutate fp in the body, keep the original signature -> signature_mismatch.
function tamperField(token, field, value) {
  const [bodyB64, sigB64] = token.split('.');
  const body = JSON.parse(Buffer.from(bodyB64, 'base64url').toString('utf8'));
  body[field] = value;
  return `${b64url(Buffer.from(JSON.stringify(body), 'utf8'))}.${sigB64}`;
}
const tamperedFp = tamperField(validV1, 'fp',
  'sha256:0000000000000000000000000000000000000000000000000000000000000000');
const tamperedRegV2 = tamperField(validV2, 'reg',
  'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef0');

// wrong-kid: a well-signed token whose body kid != the discovery kid -> unknown_kid.
const wrongKid = (() => {
  const fp = FP1; const prev = 'null'; const caller = 'api'; const ts = TS; const kid = 'wrong-k9';
  const body = { v: 1, kid, fp, prev, caller, ts };
  const input = `${SIGNING_PREFIX}|${kid}|${fp}|${prev}|${caller}|${ts}`;
  const sig = crypto.sign(null, Buffer.from(input, 'utf8'), privateKey);
  return `${b64url(Buffer.from(JSON.stringify(body), 'utf8'))}.${b64url(sig)}`;
})();

// truncated: drop the signature segment entirely -> one segment -> malformed_structure.
const truncated = validV1.split('.')[0];

// garbage base64: body segment decodes to non-JSON -> bad_json.
const garbageBase64 = `${b64url(Buffer.from('this is not json', 'utf8'))}.${b64url(crypto.randomBytes(64))}`;

// --- 3-link chain (oldest first) ---
const c1 = issue({ fp: FP1, prev: 'null', caller: 'api', ts: TS });
const c2 = issue({ fp: FP2, prev: `sha256:${sha256hex(c1)}`, caller: 'api', ts: TS });
const c3 = issue({ fp: FP3, prev: `sha256:${sha256hex(c2)}`, caller: 'api', ts: TS });

const vectors = {
  note: 'Ephemeral test key. NOT the production key. Regenerate with: node test/gen-vectors.js',
  kid: KID,
  public_key_pem: publicPem,
  vectors: [
    { name: 'valid_v1', token: validV1, expected: { valid: true } },
    { name: 'valid_v2', token: validV2, expected: { valid: true } },
    { name: 'tampered_fp', token: tamperedFp, expected: { valid: false, reason: 'signature_mismatch' } },
    { name: 'tampered_reg_v2', token: tamperedRegV2, expected: { valid: false, reason: 'signature_mismatch' } },
    { name: 'wrong_kid', token: wrongKid, expected: { valid: false, reason: 'unknown_kid' } },
    { name: 'truncated', token: truncated, expected: { valid: false, reason: 'malformed_structure' } },
    { name: 'garbage_base64', token: garbageBase64, expected: { valid: false, reason: 'bad_json' } },
  ],
  chain: {
    tokens: [c1, c2, c3],
    expected: { valid: true, first: 'genesis' },
  },
};

const out = path.join(__dirname, 'vectors.json');
fs.writeFileSync(out, JSON.stringify(vectors, null, 2) + '\n', 'utf8');
process.stdout.write(`wrote ${out} (${vectors.vectors.length} vectors + ${vectors.chain.tokens.length}-link chain)\n`);
