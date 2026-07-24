#!/usr/bin/env node
'use strict';

/*
 * Generate test/vectors.json with an EPHEMERAL Ed25519 key (never the prod key).
 *
 * Reproduces the CodeRifts chain-receipt format exactly (see ../RECEIPT_FORMAT.md):
 *   token       = base64url(JSON(body)) '.' base64url(sig)
 *   signed bytes= 'crchain.v1|kid|fp|prev|caller|ts'  (+ '|reg' v2; + '|reg|ir' v3)
 *   signature   = raw Ed25519 over those UTF-8 bytes
 *   prev        = 'sha256:' + sha256hex(entire previous token string) | 'null' at genesis
 *
 * Output embeds the ephemeral PUBLIC pem + every token + the expected {valid, reason}.
 * Deterministic except for the freshly generated key: fixed ts/fp/reg/ir keep diffs minimal.
 *
 * The `live` block is NOT regenerated: it is a captured REAL production receipt
 * (coderifts/demo PR #4) plus the live prod PUBLIC key, verified as-is.
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
function signingInput({ kid, fp, prev, caller, ts, reg, ir, v }) {
  const base = `${SIGNING_PREFIX}|${kid}|${fp}|${prev}|${caller}|${ts}`;
  if (v === 3) return `${base}|${reg}|${ir}`;
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

// v3 issuer: body ALWAYS carries reg (may be '') and ir, matching the live issuer.
function issueV3({ fp, prev, caller, ts, reg, ir }) {
  const body = { v: 3, kid: KID, fp, prev, caller, ts, reg, ir };
  const input = signingInput({ kid: KID, fp, prev, caller, ts, reg, ir, v: 3 });
  const sig = crypto.sign(null, Buffer.from(input, 'utf8'), privateKey);
  return `${b64url(Buffer.from(JSON.stringify(body), 'utf8'))}.${b64url(sig)}`;
}

// Fixed field values so a token only changes when the ephemeral key changes.
const TS = '2026-07-15T00:00:00.000Z';
const FP1 = 'sha256:1111111111111111111111111111111111111111111111111111111111111111';
const FP2 = 'sha256:2222222222222222222222222222222222222222222222222222222222222222';
const FP3 = 'sha256:3333333333333333333333333333333333333333333333333333333333333333';
const REG = '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945';
const IR = 'sha256:f3de7721df6ee522bc92203cf6b71eb3ac7b1d0eea106ba01d2bf81938a3a334';

// --- Standalone vectors ---
const validV1 = issue({ fp: FP1, prev: 'null', caller: 'api', ts: TS });
const validV2 = issue({ fp: FP1, prev: 'null', caller: 'anon', ts: TS, reg: REG });

// v3 (reg + ir). validV3empty locks the empty-reg layout '...|ts||ir' the issuer
// emits when a request carries no evidence-trust registry.
const validV3 = issueV3({ fp: FP1, prev: 'null', caller: 'webhook', ts: TS, reg: REG, ir: IR });
const validV3empty = issueV3({ fp: FP2, prev: 'null', caller: 'webhook', ts: TS, reg: '', ir: IR });

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

// v3 tamper cases: flip ir, flip reg -> signature_mismatch (each field is signed).
const tamperedIrV3 = tamperField(validV3, 'ir',
  'sha256:0000000000000000000000000000000000000000000000000000000000000000');
const tamperedRegV3 = tamperField(validV3, 'reg',
  'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef0');

// wrong-order v3: SIGN over the swapped layout '...|ts|ir|reg' but present a normal
// v3 body. A verifier reconstructing the frozen '...|ts|reg|ir' order must reject it.
const wrongOrderV3 = (() => {
  const fp = FP3; const prev = 'null'; const caller = 'webhook'; const ts = TS; const reg = REG; const ir = IR;
  const body = { v: 3, kid: KID, fp, prev, caller, ts, reg, ir };
  const swapped = `${SIGNING_PREFIX}|${KID}|${fp}|${prev}|${caller}|${ts}|${ir}|${reg}`;
  const sig = crypto.sign(null, Buffer.from(swapped, 'utf8'), privateKey);
  return `${b64url(Buffer.from(JSON.stringify(body), 'utf8'))}.${b64url(sig)}`;
})();

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

// Captured REAL production receipt (coderifts/demo PR #4) + the live prod PUBLIC key.
// NOT regenerated -- a frozen artifact proving the verifier accepts a genuine v3 token.
const LIVE = {
  note: 'REAL production v3 receipt captured from coderifts/demo PR #4. Verified against '
      + 'the live prod PUBLIC key (kid 2026-07-k1). Frozen artifact -- NOT regenerated.',
  source: 'coderifts/demo PR #4 sticky comment',
  kid: '2026-07-k1',
  public_key_pem: '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAJh8xDXLaOCpQ+bBC9d2I+zG1qVsCpeCuWbtH+aGjC7A=\n-----END PUBLIC KEY-----\n',
  vectors: [
    {
      name: 'live_v3_demo',
      token: 'eyJ2IjozLCJraWQiOiIyMDI2LTA3LWsxIiwiZnAiOiJzaGEyNTY6NzA2OTkzNDE1NDk3ODQwNDIyNGIyMGZkMWM1ZDllM2EwZGRjYzY5Y2FjYTU4NjdmOGU3Mzc2NmUyODZjY2ZlYyIsInByZXYiOiJudWxsIiwiY2FsbGVyIjoid2ViaG9vayIsInRzIjoiMjAyNi0wNy0yNFQwNzo0NDo0NS44MDBaIiwicmVnIjoiNGY1M2NkYTE4YzJiYWEwYzAzNTRiYjVmOWEzZWNiZTVlZDEyYWI0ZDhlMTFiYTg3M2MyZjExMTYxMjAyYjk0NSIsImlyIjoic2hhMjU2OmYzZGU3NzIxZGY2ZWU1MjJiYzkyMjAzY2Y2YjcxZWIzYWM3YjFkMGVlYTEwNmJhMDFkMmJmODE5MzhhM2EzMzQifQ.2_PhB-rDQ69MQq_JmklXUNroUbVehCr1Prr6sSHArBn6AA6eodZjiWUPEbOo7BFEuKAVQnInh-48J-oIM5phCA',
      expected: { valid: true },
    },
  ],
};

const vectors = {
  note: 'Ephemeral test key. NOT the production key. Regenerate with: node test/gen-vectors.js',
  kid: KID,
  public_key_pem: publicPem,
  vectors: [
    { name: 'valid_v1', token: validV1, expected: { valid: true } },
    { name: 'valid_v2', token: validV2, expected: { valid: true } },
    { name: 'valid_v3', token: validV3, expected: { valid: true } },
    { name: 'valid_v3_empty_reg', token: validV3empty, expected: { valid: true } },
    { name: 'tampered_fp', token: tamperedFp, expected: { valid: false, reason: 'signature_mismatch' } },
    { name: 'tampered_reg_v2', token: tamperedRegV2, expected: { valid: false, reason: 'signature_mismatch' } },
    { name: 'tampered_ir_v3', token: tamperedIrV3, expected: { valid: false, reason: 'signature_mismatch' } },
    { name: 'tampered_reg_v3', token: tamperedRegV3, expected: { valid: false, reason: 'signature_mismatch' } },
    { name: 'wrong_order_v3', token: wrongOrderV3, expected: { valid: false, reason: 'signature_mismatch' } },
    { name: 'wrong_kid', token: wrongKid, expected: { valid: false, reason: 'unknown_kid' } },
    { name: 'truncated', token: truncated, expected: { valid: false, reason: 'malformed_structure' } },
    { name: 'garbage_base64', token: garbageBase64, expected: { valid: false, reason: 'bad_json' } },
  ],
  chain: {
    tokens: [c1, c2, c3],
    expected: { valid: true, first: 'genesis' },
  },
  live: LIVE,
};

const out = path.join(__dirname, 'vectors.json');
fs.writeFileSync(out, JSON.stringify(vectors, null, 2) + '\n', 'utf8');
process.stdout.write(`wrote ${out} (${vectors.vectors.length} vectors + ${vectors.chain.tokens.length}-link chain + ${vectors.live.vectors.length} live)\n`);
