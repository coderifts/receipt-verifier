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
function signingInput({ kid, fp, prev, caller, ts, reg, ir, expires_at, bh, v }) {
  const base = `${SIGNING_PREFIX}|${kid}|${fp}|${prev}|${caller}|${ts}`;
  if (v === 4) return `${base}|${reg}|${ir}|${expires_at}|${bh}`;
  if (v === 3) return `${base}|${reg}|${ir}`;
  return v === 2 ? `${base}|${reg}` : base;
}

// Minimal canonical JSON (must match verify.js canonicalJson) for envelope-binding vectors.
function canonicalJson(value) {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'boolean' || t === 'string') return JSON.stringify(value);
  if (t === 'number') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

// Ephemeral keypair -- generated fresh every run, never persisted as a private key.
const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const publicPem = publicKey.export({ type: 'spki', format: 'pem' });

// A second ephemeral key that plays the RETIRED key in the registry vectors.
const retired = crypto.generateKeyPairSync('ed25519');
const retiredPem = retired.publicKey.export({ type: 'spki', format: 'pem' });
const RETIRED_KID = 'test-retired-k0';
const RETIRED_AT = '2026-07-10T00:00:00.000Z'; // ts before this = valid-at-issue; at/after = invalid

// v4 issuer: body carries reg + ir ('' when absent) + expires_at + bh.
function issueV4({ fp, prev, caller, ts, reg, ir, expires_at, bh }, signer = privateKey, kid = KID) {
  const body = { v: 4, kid, fp, prev, caller, ts, reg, ir, expires_at, bh };
  const input = signingInput({ kid, fp, prev, caller, ts, reg, ir, expires_at, bh, v: 4 });
  const sig = crypto.sign(null, Buffer.from(input, 'utf8'), signer);
  return `${b64url(Buffer.from(JSON.stringify(body), 'utf8'))}.${b64url(sig)}`;
}

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

// --- v4 vectors (expires_at + bh in the signed bytes) ---
const BH = 'sha256:' + 'c'.repeat(64);
const EXP_FUTURE = '2099-01-01T00:00:00.000Z';
const EXP_PAST = '2000-01-01T00:00:00.000Z';
const validV4 = issueV4({ fp: FP1, prev: 'null', caller: 'bundle', ts: TS, reg: '', ir: '', expires_at: EXP_FUTURE, bh: BH });
const expiredV4 = issueV4({ fp: FP1, prev: 'null', caller: 'bundle', ts: TS, reg: '', ir: '', expires_at: EXP_PAST, bh: BH });

// v4 downgraded to v3 by folding |expires_at|bh into ir. The reconstructed v3 bytes collide with the
// original v4 bytes (signature verifies) but ir now contains '|' -> the delimiter guard rejects it.
const downgradeV4asV3 = (() => {
  const [bodyB64, sigB64] = validV4.split('.');
  const b = JSON.parse(Buffer.from(bodyB64, 'base64url').toString('utf8'));
  const folded = { v: 3, kid: b.kid, fp: b.fp, prev: b.prev, caller: b.caller, ts: b.ts, reg: b.reg, ir: `${b.ir}|${b.expires_at}|${b.bh}` };
  return `${b64url(Buffer.from(JSON.stringify(folded), 'utf8'))}.${sigB64}`;
})();

// unsupported v5: a body with v:5 signed over the v1-layout base (the verifier's fallthrough), so the
// signature is VALID but the version exceeds MAX_SUPPORTED_V -> UNSUPPORTED_VERSION.
const unsupportedV5 = (() => {
  const fp = FP1; const prev = 'null'; const caller = 'api'; const ts = TS;
  const body = { v: 5, kid: KID, fp, prev, caller, ts };
  const input = `${SIGNING_PREFIX}|${KID}|${fp}|${prev}|${caller}|${ts}`;
  const sig = crypto.sign(null, Buffer.from(input, 'utf8'), privateKey);
  return `${b64url(Buffer.from(JSON.stringify(body), 'utf8'))}.${b64url(sig)}`;
})();

// --- v4 envelope-binding block: a token whose bh == body_hash of the envelope below ---
const bindEnvelope = {
  spec_version: 'decision-result.v1.1', decision: 'BLOCK', operation: 'merge', environment: 'production',
  receipt: null, decision_body_hash: null,
};
const bindBh = (() => {
  const rest = { ...bindEnvelope }; delete rest.receipt; delete rest.decision_body_hash;
  return 'sha256:' + sha256hex(canonicalJson(rest));
})();
const bindToken = issueV4({ fp: FP1, prev: 'null', caller: 'bundle', ts: TS, reg: '', ir: '', expires_at: EXP_FUTURE, bh: bindBh });

// --- retired-key block: tokens signed by a RETIRED key, before / after its retired_at ---
const retiredValidAtIssue = issueV4({ fp: FP1, prev: 'null', caller: 'bundle', ts: '2026-07-05T00:00:00.000Z', reg: '', ir: '', expires_at: EXP_FUTURE, bh: BH }, retired.privateKey, RETIRED_KID);
const retiredAfterRetire = issueV4({ fp: FP1, prev: 'null', caller: 'bundle', ts: '2026-07-20T00:00:00.000Z', reg: '', ir: '', expires_at: EXP_FUTURE, bh: BH }, retired.privateKey, RETIRED_KID);

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
  // 1132 — the generator that produced this file, as a path resolvable IN THIS REPOSITORY.
  // toolset-vectors.json once named a generator that existed only in coderifts-app (1127c); a
  // provenance field pointing somewhere unreachable is worse than none, because it reads as an
  // answer. test/verify-attest.test.js asserts every declared path exists here.
  generated_by: 'test/gen-vectors.js',
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
    { name: 'valid_v4', token: validV4, expected: { valid: true, status: 'VERIFIED_CURRENT' } },
    { name: 'expired_v4', token: expiredV4, expected: { valid: false, status: 'VERIFIED_EXPIRED' } },
    { name: 'downgrade_v4_as_v3', token: downgradeV4asV3, expected: { valid: false, status: 'INVALID_SIGNATURE', reason: 'delimiter_in_field' } },
    { name: 'unsupported_v5', token: unsupportedV5, expected: { valid: false, status: 'UNSUPPORTED_VERSION' } },
  ],
  chain: {
    tokens: [c1, c2, c3],
    expected: { valid: true, first: 'genesis' },
  },
  // v4 envelope-binding: verify with --envelope <bind.envelope> -> VERIFIED_CURRENT; a tampered
  // envelope -> body_hash_mismatch. run.sh writes these to temp files.
  bind: {
    token: bindToken,
    envelope: bindEnvelope,
    expected_ok: { valid: true, status: 'VERIFIED_CURRENT' },
    expected_tampered: { valid: false, status: 'INVALID_SIGNATURE', reason: 'body_hash_mismatch' },
  },
  // retired-key rule: signed by a retired key. ts before retired_at -> RETIRED_KEY_VALID_AT_ISSUE;
  // ts at/after -> INVALID_SIGNATURE. run.sh builds a registry with active + retired entries.
  retired: {
    registry: {
      keys: [
        { kid: KID, public_key_pem: publicPem, status: 'active', valid_from: null, retired_at: null },
        { kid: RETIRED_KID, public_key_pem: retiredPem, status: 'retired', valid_from: null, retired_at: RETIRED_AT },
      ],
    },
    token_valid_at_issue: retiredValidAtIssue,
    token_after_retire: retiredAfterRetire,
    expected_valid_at_issue: { valid: true, status: 'RETIRED_KEY_VALID_AT_ISSUE' },
    expected_after_retire: { valid: false, status: 'INVALID_SIGNATURE' },
  },
  live: LIVE,
};

const out = path.join(__dirname, 'vectors.json');
fs.writeFileSync(out, JSON.stringify(vectors, null, 2) + '\n', 'utf8');
process.stdout.write(`wrote ${out} (${vectors.vectors.length} vectors + ${vectors.chain.tokens.length}-link chain + ${vectors.live.vectors.length} live)\n`);
