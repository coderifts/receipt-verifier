#!/usr/bin/env node
'use strict';

/*
 * CodeRifts chain-receipt verifier -- Node >= 20, zero dependencies (node:crypto only).
 *
 * Verifies an Ed25519-signed CodeRifts chain_receipt WITHOUT trusting the CodeRifts
 * service. The reference format is frozen in ./RECEIPT_FORMAT.md.
 *
 * Usage:
 *   node verify.js <receipt> [--key pub.pem] [--kid <kid>] [--fetch <url>]
 *   node verify.js --chain receipts.txt [--key pub.pem] [--kid <kid>] [--fetch <url>]
 *
 * Key discovery: with no --key, the public key is fetched from
 *   https://app.coderifts.com/api/v1/attestation/public-key  (override with --fetch <url>).
 *
 * Output: JSON { valid, reason?, payload?, chain? } to stdout.
 * Exit codes: 0 valid, 1 invalid, 2 usage error.
 *
 * Verification order (matches the reference taxonomy exactly):
 *   structure -> json -> kid -> signature
 * Reasons: malformed_structure | bad_json | unknown_kid | signature_error | signature_mismatch
 */

const crypto = require('node:crypto');
const fs = require('node:fs');

const DEFAULT_FETCH_URL = 'https://app.coderifts.com/api/v1/attestation/public-key';
const SIGNING_PREFIX = 'crchain.v1';

function sha256hex(str) {
  return crypto.createHash('sha256').update(String(str), 'utf8').digest('hex');
}

/**
 * Reconstruct the exact signed bytes from a parsed receipt body.
 * v2 (body.v === 2) appends '|' + reg; v1 (v absent or 1) uses the base string.
 * This string must be byte-identical to the Python implementation.
 */
function reconstructSignedInput(payload) {
  const base = `${SIGNING_PREFIX}|${payload.kid}|${payload.fp}|${payload.prev}|${payload.caller}|${payload.ts}`;
  return payload.v === 2 ? `${base}|${payload.reg}` : base;
}

/**
 * Verify a single receipt token against a public key + expected kid.
 * @param {string} token
 * @param {{ publicKey: import('crypto').KeyObject, expectedKid: (string|null) }} ctx
 * @returns {{ valid: boolean, reason?: string, payload?: object }}
 */
function verifyReceipt(token, ctx) {
  // 1. structure
  if (typeof token !== 'string' || token.length === 0) {
    return { valid: false, reason: 'malformed_structure' };
  }
  const segments = token.split('.');
  if (segments.length !== 2 || segments.some((s) => !s)) {
    return { valid: false, reason: 'malformed_structure' };
  }

  // 2. json
  let payload;
  try {
    payload = JSON.parse(Buffer.from(segments[0], 'base64url').toString('utf8'));
  } catch (_) {
    return { valid: false, reason: 'bad_json' };
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return { valid: false, reason: 'bad_json' };
  }

  // 3. kid -- enforced only when an expected kid is known (from --kid or discovery).
  if (ctx.expectedKid !== null && payload.kid !== ctx.expectedKid) {
    return { valid: false, reason: 'unknown_kid', payload };
  }

  // 4. signature (raw Ed25519 over the reconstructed UTF-8 bytes)
  const sig = Buffer.from(segments[1], 'base64url');
  let ok = false;
  try {
    ok = crypto.verify(null, Buffer.from(reconstructSignedInput(payload), 'utf8'), ctx.publicKey, sig);
  } catch (_) {
    return { valid: false, reason: 'signature_error', payload };
  }
  if (!ok) return { valid: false, reason: 'signature_mismatch', payload };

  return { valid: true, payload };
}

/**
 * Verify a chain of tokens (oldest first): every signature valid AND every non-genesis
 * link's prev == 'sha256:' + sha256hex(previous token string).
 */
function verifyChain(tokens, ctx) {
  const links = [];
  let allValid = true;
  let first = null;

  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    const res = verifyReceipt(token, ctx);
    const link = { index: i, signature_valid: res.valid };
    if (!res.valid) link.reason = res.reason;
    const prev = res.payload ? res.payload.prev : undefined;
    if (res.payload) link.prev = prev;

    if (i === 0) {
      first = prev === 'null' ? 'genesis' : 'continuation';
      link.role = first;
      // A genesis needs prev === 'null'; a continuation links to a token we do not hold.
      link.prev_ok = prev === 'null' ? true : null;
    } else {
      const expected = `sha256:${sha256hex(tokens[i - 1])}`;
      link.expected_prev = expected;
      link.prev_ok = prev === expected;
      if (!link.prev_ok) allValid = false;
    }

    if (!res.valid) allValid = false;
    links.push(link);
  }

  return { valid: allValid, chain: { length: tokens.length, first, links } };
}

// ---------------------------------------------------------------------------
// Key loading
// ---------------------------------------------------------------------------

function keyFromPem(pem) {
  return crypto.createPublicKey(pem);
}

async function fetchKeyInfo(url) {
  const res = await fetch(url, { headers: { Accept: 'application/json' } });
  if (!res.ok) throw new Error(`fetch ${url} -> HTTP ${res.status}`);
  const info = await res.json();
  if (!info || !info.public_key_pem) throw new Error(`no public_key_pem at ${url}`);
  return { publicKey: keyFromPem(info.public_key_pem), kid: info.kid || null };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const opts = { receipt: null, chainFile: null, keyFile: null, kid: null, fetchUrl: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--chain') opts.chainFile = argv[++i];
    else if (a === '--key') opts.keyFile = argv[++i];
    else if (a === '--kid') opts.kid = argv[++i];
    else if (a === '--fetch') opts.fetchUrl = argv[++i];
    else if (a === '-h' || a === '--help') opts.help = true;
    else if (a.startsWith('--')) throw new Error(`unknown flag: ${a}`);
    else if (opts.receipt === null) opts.receipt = a;
    else throw new Error(`unexpected argument: ${a}`);
  }
  return opts;
}

const USAGE =
  'usage: node verify.js <receipt> [--key pub.pem] [--kid <kid>] [--fetch <url>]\n' +
  '       node verify.js --chain receipts.txt [--key pub.pem] [--kid <kid>] [--fetch <url>]\n';

function fail(msg) {
  process.stderr.write(`${msg}\n${USAGE}`);
  process.exit(2);
}

async function main() {
  let opts;
  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (e) {
    return fail(e.message);
  }
  if (opts.help) {
    process.stdout.write(USAGE);
    process.exit(2);
  }
  if (!opts.chainFile && !opts.receipt) return fail('no receipt provided');

  // Resolve the verification key + expected kid.
  let ctx;
  try {
    if (opts.keyFile) {
      const pem = fs.readFileSync(opts.keyFile, 'utf8');
      ctx = { publicKey: keyFromPem(pem), expectedKid: opts.kid };
    } else {
      const info = await fetchKeyInfo(opts.fetchUrl || DEFAULT_FETCH_URL);
      // An explicit --kid overrides the discovered kid.
      ctx = { publicKey: info.publicKey, expectedKid: opts.kid || info.kid };
    }
  } catch (e) {
    return fail(`could not load public key: ${e.message}`);
  }

  let result;
  if (opts.chainFile) {
    const raw = fs.readFileSync(opts.chainFile, 'utf8');
    const tokens = raw.split('\n').map((l) => l.trim()).filter((l) => l.length > 0);
    if (tokens.length === 0) return fail('chain file is empty');
    result = verifyChain(tokens, ctx);
  } else {
    result = verifyReceipt(opts.receipt, ctx);
  }

  process.stdout.write(JSON.stringify(result) + '\n');
  process.exit(result.valid ? 0 : 1);
}

main().catch((e) => fail(e.message));
