#!/usr/bin/env node
'use strict';

/*
 * CodeRifts chain-receipt verifier -- Node >= 20, zero dependencies (node:crypto only).
 *
 * Verifies an Ed25519-signed CodeRifts chain_receipt WITHOUT trusting the CodeRifts
 * service. The reference format is frozen in ./RECEIPT_FORMAT.md.
 *
 * Usage:
 *   node verify.js <receipt> [--key pub.pem | --keys <url|file>] [--kid <kid>] [--fetch <url>]
 *   node verify.js --chain receipts.txt [--key pub.pem | --keys <url|file>] [--kid <kid>] [--fetch <url>]
 *
 * Key discovery: with no --key/--keys, the public key is fetched from
 *   https://app.coderifts.com/api/v1/attestation/public-key  (override with --fetch <url>).
 * --keys resolves each receipt's key by kid from a registry
 *   ({ keys: [{ kid, public_key_pem, status, valid_from }] }); accepts a URL or file.
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
 *   v1 (v absent or 1): the base string.
 *   v2 (v === 2):       base + '|' + reg.
 *   v3 (v === 3):       base + '|' + reg + '|' + ir.
 * Field order matches the CodeRifts issuer exactly (chain-attestation.js signingInputV3).
 * This string must be byte-identical to the Python implementation.
 */
function reconstructSignedInput(payload) {
  const base = `${SIGNING_PREFIX}|${payload.kid}|${payload.fp}|${payload.prev}|${payload.caller}|${payload.ts}`;
  if (payload.v === 3) return `${base}|${payload.reg}|${payload.ir}`;
  if (payload.v === 2) return `${base}|${payload.reg}`;
  return base;
}

/**
 * Resolve the verification key for a parsed payload.
 * Two modes:
 *   - keyring (from --keys): pick the entry whose kid matches payload.kid; an
 *     unlisted kid resolves to null (=> unknown_kid). A retired key still verifies
 *     so receipts issued before a rotation stay checkable.
 *   - single key (default): the one loaded key, gated by expectedKid when known.
 * Returns a KeyObject, or null when the kid is not accepted.
 */
function resolveKey(ctx, payload) {
  if (ctx.keyring) {
    const entry = ctx.keyring.get(payload.kid);
    if (!entry) return null;
    if (ctx.expectedKid !== null && payload.kid !== ctx.expectedKid) return null;
    return entry.publicKey;
  }
  if (ctx.expectedKid !== null && payload.kid !== ctx.expectedKid) return null;
  return ctx.publicKey;
}

/**
 * Verify a single receipt token against a public key (or keyring) + expected kid.
 * @param {string} token
 * @param {{ publicKey?: import('crypto').KeyObject, keyring?: Map<string,{publicKey:import('crypto').KeyObject}>, expectedKid: (string|null) }} ctx
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

  // 3. kid -- resolve the key by kid (keyring) or gate the single key by expectedKid.
  const publicKey = resolveKey(ctx, payload);
  if (!publicKey) {
    return { valid: false, reason: 'unknown_kid', payload };
  }

  // 4. signature (raw Ed25519 over the reconstructed UTF-8 bytes)
  const sig = Buffer.from(segments[1], 'base64url');
  let ok = false;
  try {
    ok = crypto.verify(null, Buffer.from(reconstructSignedInput(payload), 'utf8'), publicKey, sig);
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

/**
 * Build a kid -> key map from a CodeRifts key registry
 * ({ keys: [{ kid, public_key_pem, status, valid_from }] }). A --keys source may be
 * an http(s) URL or a local file path. Both active and retired keys are loaded.
 */
async function loadKeyring(source) {
  let text;
  if (/^https?:\/\//i.test(source)) {
    const res = await fetch(source, { headers: { Accept: 'application/json' } });
    if (!res.ok) throw new Error(`fetch ${source} -> HTTP ${res.status}`);
    text = await res.text();
  } else {
    text = fs.readFileSync(source, 'utf8');
  }
  const doc = JSON.parse(text);
  const keys = doc && Array.isArray(doc.keys) ? doc.keys : null;
  if (!keys || keys.length === 0) throw new Error(`no keys[] in registry ${source}`);
  const keyring = new Map();
  for (const k of keys) {
    if (!k || !k.kid || !k.public_key_pem) throw new Error(`registry entry missing kid/public_key_pem in ${source}`);
    keyring.set(k.kid, { publicKey: keyFromPem(k.public_key_pem), status: k.status || null });
  }
  return keyring;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const opts = { receipt: null, chainFile: null, keyFile: null, keysSource: null, kid: null, fetchUrl: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--chain') opts.chainFile = argv[++i];
    else if (a === '--key') opts.keyFile = argv[++i];
    else if (a === '--keys') opts.keysSource = argv[++i];
    else if (a === '--kid') opts.kid = argv[++i];
    else if (a === '--fetch') opts.fetchUrl = argv[++i];
    else if (a === '-h' || a === '--help') opts.help = true;
    else if (a.startsWith('--')) throw new Error(`unknown flag: ${a}`);
    else if (opts.receipt === null) opts.receipt = a;
    else throw new Error(`unexpected argument: ${a}`);
  }
  if (opts.keyFile && opts.keysSource) throw new Error('--key and --keys are mutually exclusive');
  return opts;
}

const USAGE =
  'usage: node verify.js <receipt> [--key pub.pem | --keys <url|file>] [--kid <kid>] [--fetch <url>]\n' +
  '       node verify.js --chain receipts.txt [--key pub.pem | --keys <url|file>] [--kid <kid>] [--fetch <url>]\n';

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

  // Resolve the verification key(s) + expected kid.
  let ctx;
  try {
    if (opts.keysSource) {
      // Registry mode: resolve each receipt's key by its kid. --kid stays an
      // optional additional guard (null => accept any kid present in the registry).
      const keyring = await loadKeyring(opts.keysSource);
      ctx = { keyring, expectedKid: opts.kid };
    } else if (opts.keyFile) {
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
