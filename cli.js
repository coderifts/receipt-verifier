#!/usr/bin/env node
'use strict';

/*
 * CodeRifts chain-receipt verifier — THE COMMAND.
 *
 * `./verify.js` is the pure library; everything that makes this a program — the shebang, argument
 * parsing, the network key fetch, stdout/exit codes — lives here. Four repositories vendor
 * `verify.js` as their `src/verify.js` and none of them can run a CLI; carrying one inside the
 * library meant every one of them shipped a command they could not invoke, and a network path
 * their offline verifiers must never take.
 *
 * Usage:
 *   node cli.js <receipt> [--key pub.pem | --keys <url|file>] [--kid <kid>] [--fetch <url>] [--refresh-keys]
 *   node cli.js --chain receipts.txt [--key pub.pem | --keys <url|file>] [--kid <kid>] [--fetch <url>] [--refresh-keys]
 *
 * ── 1355-default: VENDORED KEYS ARE THE DEFAULT; THE NETWORK IS OPT-IN ──────────────────────
 *
 * With no --key/--keys/--fetch/--refresh-keys, keys are loaded from the pinned snapshot at
 * keys/coderifts-keys.json (offline). A CA pins roots locally; this command does the same.
 * Live discovery is opt-in: --refresh-keys (well-known URL) or --keys <url> / --fetch <url>.
 *
 * ── 1282-A': THE LEGACY SINGLE-KEY BODY CANNOT SUPPORT A CURRENT VERDICT ────────────────────
 *
 * --fetch / --refresh-keys may answer with either shape:
 *
 *   registry  { keys: [{ kid, public_key_pem, status, valid_from, retired_at, revoked_at }] }
 *   legacy    { kid, public_key_pem }                       (/api/v1/attestation/public-key)
 *
 * The legacy body carries NO status field. The library reads a status-less entry as `status: null`
 * and `null` is a KNOWN status, so the healthy path is taken and the answer is VERIFIED_CURRENT.
 * That answer is not wrong about the signature — it is wrong about what it could see: a key the
 * operator has since REVOKED produces exactly the same output, because the document that would
 * have said so was never asked for.
 *
 * So on the legacy path this command:
 *   - prints a KEY_STATUS_UNAVAILABLE warning to stderr, naming the document it read; and
 *   - refuses to report a CURRENT verdict, re-classing it as UNKNOWN_KEY_STATUS — the existing
 *     fail-closed-on-a-status-we-cannot-read status, not a new word.
 *
 * WHAT IS NOT CHANGED: the signature verdict itself. A MALFORMED / INVALID_SIGNATURE /
 * UNKNOWN_KEY answer is already non-current and is passed through untouched — downgrading a
 * refusal to a different refusal would lose the reason. Registry bodies, --key and --keys are
 * unaffected: they can see key status, so they keep their verdicts.
 */

const fs = require('fs');
const path = require('path');
const {
  verifyReceipt,
  verifyChain,
  loadKeyring,
  keyFromPem,
  keyringFromDocument,
  pickActiveFromKeyring,
  DEFAULT_FETCH_URL,
} = require('./verify');

/** Pinned well-known snapshot shipped with the package. Default verify is offline against this file. */
const VENDORED_KEYS_PATH = path.join(__dirname, 'keys', 'coderifts-keys.json');

/**
 * Fetch a key document. Accepts BOTH shapes:
 *   - registry: { keys: [{ kid, public_key_pem, status, retired_at, ...}] }
 *   - legacy single-key: { kid, public_key_pem }  (/api/v1/attestation/public-key)
 * Registry returns { publicKey, kid, keyring } (keyring carries retired keys).
 * Legacy returns { publicKey, kid } — same as before, so --keys users + grant
 * verifiers that read publicKey/kid stay byte-compatible.
 */
async function fetchKeyInfo(url) {
  const res = await fetch(url, { headers: { Accept: 'application/json' } });
  if (!res.ok) throw new Error(`fetch ${url} -> HTTP ${res.status}`);
  const info = await res.json();
  const keyring = keyringFromDocument(info, url);
  if (keyring) {
    const picked = pickActiveFromKeyring(keyring);
    if (!picked) throw new Error(`no usable keys at ${url}`);
    return { publicKey: picked.entry.publicKey, kid: picked.kid, keyring };
  }
  if (!info || !info.public_key_pem) throw new Error(`no public_key_pem at ${url}`);
  // `legacy: true` is the whole 1282-A' signal: this document cannot say whether the key is
  // still trusted, and the caller must not report a current verdict from it.
  return { publicKey: keyFromPem(info.public_key_pem), kid: info.kid || null, legacy: true, source: url };
}

/**
 * 1282-A' — a verdict from a document that cannot report key status is not CURRENT.
 *
 * Applied ONLY on the legacy single-key path, and only to a verdict that would otherwise be
 * current. Every other status is already a refusal carrying its own reason, and rewriting a
 * refusal into a different refusal would throw that reason away.
 */
function downgradeLegacyVerdict(result, source) {
  if (!result || result.valid !== true) return result;
  return {
    ...result,
    valid: false,
    status: 'UNKNOWN_KEY_STATUS',
    reason: 'key_status_unavailable',
    key_status_unavailable: {
      source,
      why: 'the key document is the legacy single-key body and carries no status field, so a '
        + 'revoked or retired key is indistinguishable from an active one',
      remedy: 'point --keys (or --fetch) at a key registry that publishes keys[].status',
    },
  };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const opts = { receipt: null, chainFile: null, keyFile: null, keysSource: null, kid: null, fetchUrl: null, refreshKeys: false, envelopeFile: null, audience: null, environment: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--chain') opts.chainFile = argv[++i];
    else if (a === '--key') opts.keyFile = argv[++i];
    else if (a === '--keys') opts.keysSource = argv[++i];
    else if (a === '--kid') opts.kid = argv[++i];
    else if (a === '--fetch') opts.fetchUrl = argv[++i];
    else if (a === '--refresh-keys') opts.refreshKeys = true;
    else if (a === '--envelope') opts.envelopeFile = argv[++i];
    else if (a === '--audience') opts.audience = argv[++i];
    else if (a === '--environment') opts.environment = argv[++i];
    else if (a === '-h' || a === '--help') opts.help = true;
    else if (a.startsWith('--')) throw new Error(`unknown flag: ${a}`);
    else if (opts.receipt === null) opts.receipt = a;
    else throw new Error(`unexpected argument: ${a}`);
  }
  if (opts.keyFile && opts.keysSource) throw new Error('--key and --keys are mutually exclusive');
  if (opts.refreshKeys && (opts.keyFile || opts.keysSource)) {
    throw new Error('--refresh-keys is mutually exclusive with --key and --keys');
  }
  return opts;
}

const USAGE =
  'usage: node cli.js <receipt> [--key pub.pem | --keys <url|file>] [--kid <kid>] [--fetch <url>] [--refresh-keys]\n' +
  '       node cli.js --chain receipts.txt [--key pub.pem | --keys <url|file>] [--kid <kid>] [--fetch <url>] [--refresh-keys]\n';

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
  // Empty string from `$(curl -s … | grep …)` on GitHub 403/rate-limit is a common silent path
  // when the homepage one-liner is used without HTTP status checks — fail honestly.
  if (!opts.chainFile && (!opts.receipt || !String(opts.receipt).trim())) {
    return fail(
      'no receipt provided — if you fetched via unauthenticated GitHub comments, a 403 rate limit '
      + 'yields an empty capture; try again in a minute, or paste the receipt token directly',
    );
  }

  // Resolve the verification key(s) + expected kid.
  let ctx;
  // Non-null once the fetch resolved the LEGACY single-key body (1282-A').
  let legacyKeySource = null;
  try {
    if (opts.keysSource) {
      // Registry mode: resolve each receipt's key by its kid. --kid stays an
      // optional additional guard (null => accept any kid present in the registry).
      // A URL here is the opt-in network path; a file is offline.
      const keyring = await loadKeyring(opts.keysSource);
      ctx = { keyring, expectedKid: opts.kid };
    } else if (opts.keyFile) {
      const pem = fs.readFileSync(opts.keyFile, 'utf8');
      ctx = { publicKey: keyFromPem(pem), expectedKid: opts.kid };
    } else if (opts.refreshKeys || opts.fetchUrl) {
      // Opt-in live discovery. --refresh-keys hits the well-known URL; --fetch overrides it.
      const info = await fetchKeyInfo(opts.fetchUrl || DEFAULT_FETCH_URL);
      if (info.keyring) {
        // Registry shape: resolve each receipt by kid (retired window included).
        ctx = { keyring: info.keyring, expectedKid: opts.kid };
      } else {
        // Legacy single-key body. An explicit --kid overrides the discovered kid.
        ctx = { publicKey: info.publicKey, expectedKid: opts.kid || info.kid };
        legacyKeySource = info.source || opts.fetchUrl || DEFAULT_FETCH_URL;
      }
    } else {
      // Default: vendored snapshot, no network. A CA pins roots locally.
      const keyring = await loadKeyring(VENDORED_KEYS_PATH);
      ctx = { keyring, expectedKid: opts.kid };
    }
  } catch (e) {
    return fail(`could not load public key: ${e.message}`);
  }

  // Optional envelope + dormant-check inputs for the taxonomy.
  let envelope = null;
  if (opts.envelopeFile) {
    try {
      envelope = JSON.parse(fs.readFileSync(opts.envelopeFile, 'utf8'));
    } catch (e) {
      return fail(`could not read --envelope: ${e.message}`);
    }
  }
  const verifyOpts = { envelope, expectedAudience: opts.audience, expectedEnvironment: opts.environment };

  let result;
  if (opts.chainFile) {
    const raw = fs.readFileSync(opts.chainFile, 'utf8');
    const tokens = raw.split('\n').map((l) => l.trim()).filter((l) => l.length > 0);
    if (tokens.length === 0) return fail('chain file is empty');
    // The PUBLIC library entry points — the *Inner variants are private to verify.js and are
    // not part of what the four vendoring repos consume.
    result = verifyChain(tokens, ctx, verifyOpts);
  } else {
    result = verifyReceipt(opts.receipt, ctx, verifyOpts);
  }

  if (legacyKeySource) {
    // Non-silent: the operator learns WHY the verdict cannot be current, on stderr, so stdout
    // stays a clean JSON document for a pipe.
    process.stderr.write(
      `warning: KEY_STATUS_UNAVAILABLE — ${legacyKeySource} returned the legacy single-key body, `
      + 'which carries no keys[].status. A revoked key is indistinguishable from an active one '
      + 'here, so no CURRENT verdict is reported. Use a key registry (--keys <url|file>) for a '
      + 'verdict that can see key status.\n',
    );
    result = downgradeLegacyVerdict(result, legacyKeySource);
  }

  process.stdout.write(JSON.stringify(result) + '\n');
  process.exit(result.valid ? 0 : 1);
}

// CLI entry — this file IS the command; verify.js never runs one.
if (require.main === module) {
  main().catch((e) => fail(e.message));
}

module.exports = { fetchKeyInfo, downgradeLegacyVerdict, parseArgs, main, USAGE, VENDORED_KEYS_PATH };
