'use strict';

/*
 * Smoke test: require('../verify') imports the pure verify logic WITHOUT running the CLI.
 *
 * If requiring the module executed main(), the process would parse process.argv, find no receipt,
 * and process.exit(2) BEFORE reaching the assertions below — so reaching the final "OK" line is
 * itself the proof that the `if (require.main === module)` guard works.
 */

const assert = require('node:assert');
const v = require('../verify.js');

const EXPECTED = [
  'verifyReceipt', 'verifyChain', 'deriveStatus', 'resolveEntry', 'reconstructSignedInput',
  'canonicalJson', 'loadKeyring', 'keyFromPem', 'fetchKeyInfo', 'sha256hex',
  'expiryLeewayMs', 'isExpiredAt',
];
for (const k of EXPECTED) {
  assert.strictEqual(typeof v[k], 'function', `missing exported function: ${k}`);
}
assert.strictEqual(v.MAX_SUPPORTED_V, 4, 'MAX_SUPPORTED_V export');
assert.strictEqual(v.SIGNING_PREFIX, 'crchain.v1', 'SIGNING_PREFIX export');
assert.strictEqual(v.CLOCK_SKEW_LEEWAY_MS, 30_000, 'CLOCK_SKEW_LEEWAY_MS export');

// Pure call (no key, no CLI): a malformed token is MALFORMED.
const r = v.verifyReceipt('', { publicKey: null, expectedKid: null });
assert.strictEqual(r.valid, false);
assert.strictEqual(r.status, 'MALFORMED');

// canonicalJson is the same rule the app + verify.py use.
assert.strictEqual(v.canonicalJson({ b: 1, a: 2 }), '{"a":2,"b":1}');

// ID104 clock-skew leeway (deriveStatus, no key needed).
{
  const now = Date.parse('2026-08-23T12:00:00.000Z');
  const entry = { status: null, retired_at: null };
  const isoAgo = (ms) => new Date(now - ms).toISOString();
  const current = v.deriveStatus({ v: 4, expires_at: isoAgo(10_000) }, entry, { now });
  assert.strictEqual(current, 'VERIFIED_CURRENT', 'exp 10s past + 30s leeway → CURRENT');
  const expired = v.deriveStatus({ v: 4, expires_at: isoAgo(40_000) }, entry, { now });
  assert.strictEqual(expired, 'VERIFIED_EXPIRED', 'exp 40s past → EXPIRED');
  const prod = v.deriveStatus(
    { v: 4, expires_at: isoAgo(1_000) },
    entry,
    { now, envelope: { environment: 'production', operation: 'deploy' } },
  );
  assert.strictEqual(prod, 'VERIFIED_CURRENT', 'production+deploy 1s past not guessed destructive');
  const staging = v.deriveStatus(
    { v: 4, expires_at: isoAgo(1_000) },
    entry,
    { now, envelope: { environment: 'staging', operation: 'merge' } },
  );
  assert.strictEqual(staging, 'VERIFIED_CURRENT', 'non-destructive 1s past → CURRENT');
  assert.strictEqual(v.isExpiredAt(now - 10_000, now), false);
  assert.strictEqual(v.isExpiredAt(now - 40_000, now), true);
}

console.log('require-smoke: OK (module imported without running the CLI; exports present)');
