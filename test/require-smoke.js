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
];
for (const k of EXPECTED) {
  assert.strictEqual(typeof v[k], 'function', `missing exported function: ${k}`);
}
assert.strictEqual(v.MAX_SUPPORTED_V, 4, 'MAX_SUPPORTED_V export');
assert.strictEqual(v.SIGNING_PREFIX, 'crchain.v1', 'SIGNING_PREFIX export');

// Pure call (no key, no CLI): a malformed token is MALFORMED.
const r = v.verifyReceipt('', { publicKey: null, expectedKid: null });
assert.strictEqual(r.valid, false);
assert.strictEqual(r.status, 'MALFORMED');

// canonicalJson is the same rule the app + verify.py use.
assert.strictEqual(v.canonicalJson({ b: 1, a: 2 }), '{"a":2,"b":1}');

console.log('require-smoke: OK (module imported without running the CLI; exports present)');
