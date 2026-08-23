'use strict';

/*
 * Smoke: require('../verify-grant') imports the pure verify logic WITHOUT running the CLI.
 */

const assert = require('node:assert');
const g = require('../verify-grant.js');

const EXPECTED = [
  'verifyExecutionGrant', 'reconstructSignedInput', 'computeScopeHash',
  'receiptDigest', 'resolveEntry', 'isIssuedInFuture',
];
for (const k of EXPECTED) {
  assert.strictEqual(typeof g[k], 'function', `missing exported function: ${k}`);
}
assert.strictEqual(g.GRANT_VERSION, 'cr.exec.v1');
assert.strictEqual(g.SIGNING_PREFIX, 'crexec.v1');
assert.strictEqual(g.CLOCK_SKEW_LEEWAY_MS, 30_000);

const r = g.verifyExecutionGrant('', { publicKey: null, expectedKid: null });
assert.strictEqual(r.valid, false);
assert.strictEqual(r.status, 'MALFORMED');

const h = g.computeScopeHash({ operation: 'merge', target_id: 't', after_payload: '{"ok":true}' });
assert.match(h, /^sha256:[a-f0-9]{64}$/);
assert.strictEqual(
  h,
  'sha256:bda9dac1974036a2e2de4e882a9207bed2dc6f0f4d360db5a60f877771172cbe',
);

console.log('require-grant-smoke: OK');
