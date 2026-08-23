'use strict';

/*
 * Smoke: require('../verify-attest') imports the pure verify logic WITHOUT running the CLI.
 */

const assert = require('node:assert');
const a = require('../verify-attest.js');

const EXPECTED = [
  'verifyExecutionAttestation', 'parseAttestToken', 'signingInput', 'resolveExecutorKey',
  'isIssueTimeWithinKeyWindow',
];
for (const k of EXPECTED) {
  assert.strictEqual(typeof a[k], 'function', `missing exported function: ${k}`);
}
assert.strictEqual(a.ATTEST_VERSION, 'cr.exec.attest.v1');
assert.strictEqual(a.SIGNING_PREFIX, 'crexecattest.v1');
assert.strictEqual(a.ENVELOPE_TAG, 'cr.exec.attest.v1');
assert.strictEqual(a.CLOCK_SKEW_LEEWAY_MS, 30_000);

const r = a.verifyExecutionAttestation('', { registry: { keys: [] } });
assert.strictEqual(r.valid, false);
assert.strictEqual(r.status, 'ATTEST_MALFORMED');

console.log('require-attest-smoke: OK');
