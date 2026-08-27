#!/usr/bin/env node
/**
 * Generate test/monitor-vectors.json with an EPHEMERAL Ed25519 key (never the prod key).
 *
 * THESE ARE THE PUBLIC RUNNERS FOR THE APP'S MON-A-* CASES (1115). The seven ids below are
 * byte-identical to the scenario ids in coderifts-app/test/adapter-acceptance/cases.v1.json,
 * where they exist as `{ scenario }` names with NO runner in either repository — the app's
 * subjects implement only `decide` and `tool_selection` and throw on everything else. Keep the
 * id strings exactly as they are; they are the only link between the two.
 *
 * INDEPENDENT of coderifts-app by decision (1127c): ids and scenarios are kept aligned by
 * intent, bytes are not, and cross-checks compare VERDICTS.
 *
 * NO PRIVATE KEY IS WRITTEN. The keypair lives in memory for this run; only public PEMs are
 * embedded, in the registries the vectors verify against.
 *
 *   node test/gen-monitor-vectors.js
 */
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { ATTEST_VERSION, ENVELOPE_TAG, signingInput } = require('../verify-monitor.js');

const OUT = path.join(__dirname, 'monitor-vectors.json');

const KID = 'mon-test-k1';
const RETIRED_KID = 'mon-test-k0';
const DECISION_ID = 'dec-0001';
const RECEIPT_DIGEST = `sha256:${'ab'.repeat(32)}`;
const OBSERVED = '2026-03-01T00:00:00.000Z';

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function main() {
  const kp = crypto.generateKeyPairSync('ed25519');
  const pem = kp.publicKey.export({ type: 'spki', format: 'pem' });

  const base = {
    v: ATTEST_VERSION,
    kid: KID,
    decision_id: DECISION_ID,
    receipt_digest: RECEIPT_DIGEST,
    delivery_status: 'delivered_acked',
    sink_kind: 'http',
    observed_at: OBSERVED,
  };

  const issue = (over = {}) => {
    const body = { ...base, ...over };
    const sig = crypto.sign(null, Buffer.from(signingInput(body), 'utf8'), kp.privateKey);
    return [ENVELOPE_TAG, body.kid, b64url(Buffer.from(JSON.stringify(body), 'utf8')), b64url(sig)]
      .join('|');
  };

  const valid = issue();
  const notDelivered = issue({ delivery_status: 'not_delivered' });
  const retired = issue({ kid: RETIRED_KID });

  // BAD-SIG: re-encode a changed payload while keeping the ORIGINAL signature.
  const seg = valid.split('|');
  const badPayload = JSON.parse(Buffer.from(seg[2], 'base64url').toString('utf8'));
  badPayload.decision_id = 'dec-tampered';
  const badSig = [seg[0], seg[1], b64url(Buffer.from(JSON.stringify(badPayload), 'utf8')), seg[3]]
    .join('|');

  const registry = {
    keys: [{ kid: KID, public_key_pem: pem, status: 'active' }],
  };
  const retiredRegistry = {
    keys: [{
      kid: RETIRED_KID,
      public_key_pem: pem,
      status: 'retired',
      valid_from: '2026-01-01T00:00:00.000Z',
      retired_at: '2026-06-01T00:00:00.000Z',
    }],
  };

  const doc = {
    spec: ATTEST_VERSION,
    note: 'Ephemeral key, regenerated per run. Never a production key.',
    generated_by: 'test/gen-monitor-vectors.js',
    independence: 'Independent of coderifts-app by decision (1127c); ids and scenarios are kept '
      + 'aligned by intent, bytes are not, cross-checks compare verdicts. The seven MON-A-* ids '
      + 'match coderifts-app/test/adapter-acceptance/cases.v1.json, which carries them as '
      + 'scenario names with no runner.',
    kid: KID,
    registry,
    retired_registry: retiredRegistry,
    empty_registry: { keys: [] },
    decision_id: DECISION_ID,
    receipt_digest: RECEIPT_DIGEST,
    vectors: [
      { name: 'MON-A-VALID', token: valid, keys: 'registry', expected: { valid: true, status: 'MON_ATTEST_VALID' } },
      { name: 'MON-A-BAD-SIG', token: badSig, keys: 'registry', expected: { valid: false, status: 'MON_ATTEST_INVALID_SIGNATURE', reason: 'signature_mismatch' } },
      { name: 'MON-A-UNKNOWN-KID', token: valid, keys: 'empty', expected: { valid: false, status: 'MON_ATTEST_UNKNOWN_KEY', reason: 'unknown_kid' } },
      { name: 'MON-A-RETIRED-KEY-VALID-AT-ISSUE', token: retired, keys: 'retired_registry', expected: { valid: true, status: 'MON_ATTEST_RETIRED_KEY_VALID_AT_ISSUE' } },
      { name: 'MON-A-MALFORMED', token: 'cr.monitor.attest.v1|k|only-three', keys: 'registry', expected: { valid: false, status: 'MON_ATTEST_MALFORMED', reason: 'malformed_structure' } },
      {
        name: 'MON-A-UNBOUND',
        token: valid,
        keys: 'registry',
        flags: { decision_id: 'dec-somewhere-else' },
        expected: { valid: false, status: 'MON_ATTEST_UNBOUND', reason: 'decision_id_mismatch' },
      },
      {
        // VALID ON PURPOSE. A signature over an honest "not delivered" is exactly as valid as one
        // over a delivery: the artifact attests what was observed, and a failed delivery honestly
        // reported is a true statement. Reading this as a failure would be reading the DELIVERY,
        // not the ATTESTATION.
        name: 'MON-A-NOT-DELIVERED',
        token: notDelivered,
        keys: 'registry',
        expected: { valid: true, status: 'MON_ATTEST_VALID' },
      },
      {
        name: 'MON-A-MISMATCH-RECEIPT',
        note: 'INTENTIONALLY NON-MATCHING: verified against a different receipt_digest than this '
          + 'attestation binds. It must never be "fixed" to match — it exists to prove the '
          + 'attestation->receipt binding is actually checked.',
        token: valid,
        keys: 'registry',
        flags: { receipt_digest: `sha256:${'11'.repeat(32)}` },
        expected: { valid: false, status: 'MON_ATTEST_UNBOUND', reason: 'receipt_digest_mismatch' },
      },
    ],
  };

  fs.writeFileSync(OUT, `${JSON.stringify(doc, null, 2)}\n`);
  process.stdout.write(`wrote ${OUT} (${doc.vectors.length} vectors, kid=${KID})\n`);
}

main();
