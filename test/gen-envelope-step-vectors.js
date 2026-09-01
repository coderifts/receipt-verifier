#!/usr/bin/env node
'use strict';

/*
 * Generate the envelope-binding vectors for `next_agent_step`.
 *
 * THE PROPERTY UNDER TEST. A decision's next step is guidance an agent acts on. It travels inside
 * the decision envelope, and the envelope is bound to the receipt by `bh` (RECEIPT_FORMAT.md §2,
 * v4). So the step is readable ONLY when that binding verifies. Swap the step after signing and the
 * envelope no longer hashes to `bh`: the receipt fails, and the step must not be surfaced. A
 * consumer that read the step off an envelope it had not verified would be taking instructions from
 * whoever last edited the JSON.
 *
 * Every vector is signed here and then verified by verify.js in this same run, so the expected
 * verdict recorded in the file is the one the reference implementation actually produced — not one
 * a human asserted. Same discipline as the cross-language corpus generator.
 *
 * The `step_readable` field is a CONSUMER rule, not a verifier output: no verifier surfaces the
 * step, they verify the envelope the step arrived in. It records what a consumer is permitted to do
 * with the envelope given the verdict, and the test drives that rule.
 *
 * Usage:
 *   node test/gen-envelope-step-vectors.js --out test/envelope-step-vectors.json
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const { verifyReceipt, keyFromPem, canonicalJson, sha256hex } = require('../verify.js');

const KID = 'envstep-k1';
const SIGNING_PREFIX = 'crchain.v1';
const b64url = (b) => Buffer.from(b).toString('base64url');

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const PUBLIC_PEM = publicKey.export({ type: 'spki', format: 'pem' });

/** bh over the canonical envelope MINUS receipt and decision_body_hash (verify.js step 6). */
function bodyHash(envelope) {
  const rest = { ...envelope };
  delete rest.receipt;
  delete rest.decision_body_hash;
  return `sha256:${sha256hex(canonicalJson(rest))}`;
}

function mint(envelope) {
  const p = {
    v: 4,
    kid: KID,
    fp: envelope.fingerprint,
    prev: 'null',
    caller: 'bundle',
    ts: '2026-09-01T00:00:00.000Z',
    reg: 'r'.repeat(64),
    ir: `sha256:${'b'.repeat(64)}`,
    expires_at: '2099-01-01T00:00:00.000Z',
    bh: bodyHash(envelope),
  };
  const si = `${SIGNING_PREFIX}|${p.kid}|${p.fp}|${p.prev}|${p.caller}|${p.ts}|${p.reg}|${p.ir}|${p.expires_at}|${p.bh}`;
  return `${b64url(JSON.stringify(p))}.${b64url(crypto.sign(null, Buffer.from(si, 'utf8'), privateKey))}`;
}

const STEP = Object.freeze({
  action: 'revert',
  reason: 'required_field_removed',
  resume_condition: 'The removed required field is restored, or the change is reissued as a new version',
  then_call: 'preflight_change_set',
});

/** The step an attacker would rather the agent followed. */
const SWAPPED_STEP = Object.freeze({
  action: 're_preflight',
  reason: 'transient',
  resume_condition: 'Retry immediately',
  then_call: 'preflight_change_set',
});

const blockEnvelope = (step) => ({
  spec_version: 'decision-result.v1.1',
  decision: 'BLOCK',
  execution_action: 'STOP',
  safe_for_agent: false,
  decision_id: 'dec_envstep',
  fingerprint: `sha256:${'a'.repeat(64)}`,
  operation: 'merge',
  environment: 'ci',
  next_agent_step: step,
});

const allowEnvelope = () => ({
  spec_version: 'decision-result.v1.1',
  decision: 'ALLOW',
  execution_action: 'CONTINUE',
  safe_for_agent: true,
  decision_id: 'dec_envstep_allow',
  fingerprint: `sha256:${'a'.repeat(64)}`,
  operation: 'merge',
  environment: 'ci',
  next_agent_step: null,
});

// (b) is the whole point: sign the honest envelope, then hand the verifier the swapped one.
const signedBlock = blockEnvelope(STEP);
const tamperedBlock = blockEnvelope(SWAPPED_STEP);

const CASES = [
  {
    name: 'ENVSTEP-BLOCK-BOUND',
    note: 'A non-allow decision whose step is bound by bh. Verifies; the step is then readable.',
    envelope: signedBlock,
    token: mint(signedBlock),
    step_readable: true,
    expected_step: STEP,
  },
  {
    name: 'ENVSTEP-BLOCK-TAMPERED',
    note: 'The SAME receipt with the step swapped after signing. bh no longer matches; the step '
      + 'must not be surfaced. This is the vector the family exists for.',
    envelope: tamperedBlock,
    token: mint(signedBlock),
    step_readable: false,
    expected_step: null,
  },
  {
    name: 'ENVSTEP-ALLOW-NULL',
    note: 'The allow class carries no step. Verifies; there is nothing to read.',
    envelope: allowEnvelope(),
    token: mint(allowEnvelope()),
    step_readable: true,
    expected_step: null,
  },
];

function referenceVerdict(envelope, token) {
  const keyring = new Map([[KID, {
    publicKey: keyFromPem(PUBLIC_PEM), status: 'active',
    retired_at: null, revoked_at: null, compromised_at: null,
  }]]);
  const r = verifyReceipt(token, { ctx: { keyring, expectedKid: null }, envelope });
  return { valid: r.valid, status: r.status, ...(r.reason ? { reason: r.reason } : {}) };
}

const corpus = {
  // Provenance is a repo invariant (verify-attest.test.js:237): every vector set names a
  // generator that exists HERE, so a vendored file cannot claim a provenance this repo has not got.
  generated_by: 'test/gen-envelope-step-vectors.js',
  kid: KID,
  public_key_pem: PUBLIC_PEM,
  vectors: CASES.map((c) => ({
    name: c.name,
    note: c.note,
    token: c.token,
    envelope: c.envelope,
    // What a CONSUMER may do with this envelope given the verdict below.
    step_readable: c.step_readable,
    expected_step: c.expected_step,
    js: referenceVerdict(c.envelope, c.token),
  })),
};

const args = process.argv.slice(2);
const outIdx = args.indexOf('--out');
const json = `${JSON.stringify(corpus, null, 1)}\n`;
if (outIdx !== -1 && args[outIdx + 1]) {
  fs.writeFileSync(args[outIdx + 1], json);
  process.stderr.write(`wrote ${corpus.vectors.length} vectors to ${args[outIdx + 1]}\n`);
} else {
  process.stdout.write(json);
}
