#!/usr/bin/env node
'use strict';

/*
 * Generate test/atomic-attest-vectors.json with an EPHEMERAL Ed25519 key (never a prod key).
 *
 * The seals are minted by the PRODUCER ITSELF — capability-demo demo/src/atomic.js, required
 * read-only from the sibling checkout. Reimplementing the encoder here would test this repository
 * against its own idea of the format, which is exactly how two implementations drift while both
 * their suites stay green.
 *
 * Every vector is verified by verify-atomic-attestation.js in this same run, so the recorded
 * expectation is what the verifier actually produced.
 *
 * Usage: node test/gen-atomic-attest-vectors.js --out test/atomic-attest-vectors.json
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { verifyAtomicExecutionAttestation } = require('../verify-atomic-attestation.js');

const DEMO = path.join(os.homedir(), 'capability-demo', 'demo', 'src', 'atomic.js');
if (!fs.existsSync(DEMO)) {
  console.error(`gen-atomic-attest-vectors: producer not found at ${DEMO} — `
    + 'this generator mints with the real producer and will not substitute its own encoder');
  process.exit(1);
}
// eslint-disable-next-line import/no-dynamic-require, global-require
const { encodeAtomicExecutionAttestation, signPreimage } = require(DEMO);

const KID = 'atomic-vec-k1';
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const PUBLIC_PEM = publicKey.export({ type: 'spki', format: 'pem' });

const JTI = 'jti-atomic-1';
const DEPLOYMENT = 'dep-atomic-1';
const DIGEST = `sha256:${'a'.repeat(64)}`;
const TARGET = '/articles/7';

/** cr.gate.preimage.v1|jti|deployment_id|sha256:digest|target_id — gate.sql:146-148. */
const preimage = (o = {}) => [
  'cr.gate.preimage.v1',
  o.jti ?? JTI,
  o.deployment_id ?? DEPLOYMENT,
  o.mutation_digest ?? DIGEST,
  o.target_id ?? TARGET,
].join('|');

const seal = (pre, key = privateKey) => encodeAtomicExecutionAttestation({
  executor_kid: KID, preimage: pre, signature: signPreimage(key, pre),
});

const registry = { keys: [{ kid: KID, public_key_pem: PUBLIC_PEM, status: 'active' }] };
const INTENDED = { jti: JTI, deployment_id: DEPLOYMENT, mutation_digest: DIGEST, target_id: TARGET };
const other = crypto.generateKeyPairSync('ed25519');

const CASES = [
  { name: 'ATOMIC-VALID', note: 'A real seal from the producer, every bound field matching.',
    token: seal(preimage()), intended: INTENDED },

  // One bound field flipped per vector, so each has its OWN refusal rather than a shared one.
  { name: 'ATOMIC-UNBOUND-JTI', note: 'Signed for a different grant.',
    token: seal(preimage({ jti: 'jti-other' })), intended: INTENDED },
  { name: 'ATOMIC-UNBOUND-DEPLOYMENT', note: 'Signed under a different deployment id.',
    token: seal(preimage({ deployment_id: 'dep-other' })), intended: INTENDED },
  { name: 'ATOMIC-UNBOUND-DIGEST', note: 'Signed over a different mutation.',
    token: seal(preimage({ mutation_digest: `sha256:${'b'.repeat(64)}` })), intended: INTENDED },
  { name: 'ATOMIC-UNBOUND-TARGET', note: 'Signed for a different target — the resource-swap case.',
    token: seal(preimage({ target_id: '/articles/9' })), intended: INTENDED },

  { name: 'ATOMIC-BAD-SIGNATURE', note: 'Correct preimage, signature from another key.',
    token: seal(preimage(), other.privateKey), intended: INTENDED },
  { name: 'ATOMIC-UNKNOWN-KID', note: 'A kid the registry does not carry.',
    token: seal(preimage()).replace(`|${KID}|`, '|nobody-knows-me|'), intended: INTENDED },
  { name: 'ATOMIC-MALFORMED', note: 'Three segments where four are required.',
    token: 'cr.atomic.execution.attestation.v1|k|only-three', intended: INTENDED },
  { name: 'ATOMIC-WRONG-ENVELOPE', note: 'A cr.exec.attest.v1-shaped token must not verify here.',
    token: seal(preimage()).replace('cr.atomic.execution.attestation.v1', 'cr.exec.attest.v1'), intended: INTENDED },
];

const corpus = {
  generated_by: 'test/gen-atomic-attest-vectors.js',
  minted_by: 'capability-demo demo/src/atomic.js (encodeAtomicExecutionAttestation + signPreimage)',
  kid: KID,
  public_key_pem: PUBLIC_PEM,
  vectors: CASES.map((c) => {
    const r = verifyAtomicExecutionAttestation(c.token, { registry, intended: c.intended });
    return {
      name: c.name,
      note: c.note,
      token: c.token,
      intended: c.intended,
      expected: { valid: r.valid, status: r.status, ...(r.reason ? { reason: r.reason } : {}) },
    };
  }),
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
