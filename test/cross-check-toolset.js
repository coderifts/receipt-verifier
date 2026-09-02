#!/usr/bin/env node
'use strict';

/*
 * Cross-check TS-A-* classes: the public verify-toolset.js against the app kernel
 * (coderifts-app/src/verdict-core/toolset-attestation.js).
 *
 * THREE MODES, and the mode is always printed, because the whole point is that a reader can tell
 * which comparison actually ran:
 *
 *   LIVE      the app checkout is present. Public verifier vs the kernel module, right now, and
 *             the recorded fixture is re-derived and must match — a drifted kernel is caught here.
 *   RECORDED  no app checkout (this is CI). Public verifier vs the kernel verdicts recorded in
 *             test/toolset-kernel-verdicts.json, pinned by vectors_sha256 to the exact tokens
 *             they describe.
 *   (refuse)  no checkout AND no fixture, or a fixture that does not describe these vectors.
 *
 * ─── WHY RECORDED EXISTS (1127, the CI-independence half) ────────────────────────────────────
 *
 * 1133 fixed a fabricated pass here: a missing checkout printed "— skip", exited 0, and run.sh
 * rendered `ok cross-check-toolset (js == app kernel …)` for a comparison that never ran.
 *
 * But it left the underlying problem in place and made it visible instead of fixing it. MEASURED
 * 2026-09-02: .github/workflows/verify-live-receipt.yml:23 checks out THIS repository only, so
 * $HOME/coderifts-app never exists in CI, so this harness — and cross-check-grant, -attest and
 * -monitor with it — now exits 1 on every CI run. `bash test/run.sh` reports `checks=90 fails=4`.
 * The js==kernel half of the independence claim has STILL never executed in CI; it went from
 * silently green to permanently red, and a permanently red job is a job nobody reads.
 *
 * RECORDED is the third option: compare against something real rather than against nothing. It is
 * WEAKER than LIVE and says so in its own output — it fixes the kernel at a recorded revision.
 * That is not the silent skip 1133 removed: a skip asserted an agreement nobody had tested, while
 * this asserts an agreement that was tested, names when, and refuses if the recording does not
 * describe the vectors in front of it.
 *
 * ONLY THIS HARNESS HAS IT. cross-check-grant / -attest / -monitor still hard-fail without the
 * checkout and still make the CI job red. Giving them the same treatment is the same shape of work
 * and is deliberately not done here, so that this change is one item and the remaining three are
 * visible rather than folded into a green line.
 */

const fs = require('node:fs');
const path = require('node:path');

const doc = require('./toolset-vectors.json');
const pub = require('../verify-toolset.js');
const {
  build: buildFixture, optsFor, PROBE_BODY, OUT: FIXTURE, VECTORS, appKernelPath, sha256,
} = require('./gen-toolset-kernel-verdicts.js');

const APP = appKernelPath();
const HAVE_APP = fs.existsSync(APP);

let fails = 0;
const fail = (msg) => { console.log(`FAIL  ${msg}`); fails += 1; };

/**
 * The comparison target: a function id → {valid,status,reason}, plus the two derived values.
 * LIVE reads the kernel module; RECORDED reads the fixture. Everything below is identical for
 * both, so the two modes cannot drift into testing different things.
 */
let mode;
let verdictFor;
let expectedSetDigest;
let expectedSigningInputSha;

if (HAVE_APP) {
  mode = 'LIVE';
  // eslint-disable-next-line import/no-dynamic-require, global-require
  const kernel = require(APP);
  verdictFor = (v) => kernel.verifyToolsetAttestation(v.token, optsFor(doc, v));
  expectedSetDigest = kernel.computeSetDigest(doc.entries).digest;
  expectedSigningInputSha = sha256(Buffer.from(kernel.signingInput(PROBE_BODY), 'utf8'));

  // A stale recording is caught HERE, on the first local run after a kernel change — never
  // carried silently into CI, where nothing can see the kernel to notice.
  const want = buildFixture();
  const have = fs.existsSync(FIXTURE) ? fs.readFileSync(FIXTURE, 'utf8') : '';
  if (have !== want) {
    fail('toolset-kernel-verdicts.json is STALE — regenerate: node test/gen-toolset-kernel-verdicts.js');
  } else {
    console.log('ok    recorded-verdicts  fixture matches the live kernel');
  }
} else {
  if (!fs.existsSync(FIXTURE)) {
    console.error(
      `cross-check-toolset: app kernel not found at ${APP} and no recorded verdicts at ${FIXTURE}; `
      + 'set CODERIFTS_APP_DIR to a coderifts-app checkout, or restore the fixture. Refusing to '
      + 'skip: this harness is the only place the public verifier is compared against the app '
      + 'kernel, and reporting a comparison that did not happen is worse than not having one.',
    );
    process.exit(1);
  }
  const rec = JSON.parse(fs.readFileSync(FIXTURE, 'utf8'));

  // THE BINDING. Recorded verdicts describe specific tokens. If the vectors were regenerated
  // (they carry an ephemeral key, so every regeneration changes every token), these verdicts
  // describe a different document and comparing them would be theatre.
  const nowSha = sha256(fs.readFileSync(VECTORS));
  if (rec.vectors_sha256 !== nowSha) {
    console.error(
      'cross-check-toolset: the recorded kernel verdicts do not describe these vectors\n'
      + `  recorded for: ${rec.vectors_sha256}\n`
      + `  vectors now : ${nowSha}\n`
      + '  regenerate them together on a machine with the app checkout:\n'
      + '    node test/gen-toolset-vectors.js && node test/gen-toolset-kernel-verdicts.js',
    );
    process.exit(1);
  }

  mode = 'RECORDED';
  const byId = new Map(rec.verdicts.map((r) => [r.id, r]));
  verdictFor = (v) => {
    const r = byId.get(v.id);
    if (!r) {
      // A vector with no recording must FAIL, not pass unexamined — otherwise adding a vector
      // silently shrinks what CI compares.
      return { valid: null, status: `NO_RECORDED_VERDICT_FOR_${v.id}`, reason: null };
    }
    return r;
  };
  expectedSetDigest = rec.set_digest;
  expectedSigningInputSha = rec.signing_input_sha256;
  console.log(`ok    recorded-verdicts  kernel ${rec.kernel_sha256.slice(0, 19)}… over the pinned vectors`);
}

for (const v of doc.vectors) {
  const a = pub.verifyToolsetAttestation(v.token, optsFor(doc, v));
  const b = verdictFor(v);
  const bReason = b.reason === undefined ? null : b.reason;
  const aReason = a.reason === undefined ? null : a.reason;

  if (a.valid !== b.valid || a.status !== b.status || aReason !== bReason) {
    fail(`${v.id}: public=${a.status}/${aReason} kernel=${b.status}/${bReason}`);
  } else if (a.status !== v.expect.status) {
    fail(`${v.id}: agreed on ${a.status} but vector expects ${v.expect.status}`);
  } else {
    console.log(`ok    ${v.id}  public==kernel==${a.status}`);
  }
}

// The digest itself must agree, or a correct signature would still read UNBOUND.
const dPub = pub.computeSetDigest(doc.entries);
if (dPub.digest !== expectedSetDigest) {
  fail(`set_digest: public=${dPub.digest} kernel=${expectedSetDigest}`);
} else {
  console.log(`ok    set_digest  public==kernel==${dPub.digest}`);
}

// The signing input must agree byte-for-byte.
const sPub = sha256(Buffer.from(pub.signingInput(PROBE_BODY), 'utf8'));
if (sPub !== expectedSigningInputSha) {
  fail('signingInput: public != kernel');
} else {
  console.log('ok    signingInput  public==kernel');
}

if (fails > 0) {
  console.log(`cross-check-toolset: ${fails} disagreement(s) [${mode}]`);
  process.exit(1);
}
// The mode is in the success line too. run.sh renders this, and a reader must never have to guess
// whether the green line came from the live kernel or from a recording.
console.log(
  mode === 'LIVE'
    ? `cross-check-toolset: ${doc.vectors.length}/${doc.vectors.length} agree with app kernel (TS-A-*) [LIVE]`
    : `cross-check-toolset: ${doc.vectors.length}/${doc.vectors.length} agree with RECORDED app-kernel verdicts (TS-A-*) [RECORDED — weaker than LIVE: the kernel is pinned at the recorded revision]`,
);
process.exit(0);
