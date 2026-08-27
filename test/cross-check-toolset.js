#!/usr/bin/env node
'use strict';

/*
 * Cross-check TS-A-* classes: public verify-toolset.js vs the app kernel
 * (coderifts-app/src/verdict-core/toolset-attestation.js) when that checkout exists.
 *
 * Exit 0 if the app kernel is missing (do not fail a standalone clone) OR if every
 * class agrees. Exit 1 on disagreement.
 *
 * This is the check that keeps an independent port honest: the vectors are self-contained,
 * so the public verifier can be exercised without the app at all — but when the app IS
 * present, "independent" must still mean "agrees".
 */

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const doc = require('./toolset-vectors.json');
const pub = require('../verify-toolset.js');

const APP = process.env.CODERIFTS_APP_DIR
  || path.join(os.homedir(), 'coderifts-app', 'src', 'verdict-core', 'toolset-attestation.js');

// ── 1133: A MISSING APP CHECKOUT FAILS LOUD, IT DOES NOT SKIP ────────────────────────────────
//
// This used to print "— skip" and exit 0. run.sh checks the exit code explicitly, so a skip did
// not become a swallowed failure — it became something worse: run.sh printed
//   ok    cross-check-toolset (js == app kernel on ...)
// a green line asserting an agreement that was never tested. MEASURED 2026-08-27: the CI workflow
// (.github/workflows/verify-live-receipt.yml) checks out THIS repository only and never the app,
// so $HOME/coderifts-app does not exist there and this comparison has never actually run in CI.
//
// Same rule the app applies to its own vendored-sync gate: a missing checkout fails loud, never
// skips. An absent comparison must not be reported as a passing one.
if (!fs.existsSync(APP)) {
  console.error(
    `cross-check-toolset: app kernel not found at ${APP}; set CODERIFTS_APP_DIR to a `
    + 'coderifts-app checkout, or clone it at $HOME/coderifts-app. Refusing to skip: this harness '
    + 'is the only place the public verifier is compared against the app kernel, and reporting a '
    + 'comparison that did not happen is worse than not having one.',
  );
  process.exit(1);
}

// eslint-disable-next-line import/no-dynamic-require, global-require
const kernel = require(APP);

let fails = 0;

for (const v of doc.vectors) {
  const registry = v.registry_override || doc.registry;
  const opts = { registry };
  if (v.entries_override) opts.entries = v.entries_override;
  else if (v.id === 'TS-A-VALID') opts.entries = doc.entries;

  const a = pub.verifyToolsetAttestation(v.token, opts);
  const b = kernel.verifyToolsetAttestation(v.token, opts);

  if (a.valid !== b.valid || a.status !== b.status || a.reason !== b.reason) {
    console.log(`FAIL  ${v.id}: public=${a.status}/${a.reason} kernel=${b.status}/${b.reason}`);
    fails += 1;
  } else if (a.status !== v.expect.status) {
    console.log(`FAIL  ${v.id}: agreed on ${a.status} but vector expects ${v.expect.status}`);
    fails += 1;
  } else {
    console.log(`ok    ${v.id}  public==kernel==${a.status}`);
  }
}

// The digest itself must agree, or a correct signature would still read UNBOUND.
const dPub = pub.computeSetDigest(doc.entries);
const dKer = kernel.computeSetDigest(doc.entries);
if (dPub.digest !== dKer.digest) {
  console.log(`FAIL  set_digest: public=${dPub.digest} kernel=${dKer.digest}`);
  fails += 1;
} else {
  console.log(`ok    set_digest  public==kernel==${dPub.digest}`);
}

// The signing input must agree byte-for-byte.
const body = {
  v: pub.ATTEST_VERSION, kid: 'k', declarer: 'D', statement: pub.STATEMENTS[0],
  set_digest: 'sha256:abc', declared_at: '2026-08-25T00:00:00Z', session_id: 'S',
  receipt_digest: 'sha256:rd', framework: 'FW', framework_version: 'FV',
  guard_version: 'GV', tool_count: 3, mutating_count: 2, scope_note: 'SN',
};
if (pub.signingInput(body) !== kernel.signingInput(body)) {
  console.log('FAIL  signingInput: public != kernel');
  fails += 1;
} else {
  console.log('ok    signingInput  public==kernel');
}

if (fails > 0) {
  console.log(`cross-check-toolset: ${fails} disagreement(s)`);
  process.exit(1);
}
console.log(`cross-check-toolset: ${doc.vectors.length}/${doc.vectors.length} agree with app kernel (TS-A-*)`);
process.exit(0);
