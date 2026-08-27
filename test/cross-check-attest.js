#!/usr/bin/env node
'use strict';

/*
 * Cross-check EG-A-* classes: public verify-attest.js vs the app kernel
 * (coderifts-app/src/verdict-core/execution-attestation.js) when that checkout exists.
 *
 * Exit 0 if app kernel is missing (do not fail a standalone clone) OR if every
 * class agrees. Exit 1 on disagreement.
 */

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const vectors = require('./attest-vectors.json');
const { verifyExecutionAttestation } = require('../verify-attest.js');

const APP = process.env.CODERIFTS_APP_DIR
  || path.join(os.homedir(), 'coderifts-app', 'src', 'verdict-core', 'execution-attestation.js');

// ── 1133: A MISSING APP CHECKOUT FAILS LOUD, IT DOES NOT SKIP ────────────────────────────────
//
// This used to print "— skip" and exit 0. run.sh checks the exit code explicitly, so a skip did
// not become a swallowed failure — it became something worse: run.sh printed
//   ok    cross-check-attest (js == app kernel on ...)
// a green line asserting an agreement that was never tested. MEASURED 2026-08-27: the CI workflow
// (.github/workflows/verify-live-receipt.yml) checks out THIS repository only and never the app,
// so $HOME/coderifts-app does not exist there and this comparison has never actually run in CI.
//
// Same rule the app applies to its own vendored-sync gate: a missing checkout fails loud, never
// skips. An absent comparison must not be reported as a passing one.
if (!fs.existsSync(APP)) {
  console.error(
    `cross-check-attest: app kernel not found at ${APP}; set CODERIFTS_APP_DIR to a `
    + 'coderifts-app checkout, or clone it at $HOME/coderifts-app. Refusing to skip: this harness '
    + 'is the only place the public verifier is compared against the app kernel, and reporting a '
    + 'comparison that did not happen is worse than not having one.',
  );
  process.exit(1);
}

const app = require(APP);

function registryFor(v) {
  if (v.keys === 'empty') return vectors.empty_registry;
  if (v.keys === 'retired_registry') return vectors.retired_registry;
  return vectors.registry;
}

function intendedFor(v) {
  const f = v.flags || {};
  const intended = {};
  if (f.grant) intended.grant = f.grant;
  if (f.receipt_digest) intended.receipt_digest = f.receipt_digest;
  return Object.keys(intended).length ? intended : undefined;
}

let fails = 0;
const names = vectors.vectors.map((x) => x.name);

for (const v of vectors.vectors) {
  const registry = registryFor(v);
  const intended = intendedFor(v);
  const opts = { registry, ...(intended ? { intended } : {}) };
  const pub = verifyExecutionAttestation(v.token, opts);
  const ref = app.verifyExecutionAttestation(v.token, opts);
  const agree = pub.status === ref.status && pub.valid === ref.valid
    && (pub.reason || null) === (ref.reason || null)
    && pub.status === v.expected.status
    && pub.valid === v.expected.valid;
  if (!agree) {
    console.log(`FAIL  ${v.name}: js=${pub.status}/${pub.reason} app=${ref.status}/${ref.reason} expected=${v.expected.status}`);
    fails += 1;
  } else {
    console.log(`ok    ${v.name}  js=app=${pub.status}`);
  }
}

console.log(`cross-check-attest: ${names.length - fails}/${names.length} agree with app kernel at ${APP}`);
process.exit(fails === 0 ? 0 : 1);
