#!/usr/bin/env node
'use strict';

/*
 * Cross-check MON-A-* classes: public verify-monitor.js vs the app kernel
 * (coderifts-app/src/verdict-core/monitoring-attestation.js) when that checkout exists.
 *
 * Exit 0 only if every class agrees. Exit 1 on disagreement OR on a missing app checkout.
 */

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const vectors = require('./monitor-vectors.json');
const { verifyMonitoringAttestation } = require('../verify-monitor.js');

const APP = process.env.CODERIFTS_APP_DIR
  ? path.join(process.env.CODERIFTS_APP_DIR, 'src', 'verdict-core', 'monitoring-attestation.js')
  : path.join(os.homedir(), 'coderifts-app', 'src', 'verdict-core', 'monitoring-attestation.js');

// ── 1133: A MISSING APP CHECKOUT FAILS LOUD, IT DOES NOT SKIP ────────────────────────────────
//
// Written this way from the first commit rather than retrofitted. A skip here would not be a
// swallowed failure — run.sh checks the exit code — it would be something worse: run.sh would
// print
//   ok    cross-check-monitor (js == app kernel on ...)
// a green line asserting an agreement that was never tested. MEASURED 2026-08-27: the CI workflow
// (.github/workflows/verify-live-receipt.yml) checks out THIS repository only and never the app,
// so $HOME/coderifts-app does not exist there and this comparison does not run in CI.
//
// An absent comparison must not be reported as a passing one.
if (!fs.existsSync(APP)) {
  console.error(
    `cross-check-monitor: app kernel not found at ${APP}; set CODERIFTS_APP_DIR to a `
    + 'coderifts-app checkout, or clone it at $HOME/coderifts-app. Refusing to skip: this harness '
    + 'is the only place the public monitoring verifier is compared against the app kernel, and '
    + 'reporting a comparison that did not happen is worse than not having one.',
  );
  process.exit(1);
}

const app = require(APP);

// If the app kernel ever stops exporting the entry point, that is a rename or a removal — either
// way the comparison cannot run, and `undefined is not a function` further down would read as a
// crash of unclear origin. Name it here instead.
if (typeof app.verifyMonitoringAttestation !== 'function') {
  console.error(
    `cross-check-monitor: ${APP} exists but exports no verifyMonitoringAttestation `
    + `(exports: ${Object.keys(app).join(', ') || 'none'}). The kernel entry point was renamed or `
    + 'removed; this comparison cannot run and must not be reported as passing.',
  );
  process.exit(1);
}

function registryFor(v) {
  if (v.keys === 'empty') return vectors.empty_registry;
  if (v.keys === 'retired_registry') return vectors.retired_registry;
  return vectors.registry;
}

function intendedFor(v) {
  const f = v.flags || {};
  const intended = {};
  if (f.decision_id) intended.decision_id = f.decision_id;
  if (f.receipt_digest) intended.receipt_digest = f.receipt_digest;
  return Object.keys(intended).length ? intended : undefined;
}

let fails = 0;
const names = vectors.vectors.map((x) => x.name);

for (const v of vectors.vectors) {
  const registry = registryFor(v);
  const intended = intendedFor(v);
  const opts = { registry, ...(intended ? { intended } : {}) };
  const pub = verifyMonitoringAttestation(v.token, opts);
  const ref = app.verifyMonitoringAttestation(v.token, opts);
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

console.log(`cross-check-monitor: ${names.length - fails}/${names.length} agree with app kernel at ${APP}`);
process.exit(fails === 0 ? 0 : 1);
