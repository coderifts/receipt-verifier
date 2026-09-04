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
const { loadRecorded, FAMILIES } = require('./gen-kernel-verdicts');

const APP = process.env.CODERIFTS_APP_DIR
  ? path.join(process.env.CODERIFTS_APP_DIR, 'src', 'verdict-core', 'monitoring-attestation.js')
  : path.join(os.homedir(), 'coderifts-app', 'src', 'verdict-core', 'monitoring-attestation.js');

let mode;
let kernelVerify;
if (fs.existsSync(APP)) {
  mode = 'LIVE';
  // eslint-disable-next-line import/no-dynamic-require, global-require
  const app = require(APP);
  if (typeof app.verifyMonitoringAttestation !== 'function') {
    console.error(
      `cross-check-monitor: ${APP} exists but exports no verifyMonitoringAttestation `
      + `(exports: ${Object.keys(app).join(', ') || 'none'}). The kernel entry point was renamed or `
      + 'removed; this comparison cannot run and must not be reported as passing.',
    );
    process.exit(1);
  }
  kernelVerify = (token, opts) => app.verifyMonitoringAttestation(token, opts);
  const want = FAMILIES.monitor().text;
  const fix = path.join(__dirname, 'monitor-kernel-verdicts.json');
  const have = fs.existsSync(fix) ? fs.readFileSync(fix, 'utf8') : '';
  if (have !== want) {
    console.log('FAIL  monitor-kernel-verdicts.json is STALE — regenerate: node test/gen-kernel-verdicts.js --family monitor');
    process.exit(1);
  }
} else {
  let rec;
  try {
    rec = loadRecorded('monitor', path.join(__dirname, 'monitor-vectors.json'));
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
  mode = 'RECORDED';
  kernelVerify = (_token, _opts, name) => rec.byName.get(name)
    || { valid: null, status: `NO_RECORDED_VERDICT_FOR_${name}`, reason: null };
  console.log(`ok    recorded-verdicts  kernel ${rec.rec.kernel_sha256.slice(0, 19)}… over the pinned vectors`);
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
  const ref = kernelVerify(v.token, opts, v.name);
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

if (fails > 0) {
  console.log(`cross-check-monitor: ${fails} disagreement(s) [${mode}]`);
  process.exit(1);
}
if (mode === 'LIVE') {
  console.log(`cross-check-monitor: ${names.length}/${names.length} agree with app kernel at ${APP} [LIVE]`);
} else {
  console.log(`cross-check-monitor: ${names.length}/${names.length} agree with RECORDED app-kernel verdicts [RECORDED — weaker than LIVE]`);
}
process.exit(0);
