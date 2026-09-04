#!/usr/bin/env node
'use strict';

/*
 * Cross-check EG-A-* classes: public verify-attest.js vs the app kernel
 * (coderifts-app/src/verdict-core/execution-attestation.js) when that checkout exists.
 *
 * LIVE when the app checkout exists; RECORDED (weaker, named) in CI where it does not.
 * Exit 1 on disagreement or a missing/stale recording. Never skip.
 */

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const vectors = require('./attest-vectors.json');
const { verifyExecutionAttestation } = require('../verify-attest.js');
const { loadRecorded, FAMILIES } = require('./gen-kernel-verdicts');

const APP = process.env.CODERIFTS_APP_DIR
  ? path.join(process.env.CODERIFTS_APP_DIR, 'src', 'verdict-core', 'execution-attestation.js')
  : path.join(os.homedir(), 'coderifts-app', 'src', 'verdict-core', 'execution-attestation.js');

let mode;
let kernelVerify;
if (fs.existsSync(APP)) {
  mode = 'LIVE';
  // eslint-disable-next-line import/no-dynamic-require, global-require
  const app = require(APP);
  kernelVerify = (token, opts) => app.verifyExecutionAttestation(token, opts);
  const want = FAMILIES.attest().text;
  const fix = path.join(__dirname, 'attest-kernel-verdicts.json');
  const have = fs.existsSync(fix) ? fs.readFileSync(fix, 'utf8') : '';
  if (have !== want) {
    console.log('FAIL  attest-kernel-verdicts.json is STALE — regenerate: node test/gen-kernel-verdicts.js --family attest');
    process.exit(1);
  }
} else {
  let rec;
  try {
    rec = loadRecorded('attest', path.join(__dirname, 'attest-vectors.json'));
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
  console.log(`cross-check-attest: ${fails} disagreement(s) [${mode}]`);
  process.exit(1);
}
if (mode === 'LIVE') {
  console.log(`cross-check-attest: ${names.length}/${names.length} agree with app kernel at ${APP} [LIVE]`);
} else {
  console.log(`cross-check-attest: ${names.length}/${names.length} agree with RECORDED app-kernel verdicts [RECORDED — weaker than LIVE]`);
}
process.exit(0);
