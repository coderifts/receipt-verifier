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

if (!fs.existsSync(APP)) {
  console.log(`cross-check-attest: app kernel not found at ${APP} — skip`);
  process.exit(0);
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
