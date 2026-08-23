#!/usr/bin/env node
'use strict';

/*
 * Cross-check the five EG-* classes: public verify-grant.js vs the app kernel
 * (coderifts-app/src/verdict-core/execution-grant.js) when that checkout exists.
 *
 * App verifyExecutionGrant with a pinned publicKey skips the registry retired
 * path — retired-key is compared js/py only (run.sh). This script pins the
 * ephemeral public key and compares status/valid/reason on EG-*.
 *
 * Exit 0 if app kernel is missing (do not fail a standalone clone) OR if every
 * class agrees. Exit 1 on disagreement.
 */

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');

const vectors = require('./grant-vectors.json');
const { verifyExecutionGrant } = require('../verify-grant.js');

const APP = process.env.CODERIFTS_APP_DIR
  || path.join(os.homedir(), 'coderifts-app', 'src', 'verdict-core', 'execution-grant.js');

if (!fs.existsSync(APP)) {
  console.log(`cross-check-grant: app kernel not found at ${APP} — skip`);
  process.exit(0);
}

const app = require(APP);
const publicKey = crypto.createPublicKey(vectors.public_key_pem);
const ctx = { publicKey, expectedKid: vectors.kid };

const CLASSES = ['EG-VALID', 'EG-EXPIRED', 'EG-WRONG-AUDIENCE', 'EG-SCOPE-MISMATCH', 'EG-UNBOUND-DIGEST'];
let fails = 0;
const rows = [];

for (const name of CLASSES) {
  const v = vectors.vectors.find((x) => x.name === name);
  if (!v) {
    console.log(`FAIL  ${name}: missing from grant-vectors.json`);
    fails += 1;
    continue;
  }
  const intended = {};
  const f = v.flags || {};
  if (f['intended-operation']) intended.operation = f['intended-operation'];
  if (f['intended-target']) intended.target_id = f['intended-target'];
  if (f['intended-audience']) intended.audience = f['intended-audience'];
  if (f.after_payload != null) intended.after_payload = f.after_payload;
  if (f.receipt) intended.receipt_token = f.receipt;

  const pub = verifyExecutionGrant(v.token, ctx, { intended });
  const ref = app.verifyExecutionGrant(v.token, { publicKey, intended });
  const agree = pub.status === ref.status && pub.valid === ref.valid
    && (pub.reason || null) === (ref.reason || null)
    && pub.status === v.expected.status
    && pub.valid === v.expected.valid;
  rows.push({
    name,
    expected: v.expected.status,
    js: pub.status,
    app: ref.status,
    agree,
  });
  if (!agree) {
    console.log(`FAIL  ${name}: js=${pub.status}/${pub.reason} app=${ref.status}/${ref.reason} expected=${v.expected.status}`);
    fails += 1;
  } else {
    console.log(`ok    ${name}  js=app=${pub.status}`);
  }
}

console.log(`cross-check-grant: ${CLASSES.length - fails}/${CLASSES.length} agree with app kernel at ${APP}`);
process.exit(fails === 0 ? 0 : 1);
