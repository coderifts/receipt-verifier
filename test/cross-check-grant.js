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
 * LIVE when the app checkout exists; RECORDED (weaker, named) in CI where it does not.
 * Exit 1 on disagreement, on a missing recording, or on a recording that does not
 * describe these vectors. Never skip.
 */

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');

const vectors = require('./grant-vectors.json');
const { verifyExecutionGrant } = require('../verify-grant.js');
const { loadRecorded } = require('./gen-kernel-verdicts');

const APP = process.env.CODERIFTS_APP_DIR
  ? path.join(process.env.CODERIFTS_APP_DIR, 'src', 'verdict-core', 'execution-grant.js')
  : path.join(os.homedir(), 'coderifts-app', 'src', 'verdict-core', 'execution-grant.js');

const publicKey = crypto.createPublicKey(vectors.public_key_pem);
const ctx = { publicKey, expectedKid: vectors.kid };

let mode;
let kernelVerify;
if (fs.existsSync(APP)) {
  mode = 'LIVE';
  // eslint-disable-next-line import/no-dynamic-require, global-require
  const app = require(APP);
  kernelVerify = (token, intended) => app.verifyExecutionGrant(token, { publicKey, intended });
  const { FAMILIES } = require('./gen-kernel-verdicts');
  const want = FAMILIES.grant().text;
  const have = fs.existsSync(path.join(__dirname, 'grant-kernel-verdicts.json'))
    ? fs.readFileSync(path.join(__dirname, 'grant-kernel-verdicts.json'), 'utf8') : '';
  if (have !== want) {
    console.log('FAIL  grant-kernel-verdicts.json is STALE — regenerate: node test/gen-kernel-verdicts.js --family grant');
    process.exit(1);
  }
} else {
  let rec;
  try {
    rec = loadRecorded('grant', path.join(__dirname, 'grant-vectors.json'));
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
  mode = 'RECORDED';
  kernelVerify = (_token, _intended, name) => rec.byName.get(name)
    || { valid: null, status: `NO_RECORDED_VERDICT_FOR_${name}`, reason: null };
  console.log(`ok    recorded-verdicts  kernel ${rec.rec.kernel_sha256.slice(0, 19)}… over the pinned vectors`);
}

const CLASSES = [
  'EG-VALID', 'EG-EXPIRED', 'EG-WRONG-AUDIENCE', 'EG-SCOPE-MISMATCH', 'EG-UNBOUND-DIGEST',
  'EG2-VALID', 'EG2-TRANSFERRED-EXECUTOR', 'EG2-TARGET-MISMATCH', 'EG2-AUDIENCE-MISMATCH',
  'EG2-SWAP-A', 'EG2-SWAP-B',
];
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
  if (f['intended-target']) {
    intended.target_id = f['intended-target'];
    intended.target_uri = f['intended-target'];
  }
  if (f['intended-audience']) intended.audience = f['intended-audience'];
  if (f['intended-executor']) intended.executor_id = f['intended-executor'];
  if (f['intended-adapter']) intended.adapter_id = f['intended-adapter'];
  if (f.after_payload != null) intended.after_payload = f.after_payload;
  if (f.receipt) intended.receipt_token = f.receipt;

  const pub = verifyExecutionGrant(v.token, ctx, { intended });
  const ref = kernelVerify(v.token, intended, name);
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

if (fails > 0) {
  console.log(`cross-check-grant: ${fails} disagreement(s) [${mode}]`);
  process.exit(1);
}
if (mode === 'LIVE') {
  console.log(`cross-check-grant: ${CLASSES.length}/${CLASSES.length} agree with app kernel at ${APP} [LIVE]`);
} else {
  console.log(`cross-check-grant: ${CLASSES.length}/${CLASSES.length} agree with RECORDED app-kernel verdicts [RECORDED — weaker than LIVE]`);
}
process.exit(0);
