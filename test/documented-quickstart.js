#!/usr/bin/env node
'use strict';

/**
 * The command in the README has to work for someone who has only the files it names.
 *
 * MEASURED 2026-09-13, by doing exactly what a reader does — an empty directory, the files
 * fetched, the command run:
 *
 *     $ curl -sSO .../main/verify.js && node verify.js "$(cat receipt.txt)"
 *     Error: Cannot find module './arity'
 *
 * The published instruction had been broken for sixteen days. Commit edb89ef (1129, 2026-08-28)
 * moved the shared (token, opts) shim into arity.js and required it at the TOP of verify.js, and
 * the CLI had already moved to cli.js — so verify.js stopped being both single-file and runnable
 * in one change. Every tag since (v1.0.0, v1.0.1, v1.0.2 — all 2026-09-09/10) is on the far side
 * of that split, so nothing released was ever single-file either.
 *
 * The tests in this repo all passed throughout, because every one of them runs from the repo
 * root where ./arity resolves. That is the shape of this bug: the code was fine, the tree was
 * fine, and the only thing broken was the path a stranger takes. So this check does not import
 * anything — it COPIES the named files into a scratch directory and runs the documented command
 * as a subprocess, which is the only way to be standing where the reader is standing.
 *
 * WHY THE FILE LIST IS READ OUT OF THE README. Hard-coding it here would let the README drift and
 * this check keep passing on a list nobody publishes. The README's "What you need on disk" block
 * is the list; if it stops parsing, that is a failure too, not a skip.
 *
 * Offline on purpose: fetching from raw.githubusercontent would test GitHub's cache and could not
 * run on a branch before it merges. What is checked is the tree that is ABOUT to be published.
 */

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const README = path.join(ROOT, 'README.md');

/** The file list the README tells a reader to obtain, read out of its own fenced block. */
function documentedFiles() {
  const md = fs.readFileSync(README, 'utf8');
  const marker = '### What you need on disk (Node)';
  const at = md.indexOf(marker);
  assert.notEqual(at, -1,
    `README.md no longer has "${marker}". If the section was renamed, point this check at the new `
    + 'name in the same change; do not delete the check and leave the instructions unverified.');
  const open = md.indexOf('```', at);
  const close = md.indexOf('```', open + 3);
  const block = md.slice(open + 3, close);
  const files = block.split('\n')
    .map((l) => l.trim().split(/\s{2,}/)[0])
    .filter((l) => /^[\w./-]+\.(js|json)$/.test(l));
  assert.ok(files.length >= 2,
    `parsed ${files.length} filenames out of the README block; expected the Node file set`);
  return files;
}

/** The command the README tells a reader to run, reduced to argv. */
const DOCUMENTED_ENTRY = 'cli.js';

function main() {
  const files = documentedFiles();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rv-quickstart-'));
  let failures = 0;
  const fail = (msg) => { failures += 1; console.log(`FAIL  ${msg}`); };

  try {
    // 1. Only the named files exist here. Nothing else from the repo is reachable.
    for (const rel of files) {
      const src = path.join(ROOT, rel);
      if (!fs.existsSync(src)) { fail(`README names ${rel}, which is not in this repo`); continue; }
      const dest = path.join(dir, rel);
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.copyFileSync(src, dest);
    }
    if (failures) return failures;

    assert.ok(files.includes(DOCUMENTED_ENTRY),
      `the README's file list does not include ${DOCUMENTED_ENTRY}, the entry point it tells a reader to run`);

    // 2. A receipt this repo already trusts, plus the key it was signed under — both out of the
    //    committed vectors, exactly as test/run.sh does it. Offline, and what is under test is the
    //    FILE SET rather than the crypto: a production receipt would add an expiry and a live
    //    keyring to a check that is about whether four files are enough to run one command.
    const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, 'vectors.json'), 'utf8'));
    const list = vectors.vectors || vectors.cases || [];
    const good = list.find((v) => v.expected && v.expected.valid === true);
    assert.ok(good, 'no valid-expected vector found to run the documented command against');
    const token = good.token || good.receipt;
    assert.ok(typeof token === 'string' && token.length > 0, 'the chosen vector carries no token');
    assert.ok(vectors.public_key_pem && vectors.kid, 'vectors.json carries no public_key_pem / kid');

    const pem = path.join(dir, 'vector-key.pem');
    fs.writeFileSync(pem, vectors.public_key_pem);

    // 3. The documented command, as a subprocess, with cwd INSIDE the scratch directory. The key
    //    flags are the only addition, and they are the same ones run.sh passes — everything the
    //    reader would type is unchanged.
    const r = spawnSync(process.execPath,
      [DOCUMENTED_ENTRY, token, '--key', 'vector-key.pem', '--kid', vectors.kid],
      { cwd: dir, encoding: 'utf8' });

    if (r.status !== 0) {
      fail(`the documented command exited ${r.status} in a directory holding only the files the `
        + `README names (${files.join(', ')}).\n      stderr: ${(r.stderr || '').trim().split('\n')[0]}`);
      return failures;
    }
    let parsed;
    try {
      parsed = JSON.parse(r.stdout.trim().split('\n').pop());
    } catch {
      fail(`the documented command printed something that is not JSON: ${JSON.stringify(r.stdout.slice(0, 120))}`);
      return failures;
    }
    if (parsed.valid !== true) {
      fail(`the documented command ran but reported valid=${parsed.valid} (${parsed.status || parsed.reason})`);
      return failures;
    }
    console.log(`ok    documented-quickstart  (${files.length} files, cwd=scratch, `
      + `${DOCUMENTED_ENTRY} -> valid=true status=${parsed.status})`);
    return 0;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

try {
  process.exit(main() ? 1 : 0);
} catch (err) {
  console.log(`FAIL  documented-quickstart: ${err && err.message}`);
  process.exit(1);
}
