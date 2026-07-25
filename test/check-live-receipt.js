#!/usr/bin/env node
'use strict';

/*
 * CI guard: fetch the CURRENT live CodeRifts receipt from the demo pull-request
 * comment and verify it with the in-repo verify.js. Fails (exit 1) if the live
 * receipt does not verify, or if it is a newer envelope version than this verifier
 * supports. This is the tripwire that catches a receipt-format bump shipping before
 * the verifier learns it.
 *
 * Source of the token: the CodeRifts sticky check-comment on coderifts/demo PR #4,
 * which embeds the exact `node verify.js "<token>"` command.
 *
 * Auth: none required for the public demo repo (unauthenticated GitHub REST works,
 * 60 req/h per IP). In GitHub Actions the automatic GITHUB_TOKEN is used when
 * present purely to raise the rate limit (5000 req/h) -- it needs only public read,
 * no extra secret. Set GITHUB_TOKEN='' to force unauthenticated.
 *
 * Degradation: on any network/API failure (or a missing comment) the guard falls
 * back to the committed live fixture in test/vectors.json and verifies THAT offline,
 * printing a loud warning. That still catches verifier regressions; it cannot catch
 * a live-format bump while the API is unreachable (documented, never a silent pass).
 *
 * Env overrides: DEMO_REPO (default coderifts/demo), DEMO_PR (default 4),
 * FETCH_URL (default prod attestation endpoint), GITHUB_TOKEN (optional).
 */

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

// The newest envelope version verify.js understands. Bump this in lockstep with
// reconstructSignedInput() whenever a new crchain envelope version is supported.
const MAX_SUPPORTED_V = 4;

const REPO = process.env.DEMO_REPO || 'coderifts/demo';
const PR = process.env.DEMO_PR || '4';
const FETCH_URL = process.env.FETCH_URL || 'https://app.coderifts.com/api/v1/attestation/public-key';
const TOKEN = process.env.GITHUB_TOKEN || '';
const ROOT = path.join(__dirname, '..');
const VERIFY_JS = path.join(ROOT, 'verify.js');
const STICKY_MARKER = '<!-- coderifts-api-check -->';
const TOKEN_RE = /node verify\.js "([A-Za-z0-9._-]+)"/;

function log(msg) { process.stdout.write(`${msg}\n`); }
function warn(msg) { process.stderr.write(`WARN  ${msg}\n`); }

async function fetchComments() {
  const headers = { Accept: 'application/vnd.github+json', 'User-Agent': 'coderifts-receipt-verifier-ci' };
  if (TOKEN) headers.Authorization = `Bearer ${TOKEN}`;
  const comments = [];
  for (let page = 1; page <= 10; page++) {
    const url = `https://api.github.com/repos/${REPO}/issues/${PR}/comments?per_page=100&page=${page}`;
    const res = await fetch(url, { headers });
    if (!res.ok) throw new Error(`GET ${url} -> HTTP ${res.status}`);
    const batch = await res.json();
    if (!Array.isArray(batch) || batch.length === 0) break;
    comments.push(...batch);
    if (batch.length < 100) break;
  }
  return comments;
}

// Pick the CodeRifts sticky comment (or the newest comment carrying a verify command).
function extractToken(comments) {
  const candidates = comments
    .filter((c) => c && typeof c.body === 'string')
    .sort((a, b) => String(b.updated_at || '').localeCompare(String(a.updated_at || '')));
  const sticky = candidates.find((c) => c.body.includes(STICKY_MARKER) && TOKEN_RE.test(c.body));
  const any = sticky || candidates.find((c) => TOKEN_RE.test(c.body));
  if (!any) return null;
  return any.body.match(TOKEN_RE)[1];
}

// Run verify.js and return the parsed JSON result (throws on exit 2 / usage error).
function runVerify(args) {
  let out;
  try {
    out = execFileSync('node', [VERIFY_JS, ...args], { encoding: 'utf8' });
  } catch (e) {
    // exit 1 (invalid) still prints JSON on stdout; exit 2 (usage) does not.
    if (e.stdout && e.stdout.trim().startsWith('{')) out = e.stdout;
    else throw new Error(`verify.js failed: ${e.stderr || e.message}`);
  }
  return JSON.parse(out.trim());
}

function assertValid(result, where) {
  if (!result.valid) {
    throw new Error(`${where}: receipt did NOT verify (reason=${result.reason})`);
  }
  const v = result.payload && result.payload.v;
  if (typeof v === 'number' && v > MAX_SUPPORTED_V) {
    throw new Error(`${where}: live receipt is v${v} but this verifier supports up to v${MAX_SUPPORTED_V} -- update verify.js/verify.py`);
  }
  log(`ok    ${where}: valid=true v=${v} kid=${result.payload.kid}`);
}

function verifyFixtureFallback() {
  const vectors = require('./vectors.json');
  const live = vectors.live;
  if (!live || !live.vectors || !live.vectors[0]) throw new Error('no live fixture in vectors.json');
  const pemFile = path.join(os.tmpdir(), `rv_live_${process.pid}.pem`);
  fs.writeFileSync(pemFile, live.public_key_pem, 'utf8');
  try {
    const result = runVerify([live.vectors[0].token, '--key', pemFile, '--kid', live.kid]);
    assertValid(result, 'committed-fixture');
  } finally {
    fs.rmSync(pemFile, { force: true });
  }
}

async function main() {
  log(`live-receipt guard: repo=${REPO} pr=#${PR} auth=${TOKEN ? 'token' : 'anonymous'}`);
  let token = null;
  try {
    const comments = await fetchComments();
    token = extractToken(comments);
    if (!token) warn(`no receipt token found in ${REPO} PR #${PR} comments`);
  } catch (e) {
    warn(`could not fetch live receipt: ${e.message}`);
  }

  if (token) {
    // Verify the LIVE token; key discovered from the attestation endpoint.
    const result = runVerify([token, '--fetch', FETCH_URL]);
    assertValid(result, 'live-receipt');
    log('LIVE RECEIPT VERIFIED');
    return;
  }

  warn('falling back to the committed live fixture (offline). This catches verifier');
  warn('regressions but NOT a live-format bump while the API is unreachable.');
  verifyFixtureFallback();
  log('FIXTURE VERIFIED (live fetch unavailable)');
}

main().catch((e) => {
  process.stderr.write(`FAIL  ${e.message}\n`);
  process.exit(1);
});
