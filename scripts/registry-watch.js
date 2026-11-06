#!/usr/bin/env node
'use strict';

/**
 * 10t-rv (2026-11-05) — the live key registry against the pinned snapshot. Run daily by
 * .github/workflows/registry-watch.yml, never by the release gate (test/run.sh / release.yml).
 *
 * Red (exit 1) when:
 *   - the registry's bytes do not hash to the pinned sha256 (keys/coderifts-keys.json.sha256), or
 *   - 2026-07-k1 is not { status: "revoked", compromised_at: "2026-07-01T00:00:00.000Z" }.
 * Exit 2 when the registry cannot be fetched (a transport failure is not a pass).
 *
 *   node scripts/registry-watch.js [--url <registry>]
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const DEFAULT_URL = 'https://app.coderifts.com/.well-known/coderifts-keys.json';
const EXPECTED_STATUSES = Object.freeze({
  '2026-07-k1': { status: 'revoked', compromised_at: '2026-07-01T00:00:00.000Z' },
});

function pinnedSha256() {
  return fs.readFileSync(path.join(ROOT, 'keys', 'coderifts-keys.json.sha256'), 'utf8').trim().split(/\s+/)[0];
}

/** The findings for one fetched body (a Buffer); [] means it matches. Pure, so a test can feed it bytes. */
function compare(body, pinned = pinnedSha256()) {
  const findings = [];
  const live = crypto.createHash('sha256').update(body).digest('hex');
  if (live !== pinned) findings.push(`sha256 ${live} !== pinned ${pinned} (keys/coderifts-keys.json.sha256)`);
  let doc = null;
  try { doc = JSON.parse(body.toString('utf8')); } catch (e) { findings.push(`the registry is not JSON: ${e.message}`); }
  const keys = doc && Array.isArray(doc.keys) ? doc.keys : [];
  for (const [kid, want] of Object.entries(EXPECTED_STATUSES)) {
    const k = keys.find((x) => x && x.kid === kid);
    if (!k) { findings.push(`${kid} is not in the registry`); continue; }
    for (const [field, value] of Object.entries(want)) {
      if (k[field] !== value) findings.push(`${kid}.${field} is ${JSON.stringify(k[field])}, pinned ${JSON.stringify(value)}`);
    }
  }
  return { live_sha256: live, pinned_sha256: pinned, findings };
}

async function main(argv = process.argv.slice(2)) {
  const i = argv.indexOf('--url');
  const url = i >= 0 ? argv[i + 1] : DEFAULT_URL;
  let res;
  try {
    res = await fetch(url, { headers: { accept: 'application/json' }, redirect: 'error' });
  } catch (e) {
    console.error(`registry-watch: could not fetch ${url}: ${(e.cause && e.cause.code) || e.message}`);
    return 2;
  }
  if (!res.ok) { console.error(`registry-watch: ${url} answered HTTP ${res.status}`); return 2; }
  const out = compare(Buffer.from(await res.arrayBuffer()));
  console.log(JSON.stringify({ url, ...out }, null, 2));
  if (out.findings.length) {
    console.error(`registry-watch: the live registry differs from the pinned snapshot (${out.findings.length} finding(s)).`);
    console.error('  Either the server changed (refresh keys/ with keys/README.md, release the verifier) or the pin is stale.');
    return 1;
  }
  return 0;
}

if (require.main === module) main().then((code) => { process.exitCode = code; });

module.exports = { compare, pinnedSha256, EXPECTED_STATUSES, DEFAULT_URL };
