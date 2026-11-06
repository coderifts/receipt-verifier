'use strict';
/**
 * roadmap 1079 (step 2 of the migration) — an unrecognised key status must FAIL CLOSED.
 *
 * MEASURED, and it is why this landed ahead of revocation itself. Given the same receipt, the same
 * key and a registry saying status:"revoked":
 *     app kernel isIssueTimeWithinKeyWindow -> false   (rejects)
 *     verify-attest.js / verify-toolset.js  -> false   (rejects)
 *     verify.js                             -> valid:true VERIFIED_CURRENT   (ACCEPTED)
 *     verify.py                             -> valid:true VERIFIED_CURRENT   (ACCEPTED)
 * The two verifiers we point the public at hardest were the two that ignored it. An operator who
 * marked a stolen key revoked would have believed they had acted; nothing would have changed.
 *
 * THIS IS NOT REVOCATION. Revocation needs compromised_at and its own statuses across eight
 * implementations — see scratchpad/roadmap-1079-revocation-DESIGN.md. What lands here is only the
 * DIRECTION of the unknown case, which is a bug independent of that work and which makes every
 * later step safe to roll out one verifier at a time.
 *
 * Safe by measurement: the live registry publishes 'active' only, so no real consumer changes.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const LIVE_KEYS = 'https://app.coderifts.com/.well-known/coderifts-keys.json';

/** A registry built from the live one with a single field changed. */
function registryWith(status, extra = {}) {
  const base = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures-keys.json'), 'utf8'));
  base.keys[0] = { ...base.keys[0], status, ...extra };
  const p = path.join(os.tmpdir(), `keys-${status}-${process.pid}.json`);
  fs.writeFileSync(p, JSON.stringify(base));
  return p;
}

// 10t-rv (2026-11-05): test/fixtures-keys.json holds a TEST key (test-fixture-k1), not the real 2026-07-k1;
// fixtures-receipt-test-k1.txt is the same v2 payload signed by it. The real 07-k1 receipt stays for the pinned-snapshot (revoked) cases.
const RECEIPT = fs.readFileSync(path.join(__dirname, 'fixtures-receipt-test-k1.txt'), 'utf8').trim();
/**
 * Run a verifier and parse its JSON. It exits NON-ZERO on an invalid receipt — which is correct,
 * and which execFileSync surfaces as a throw — so the stdout must be read off the error too. An
 * earlier draft of this helper only read the success path and reported the working fix as broken.
 */
function run(bin, args) {
  try {
    return JSON.parse(execFileSync(bin, args, { cwd: ROOT, encoding: 'utf8' }));
  } catch (err) {
    if (err && typeof err.stdout === 'string' && err.stdout.trim()) return JSON.parse(err.stdout);
    throw err;
  }
}

describe('an unrecognised key status fails closed (both languages)', () => {
  for (const [label, bin, script] of [['cli.js', 'node', 'cli.js'], ['verify.py', 'python3', 'verify.py']]) {
    it(`${label}: status "revoked" is NOT accepted`, () => {
      // UPDATED DELIBERATELY when step 3 landed. This asserted UNKNOWN_KEY_STATUS, which was right
      // while 'revoked' was a status the verifier did not understand. It now DOES understand it,
      // so the status moves -- but the INVARIANT this test exists for does not: a revoked key is
      // never valid, whatever the timestamp says.
      const out = run(bin, [script, RECEIPT, '--keys', registryWith('revoked', { revoked_at: '2026-08-26T00:00:00Z' })]);
      assert.equal(out.valid, false, 'a revoked key must never be valid');
      assert.ok(['KEY_REVOKED', 'REVOKED_KEY', 'REVOKED_KEY_UNDECIDABLE'].includes(out.status), out.status);
    });

    it(`${label}: any future status is rejected too, not just "revoked"`, () => {
      // The point is the DIRECTION of the unknown case, not a list of known-bad values.
      for (const s of ['compromised', 'suspended', 'quarantined', 'typo']) {
        const out = run(bin, [script, RECEIPT, '--keys', registryWith(s)]);
        assert.equal(out.valid, false, `status "${s}" must fail closed`);
      }
    });

    it(`${label}: the ACTIVE path is unchanged`, () => {
      const out = run(bin, [script, RECEIPT, '--keys', registryWith('active')]);
      assert.equal(out.valid, true);
      assert.equal(out.status, 'VERIFIED_CURRENT');
    });

    it(`${label}: a retired key, signed before retired_at, no anchor → RETIRED_KEY_UNANCHORED (RECEIPT_FORMAT §7.1 row 5)`, () => {
      // 10t-rv (2026-11-05): the normative table. MEASURED on 15fbdc4: RETIRED_KEY_VALID_AT_ISSUE, valid:true.
      const out = run(bin, [script, RECEIPT, '--keys', registryWith('retired', { retired_at: '2099-01-01T00:00:00Z' })]);
      assert.equal(out.status, 'RETIRED_KEY_UNANCHORED');
      assert.equal(out.valid, false);
    });
  }

  it('BOTH LANGUAGES AGREE — a split fleet is the hazard this closes', () => {
    const keys = registryWith('revoked');
    const js = run('node', ['cli.js', RECEIPT, '--keys', keys]);
    const py = run('python3', ['verify.py', RECEIPT, '--keys', keys]);
    assert.equal(js.valid, py.valid);
    assert.equal(js.status, py.status);
  });

  it('THE FIX IS NOT REVOCATION, and the code says so', () => {
    // The normative rule lives in the LIBRARY, which is what the four repos vendor.
    // cli.js is the command; deriveStatus and its citation are in verify.js.
    const src = fs.readFileSync(path.join(ROOT, 'verify.js'), 'utf8');
    // UPDATED DELIBERATELY: this required the revocation statuses to be ABSENT, which was the
    // correct gate while only step 2 had shipped. Steps 3-5 have now landed across every public
    // verifier, so their presence is the intended state and their absence would be the regression.
    assert.match(src, /RECEIPT_FORMAT\.md .?7\.1/, 'the implementation must cite the normative rule');
    assert.match(src, /compromised_at/);
    // 10t-rv (2026-11-05): a revoked key is REVOKED_KEY at every signing time (row 2); UNDECIDABLE is no longer
    // returned, and the unanchored retired case has its own status (row 5).
    assert.doesNotMatch(src, /return 'REVOKED_KEY_UNDECIDABLE'/, 'row 2: no timestamp softens a revoked key');
    assert.match(src, /return issued >= retired \? 'KEY_RETIRED_AFTER_SIGNING' : 'RETIRED_KEY_UNANCHORED'/);
  });

  // 10t-rv (2026-11-05): out of the release gate. MEASURED before: this was the one test in the suite that called
  // the network (LIVE_KEYS above); offline it threw at fetch() and failed, and release.yml ran it on every tag,
  // so a server-side change could stop a correct release. It runs only when RV_LIVE_REGISTRY=1, which
  // .github/workflows/registry-watch.yml sets daily; otherwise it is a declared SKIP — not run, not passed.
  // When it runs, a transport failure is a failure, not a silent return.
  const LIVE = process.env.RV_LIVE_REGISTRY === '1';
  it('the live registry still publishes only statuses this verifier understands', {
    skip: LIVE ? false : 'live registry check — set RV_LIVE_REGISTRY=1 (registry-watch.yml runs it daily); NOT RUN, not passed',
  }, async () => {
    const res = await fetch(LIVE_KEYS, { headers: { Accept: 'application/json' } });
    assert.ok(res.ok, `GET ${LIVE_KEYS} → HTTP ${res.status}: the registry did not answer`);
    const doc = await res.json();
    // 1.1.8 (10s-d, 2026-11-05): "understands" is asked of the verifiers themselves, not of a hand list.
    // MEASURED: this compared each live status with ['active', 'retired'] while verify.js (deriveStatus
    // KNOWN_STATUSES) and verify.py already understood 'revoked' (REVOKED_KEY, exit 1), so the day the live
    // registry revoked 2026-07-k1 the gate failed on a status both verifiers handle. Now each live entry's
    // status (with its compromised_at / revoked_at) is put on the fixture key, run through both CLIs, and
    // must not come back UNKNOWN_KEY_STATUS — the fail-closed answer for a status a verifier does not know.
    const PY = process.env.PYTHON || 'python3';
    for (const k of doc.keys || []) {
      const extra = {};
      for (const f of ['compromised_at', 'revoked_at', 'retired_at', 'valid_from']) if (k[f] !== undefined) extra[f] = k[f];
      const keys = registryWith(String(k.status), extra);
      for (const [label, r] of [['cli.js', run('node', ['cli.js', RECEIPT, '--keys', keys])], ['verify.py', run(PY, ['verify.py', RECEIPT, '--keys', keys])]]) {
        assert.notEqual(r.status, 'UNKNOWN_KEY_STATUS',
          `live registry publishes status "${k.status}" — ${label} does not understand it; every verifier must learn it BEFORE it ships`);
      }
    }
  });
});
