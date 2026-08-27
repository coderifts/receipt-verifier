'use strict';

/**
 * 1133 — a missing app checkout must FAIL LOUD, never skip.
 *
 * THE DEFECT, measured: all three cross-check harnesses resolved CODERIFTS_APP_DIR (or
 * $HOME/coderifts-app) and, when absent, printed "— skip" and exited 0. run.sh checks the exit
 * code explicitly, so this was not a swallowed failure — it was a FABRICATED PASS:
 *
 *   ok    cross-check-grant (js == app kernel on EG-*)
 *
 * printed for a comparison that never ran. And the CI workflow checks out this repository only,
 * so $HOME/coderifts-app does not exist there: the js==app-kernel half of the independence claim
 * had never actually executed in CI.
 *
 * Same silent-skip class as the third-argument trap (1128) and the app's own "must NOT skip"
 * vendored-sync rule. An absent comparison must never be reported as a passing one.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

// DISCOVERED, not listed. A hand-maintained list is the same defect one level up: the next
// harness gets added, nobody adds it here, and it is never checked for the silent-skip shape --
// the guard would still print all-green while covering a subset. MEASURED 2026-08-27: this list
// said grant/attest/toolset while cross-check-monitor.js existed unguarded.
// `.test.js` is EXCLUDED deliberately: this file is itself named cross-check-*.js, and without
// the exclusion the loops below spawn this file, which spawns itself, without limit. Measured the
// hard way.
const HARNESSES = fs.readdirSync(__dirname)
  .filter((f) => /^cross-check-.*\.js$/.test(f) && !/\.test\.js$/.test(f))
  .map((f) => f.replace(/\.js$/, ''))
  .sort();

// An empty or shrunken glob would make every `for (const h of HARNESSES)` loop below pass
// vacuously -- zero iterations, zero assertions, all green. Pin the floor and the membership.
describe('the guard actually covers every harness', () => {
  it('discovers at least the four known cross-checks', () => {
    assert.ok(HARNESSES.length >= 4,
      `discovered only ${HARNESSES.length} harnesses (${HARNESSES.join(', ')}) -- `
      + 'a shrunken glob makes every loop in this file iterate zero times and pass vacuously');
  });
  it('covers each envelope that has an app kernel', () => {
    for (const want of ['grant', 'attest', 'toolset', 'monitor']) {
      assert.ok(HARNESSES.includes(`cross-check-${want}`),
        `cross-check-${want} is not covered by the silent-skip guard`);
    }
  });
});

const runWith = (harness, appDir) => spawnSync(
  process.execPath,
  [path.join(__dirname, `${harness}.js`)],
  { encoding: 'utf8', env: { ...process.env, CODERIFTS_APP_DIR: appDir } },
);

describe('a missing app kernel fails loud in EVERY cross-check', () => {
  for (const h of HARNESSES) {
    it(`${h} exits NON-ZERO when the checkout is absent`, () => {
      const r = runWith(h, '/nonexistent-app-checkout');
      assert.notEqual(r.status, 0,
        `${h} exited ${r.status} — a skip here is reported by run.sh as a passing comparison`);
      assert.equal(r.status, 1);
    });

    it(`${h} names the reason and the remedy`, () => {
      const r = runWith(h, '/nonexistent-app-checkout');
      const out = `${r.stdout}${r.stderr}`;
      assert.match(out, /app kernel not found at \/nonexistent-app-checkout/);
      assert.match(out, /set CODERIFTS_APP_DIR/,
        'an error without a remedy makes the next person guess');
    });

    it(`${h} does not print the word "skip" as an outcome`, () => {
      // The old line was `… — skip` on stdout with exit 0. If that shape ever returns, run.sh
      // starts printing a green "ok" for a comparison that did not happen.
      const r = runWith(h, '/nonexistent-app-checkout');
      assert.equal(/— skip/.test(`${r.stdout}${r.stderr}`), false);
    });
  }

  it('the refusal explains WHY skipping is worse than having no harness', () => {
    const r = runWith('cross-check-grant', '/nonexistent-app-checkout');
    assert.match(`${r.stderr}`, /reporting a comparison that did not happen is worse/);
  });
});

describe('the successful path is unchanged', () => {
  for (const h of HARNESSES) {
    it(`${h} still exits 0 and reports agreement when the checkout is present`, () => {
      const r = spawnSync(process.execPath, [path.join(__dirname, `${h}.js`)], { encoding: 'utf8' });
      // Skipped only if the developer genuinely has no app checkout — in which case the guard
      // above is the thing under test and this assertion cannot be meaningful.
      if (r.status === 1 && /app kernel not found/.test(r.stderr)) return;
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /agree with app kernel/);
    });
  }
});
