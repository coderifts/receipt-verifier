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

/**
 * 1127 — ONE harness now has a third, honest state, and the invariant is narrowed rather than
 * dropped.
 *
 * The rule 1133 installed is "an absent comparison must never be reported as a passing one." A
 * skip broke it by asserting an agreement nobody had tested. cross-check-toolset now falls back to
 * RECORDED kernel verdicts (test/toolset-kernel-verdicts.json), which does NOT break it: the
 * comparison genuinely runs, against verdicts the kernel actually produced, pinned by
 * vectors_sha256 to the tokens they describe — and the output says [RECORDED] so no reader mistakes
 * it for the live check.
 *
 * The fallback is therefore held to a HARDER standard below than the plain refusal it replaces:
 * it must refuse a fixture that does not describe these vectors, it must refuse when the fixture is
 * gone, and it must never print the LIVE line. Anything less would be the silent skip wearing a
 * fixture.
 */
const HAS_RECORDED_FALLBACK = new Set(['cross-check-toolset']);

const runWith = (harness, appDir) => spawnSync(
  process.execPath,
  [path.join(__dirname, `${harness}.js`)],
  { encoding: 'utf8', env: { ...process.env, CODERIFTS_APP_DIR: appDir } },
);

describe('a missing app kernel fails loud in EVERY cross-check', () => {
  for (const h of HARNESSES.filter((x) => !HAS_RECORDED_FALLBACK.has(x))) {
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

  }

  // EVERY harness, fallback included — the word must never appear as an outcome.
  for (const h of HARNESSES) {
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

/**
 * Is a LIVE app kernel reachable?
 *
 * MEASURED (1331): the stderr guard `/app kernel not found/` does NOT catch cross-check-toolset,
 * because that harness has a RECORDED fallback — with no checkout it exits 0 and prints
 * `[RECORDED …]` instead of failing. So three tests below asserted live-kernel text against a
 * RECORDED run and failed on the public HEAD, where no checkout exists. The mode is on the success
 * line by design (1127); read it there rather than inferring it from an error that never comes.
 */
function liveKernel(harness) {
  const r = spawnSync(process.execPath, [path.join(__dirname, `${harness}.js`)], { encoding: 'utf8' });
  return {
    ...r,
    live: r.status === 0 && /\[LIVE\]|agree with app kernel(?! verdicts)/.test(r.stdout),
    recorded: /\[RECORDED/.test(r.stdout),
  };
}

describe('the successful path is unchanged', () => {
  for (const h of HARNESSES) {
    it(`${h} still exits 0 and reports agreement when the checkout is present`, () => {
      const r = liveKernel(h);
      // Skipped only if the developer genuinely has no app checkout — in which case the guard
      // above is the thing under test and this assertion cannot be meaningful.
      if (r.status === 1 && /app kernel not found/.test(r.stderr)) return;
      assert.equal(r.status, 0, r.stderr);
      // BOTH modes are a success; they are not the same success. A RECORDED run agrees with a
      // kernel pinned at a revision, and its own line says so. Demanding the LIVE wording here is
      // what made this red on the public HEAD, where no checkout exists.
      assert.match(r.stdout, /agree with (app kernel|RECORDED app-kernel verdicts)/);
      if (r.recorded) assert.match(r.stdout, /weaker than LIVE/,
        'a RECORDED run must say it is the weaker of the two');
    });
  }
});

describe('1127 — the RECORDED fallback is held to a harder standard than the refusal it replaces',
  () => {
    const H = 'cross-check-toolset';
    const FIXTURE = path.join(__dirname, 'toolset-kernel-verdicts.json');
    const VECTORS = path.join(__dirname, 'toolset-vectors.json');

    it('runs the comparison without the app and says which kernel it compared against', () => {
      const r = runWith(H, '/nonexistent-app-checkout');
      assert.equal(r.status, 0, `${r.stdout}${r.stderr}`);
      assert.match(r.stdout, /\[RECORDED/, 'the mode must be on the success line');
      assert.match(r.stdout, /weaker than LIVE/, 'a weaker check must say so where it is read');
      assert.match(r.stdout, /public==kernel==/, 'the per-vector comparison must actually run');
    });

    it('NEVER prints the LIVE line when the checkout is absent', () => {
      const r = runWith(H, '/nonexistent-app-checkout');
      assert.equal(/\[LIVE\]/.test(r.stdout), false,
        'a recorded comparison reported as the live one is the 1133 defect with extra steps');
    });

    it('the run NAMES its mode, and the two are never confused', () => {
      // The property is that the mode is always stated — not that it is always LIVE. On the public
      // HEAD there is no checkout, so this harness runs RECORDED, and demanding [LIVE] here made a
      // correct RECORDED run look like a failure.
      const r = liveKernel(H);
      if (r.status === 1 && /app kernel not found/.test(r.stderr)) return; // no local checkout
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /\[LIVE\]|\[RECORDED/, 'the success line does not name the mode');
      // And never both: a line claiming each would tell a reader nothing.
      assert.equal(/\[LIVE\]/.test(r.stdout) && /\[RECORDED/.test(r.stdout), false);
    });

    it('REFUSES a fixture that does not describe these vectors', () => {
      // The binding that stops this from being theatre. Recorded verdicts are about specific
      // tokens; the vectors carry an ephemeral key, so a regeneration changes every one of them.
      const original = fs.readFileSync(FIXTURE, 'utf8');
      const doc = JSON.parse(original);
      doc.vectors_sha256 = 'sha256:' + '0'.repeat(64);
      fs.writeFileSync(FIXTURE, `${JSON.stringify(doc, null, 2)}\n`);
      try {
        const r = runWith(H, '/nonexistent-app-checkout');
        assert.equal(r.status, 1, 'a fixture describing other tokens must not be compared against');
        assert.match(`${r.stdout}${r.stderr}`, /do not describe these vectors/);
        assert.match(`${r.stdout}${r.stderr}`, /gen-toolset-kernel-verdicts/, 'name the remedy');
      } finally {
        fs.writeFileSync(FIXTURE, original);
      }
    });

    it('REFUSES when the fixture is gone — no checkout and no recording is still a refusal', () => {
      const original = fs.readFileSync(FIXTURE, 'utf8');
      fs.rmSync(FIXTURE);
      try {
        const r = runWith(H, '/nonexistent-app-checkout');
        assert.equal(r.status, 1);
        assert.match(`${r.stderr}`, /no recorded verdicts/);
        assert.match(`${r.stderr}`, /reporting a comparison that did not happen is worse/);
      } finally {
        fs.writeFileSync(FIXTURE, original);
      }
    });

    it('a vector with no recorded verdict FAILS rather than passing unexamined', () => {
      // Otherwise adding a vector silently shrinks what CI compares.
      const original = fs.readFileSync(FIXTURE, 'utf8');
      const doc = JSON.parse(original);
      doc.verdicts = doc.verdicts.slice(1);
      fs.writeFileSync(FIXTURE, `${JSON.stringify(doc, null, 2)}\n`);
      try {
        const r = runWith(H, '/nonexistent-app-checkout');
        assert.equal(r.status, 1, 'a missing recording must not be silently skipped');
        assert.match(r.stdout, /NO_RECORDED_VERDICT_FOR_/);
      } finally {
        fs.writeFileSync(FIXTURE, original);
      }
    });

    it('the LIVE run catches a STALE recording, so drift cannot be carried into CI', () => {
      // REQUIRES A LIVE KERNEL, and now says so. Poisoning kernel_sha256 and expecting STALE only
      // means something when there is a real kernel to disagree with it; in RECORDED mode the
      // poisoned value IS the only kernel, so nothing can detect the drift. Running this without a
      // checkout asserted a comparison that was not happening — the 1331 defect.
      const r0 = liveKernel(H);
      if (!r0.live) return;   // RECORDED or absent: this test has nothing to compare against
      const original = fs.readFileSync(FIXTURE, 'utf8');
      const doc = JSON.parse(original);
      doc.kernel_sha256 = 'sha256:' + 'f'.repeat(64);
      fs.writeFileSync(FIXTURE, `${JSON.stringify(doc, null, 2)}\n`);
      try {
        const r = spawnSync(process.execPath, [path.join(__dirname, `${H}.js`)], { encoding: 'utf8' });
        assert.equal(r.status, 1);
        assert.match(r.stdout, /STALE/);
      } finally {
        fs.writeFileSync(FIXTURE, original);
      }
    });

    it('the recorded vectors_sha256 describes the vectors file as it stands', () => {
      const { sha256 } = require('./gen-toolset-kernel-verdicts.js');
      const rec = JSON.parse(fs.readFileSync(FIXTURE, 'utf8'));
      assert.equal(rec.vectors_sha256, sha256(fs.readFileSync(VECTORS)));
    });

    it('the fixture states what it does NOT prove', () => {
      const rec = JSON.parse(fs.readFileSync(FIXTURE, 'utf8'));
      assert.match(rec.does_not_prove, /as it stands now/);
      assert.match(rec.proves, /AS OF/);
    });
  });
