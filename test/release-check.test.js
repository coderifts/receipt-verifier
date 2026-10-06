'use strict';

/**
 * The npm release check (T18, 2026-10-06). @coderifts/receipt-verifier was never published: every
 * CodeRifts App comment tells its reader to run `npx @coderifts/receipt-verifier`, and npm answered
 * 404 (measured). These tests hold the checks that stand between this tree and a publish:
 *   - the vendored keyring must match its pinned .sha256 (a tampered copy fails);
 *   - the version must match the tag and have a CHANGELOG heading (v1.0.3 shipped package.json 1.0.2);
 *   - the tarball must hold every file the CLI and the exports load (a tarball without the keyring
 *     fails, by name) and nothing from test/;
 *   - the installed package verifies the fixture and reproduces P58.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { checkKeyringDigest, checkVersion, requiredFiles, checkTarballFiles, releaseCheck } = require('../scripts/release-check.js');

const ROOT = path.join(__dirname, '..');

/** A copy of the working tree (no .git), for checks that must fail on a broken variant. */
function copyTree() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rv-release-test-'));
  fs.cpSync(ROOT, dir, { recursive: true, filter: (src) => !/[/\\](\.git|node_modules|\.pytest_cache)([/\\]|$)/.test(src) });
  return dir;
}

describe('release check · the keyring', () => {
  it('the shipped keyring matches its .sha256', () => {
    assert.equal(checkKeyringDigest(ROOT).ok, true);
  });
  it('a keyring changed by one byte fails, naming both digests', () => {
    const dir = copyTree();
    try {
      const f = path.join(dir, 'keys', 'coderifts-keys.json');
      fs.writeFileSync(f, `${fs.readFileSync(f, 'utf8')} `);
      const r = checkKeyringDigest(dir);
      assert.equal(r.ok, false);
      assert.match(r.reason, /does not match the pinned/);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
});

describe('release check · the version', () => {
  it('package.json is 1.1.0, the tag v1.1.0 matches, and the CHANGELOG has the heading', () => {
    assert.deepEqual(checkVersion(ROOT, 'v1.1.0'), { ok: true, version: '1.1.0' });
  });
  it('a tag that is not the package version fails (v1.0.3 was tagged on package.json 1.0.2)', () => {
    const r = checkVersion(ROOT, 'v1.0.3');
    assert.equal(r.ok, false);
    assert.match(r.reason, /tag v1\.0\.3 is not v1\.1\.0/);
  });
});

describe('release check · the tarball', () => {
  const need = requiredFiles(ROOT);
  it('the run-time set is derived from the bin, the exports and their requires', () => {
    for (const f of ['cli.js', 'verify.js', 'arity.js', 'commit-binding.js', 'receipt-from-commit.js', 'verify-grant.js',
      'verify-evidence.js', 'evidence-root.js', 'verify-prove-transcript.js', 'keys/coderifts-keys.json', 'keys/coderifts-keys.json.sha256']) {
      assert.ok(need.includes(f), `${f} is required`);
    }
  });
  it('a file list without the keyring fails and names it; a test file is refused', () => {
    const r = checkTarballFiles(need.filter((f) => f !== 'keys/coderifts-keys.json').concat('test/run.sh'), need);
    assert.equal(r.ok, false);
    assert.deepEqual(r.missing, ['keys/coderifts-keys.json']);
    assert.deepEqual(r.forbidden, ['test/run.sh']);
  });
});

describe('release check · end to end (npm pack → offline install → the installed bin)', () => {
  it('passes on this tree: fixture VERIFIED_CURRENT through the bin and npx, P58 BOUND / RECEIPT_COMMIT_MISMATCH', () => {
    const r = releaseCheck({ root: ROOT, tag: 'v1.1.0' });
    assert.equal(r.ok, true, JSON.stringify(r.steps, null, 2));
    assert.ok(!r.files.some((f) => f.startsWith('test/')), 'no test file ships');
  });
  it('⚠ fails on a package whose `files` drops the keyring, at the tarball step, naming it', () => {
    const dir = copyTree();
    try {
      const pkgPath = path.join(dir, 'package.json');
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      pkg.files = pkg.files.filter((f) => f !== 'keys/coderifts-keys.json');
      fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2));
      const r = releaseCheck({ root: dir });
      assert.equal(r.ok, false);
      const failed = r.steps.find((s) => !s.ok);
      assert.equal(failed.name, 'tarball contents');
      assert.match(failed.detail, /keys\/coderifts-keys\.json/);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
});
