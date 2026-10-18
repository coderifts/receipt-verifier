'use strict';

/*
 * 1.1.4 (2026-10-18) — the receipt verdict names its limits.
 * MEASURED on 1.1.3: `cli.js <token>` printed verifyReceipt's result verbatim, with no does_not_prove,
 * while the bundle (verify-bundle.js:140), attestation (verify-atomic-attestation.js:198) and DSSE
 * (to-dsse.js:158) verdicts carry their own. The sentences are the published ones, verbatim:
 * README.md "What it does NOT prove" and the receipt scope of the app / SDK.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'cli.js');
const { RECEIPT_DOES_NOT_PROVE } = require('../cli.js');
const TOKEN = fs.readFileSync(path.join(__dirname, 'fixtures-receipt.txt'), 'utf8').trim();
const KEYS = path.join(__dirname, 'fixtures-keys.json');
const run = (args) => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });

describe('1.1.4 · the receipt verdict carries does_not_prove', () => {
  it('⚠ a verified receipt → does_not_prove with exactly the published sentences, appended last', () => {
    const r = run([TOKEN, '--keys', KEYS]);
    const v = JSON.parse(r.stdout);
    assert.deepEqual(v.does_not_prove, [...RECEIPT_DOES_NOT_PROVE]);
    assert.equal(Object.keys(v).at(-1), 'does_not_prove');
    assert.equal(v.does_not_prove.length, 4);
  });
  it('a refused receipt carries it too (a limit is not only for a pass)', () => {
    const env = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'rv-dnp-')), 'env.json');
    fs.writeFileSync(env, '{}');
    const v = JSON.parse(run([TOKEN, '--keys', KEYS, '--envelope', env]).stdout);
    assert.equal(v.status, 'RECEIPT_VERSION_UNSUPPORTED');
    assert.deepEqual(v.does_not_prove, [...RECEIPT_DOES_NOT_PROVE]);
  });
  it('--json and plain output are the same document', () => {
    assert.equal(run([TOKEN, '--keys', KEYS, '--json']).stdout, run([TOKEN, '--keys', KEYS]).stdout);
  });
  it('the sentences are the published ones: README "What it does NOT prove", and the SDK / app receipt scope', () => {
    const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8').replace(/\*\*/g, '').replace(/\s+/g, ' ');
    assert.ok(readme.includes(RECEIPT_DOES_NOT_PROVE[0]), 'README.md no longer carries the first sentence verbatim');
    const sdk = path.join(ROOT, '..', 'sdk', 'src', 'verify-receipt-local.ts');
    if (fs.existsSync(sdk)) {
      const text = fs.readFileSync(sdk, 'utf8').replace(/'\s*\+\s*'/g, '').replace(/\\'/g, "'");
      for (const s of RECEIPT_DOES_NOT_PROVE.slice(1)) assert.ok(text.includes(s), `sdk wording drifted: ${s.slice(0, 60)}`);
    }
  });
  it('negative control: the bundle, attestation and DSSE verdicts keep their own lists (no receipt list spliced in)', () => {
    for (const f of ['verify-bundle.js', 'verify-atomic-attestation.js', 'to-dsse.js']) {
      const src = fs.readFileSync(path.join(ROOT, f), 'utf8');
      assert.ok(/does_not_prove/.test(src), `${f} has no does_not_prove of its own`);
      assert.equal(src.includes('RECEIPT_DOES_NOT_PROVE'), false, `${f} took the receipt list`);
    }
  });
  it('negative control: a --chain verdict keeps its shape (no does_not_prove added)', () => {
    const chain = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'rv-dnp-chain-')), 'chain.txt');
    fs.writeFileSync(chain, `${TOKEN}\n`);
    const v = JSON.parse(run(['--chain', chain, '--keys', KEYS]).stdout);
    assert.ok(v.chain);
    assert.equal('does_not_prove' in v, false);
  });
});
