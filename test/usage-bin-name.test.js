'use strict';

/*
 * T19 (2026-10-06): the usage text names the command a user runs. Since 1.1.0 that is the npm bin
 * `coderifts-receipt-verifier` (`npx @coderifts/receipt-verifier …`); the text said `node cli.js`, a
 * command that exists only inside a clone. Measured before: `--help` printed three `node cli.js` lines.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const CLI = path.join(__dirname, '..', 'cli.js');
const pkg = require('../package.json');

function help(args = ['--help']) {
  const env = { ...process.env };
  delete env.CODERIFTS_API_KEY;
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', env });
  return { code: r.status, text: `${r.stdout}${r.stderr}` };
}

describe('the usage text names the bin', () => {
  it('the bin in package.json is the name the text uses', () => {
    assert.deepEqual(Object.keys(pkg.bin), ['coderifts-receipt-verifier']);
  });

  it('--help names coderifts-receipt-verifier for all three forms, and never `node cli.js`', () => {
    const { code, text } = help();
    assert.equal(code, 2);
    assert.match(text, /usage: coderifts-receipt-verifier <receipt>/);
    assert.match(text, /coderifts-receipt-verifier --chain receipts\.txt/);
    assert.match(text, /coderifts-receipt-verifier --from-commit <sha>/);
    assert.doesNotMatch(text, /node cli\.js/);
  });

  it('a usage error prints the same text', () => {
    const { code, text } = help(['--from-commit']);
    assert.equal(code, 2);
    assert.match(text, /usage: coderifts-receipt-verifier/);
    assert.doesNotMatch(text, /node cli\.js/);
  });
});
