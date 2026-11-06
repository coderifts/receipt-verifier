'use strict';

/*
 * 10t-rv (2026-11-05) — scripts/registry-watch.js, offline: its comparison on bytes, no fetch.
 * The pinned snapshot passes; a changed byte, a changed 2026-07-k1 status or compromised_at, and a missing kid fail.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { compare, pinnedSha256 } = require('../scripts/registry-watch.js');

const PIN = fs.readFileSync(path.join(__dirname, '..', 'keys', 'coderifts-keys.json'));
const doc = () => JSON.parse(PIN.toString('utf8'));

describe('registry-watch compare (offline)', () => {
  it('the pinned snapshot is its own match, and its sha256 is the one keys/coderifts-keys.json.sha256 names', () => {
    assert.equal(pinnedSha256(), 'abf16e94c9a317dc9fed5651ae7a0e3c8d3a9bc03834002aebce3b70364c8957');
    assert.deepEqual(compare(PIN).findings, []);
  });

  it('one byte more (a trailing newline) is red on the hash alone', () => {
    const f = compare(Buffer.concat([PIN, Buffer.from('\n')])).findings;
    assert.equal(f.length, 1);
    assert.match(f[0], /^sha256 /);
  });

  for (const [what, mutate, expect] of [
    ['2026-07-k1 back to retired', (d) => { d.keys.find((k) => k.kid === '2026-07-k1').status = 'retired'; }, /2026-07-k1\.status is "retired"/],
    ['compromised_at moved', (d) => { d.keys.find((k) => k.kid === '2026-07-k1').compromised_at = '2026-08-01T00:00:00.000Z'; }, /2026-07-k1\.compromised_at/],
    ['2026-07-k1 removed', (d) => { d.keys = d.keys.filter((k) => k.kid !== '2026-07-k1'); }, /2026-07-k1 is not in the registry/],
  ]) {
    it(`${what} → red, named`, () => {
      const d = doc(); mutate(d);
      const f = compare(Buffer.from(JSON.stringify(d))).findings;
      assert.ok(f.some((x) => expect.test(x)), JSON.stringify(f));
    });
  }
});
