'use strict';
/**
 * 1079 B — key lifecycle timestamps (retired_at / revoked_at), ADDITIVE.
 *
 * Signing time is payload.ts (receipts have no iat). Vectors are generated into
 * test/vectors.json lifecycle[] by test/gen-vectors.js.
 */
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const doc = require('./vectors.json');

function run(bin, script, token, registry) {
  const keysPath = path.join(os.tmpdir(), `lc-${process.pid}-${Math.random().toString(16).slice(2)}.json`);
  fs.writeFileSync(keysPath, JSON.stringify(registry));
  try {
    return JSON.parse(execFileSync(bin, [script, token, '--keys', keysPath], { cwd: ROOT, encoding: 'utf8' }));
  } catch (err) {
    if (err && typeof err.stdout === 'string' && err.stdout.trim()) return JSON.parse(err.stdout);
    throw err;
  } finally {
    fs.rmSync(keysPath, { force: true });
  }
}

describe('1079 B key lifecycle (js + py)', () => {
  assert.ok(doc.lifecycle && Array.isArray(doc.lifecycle.vectors), 'lifecycle vectors missing — run node test/gen-vectors.js');

  for (const v of doc.lifecycle.vectors) {
    for (const [label, bin, script] of [['cli.js', 'node', 'cli.js'], ['verify.py', 'python3', 'verify.py']]) {
      it(`${label} ${v.name}: valid=${v.expected.valid} status=${v.expected.status}`, () => {
        const out = run(bin, script, v.token, v.registry);
        assert.equal(out.valid, v.expected.valid, `${v.name} valid`);
        assert.equal(out.status, v.expected.status, `${v.name} status`);
        if (v.expected.reason) assert.equal(out.reason, v.expected.reason, `${v.name} reason`);
      });
    }
  }

  it('ADDITIVE: old-shape entry (no retired_at, no revoked_at) is VERIFIED_CURRENT', () => {
    const v = doc.lifecycle.vectors.find((x) => x.name === 'EG-NO-LIFECYCLE');
    const keys = v.registry.keys[0];
    assert.equal(Object.prototype.hasOwnProperty.call(keys, 'retired_at'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(keys, 'revoked_at'), false);
    const js = run('node', 'cli.js', v.token, v.registry);
    assert.equal(js.valid, true);
    assert.equal(js.status, 'VERIFIED_CURRENT');
  });

  it('REVOKED is retroactive: ts BEFORE revoked_at is still KEY_REVOKED', () => {
    const v = doc.lifecycle.vectors.find((x) => x.name === 'EG-REVOKED-ANY');
    const [bodyB64] = v.token.split('.');
    const payload = JSON.parse(Buffer.from(bodyB64, 'base64url').toString('utf8'));
    assert.ok(Date.parse(payload.ts) < Date.parse(v.registry.keys[0].revoked_at),
      'the vector must sign BEFORE revoked_at or it does not prove retroactivity');
    const js = run('node', 'cli.js', v.token, v.registry);
    assert.equal(js.status, 'KEY_REVOKED');
    assert.equal(js.valid, false);
  });
});
