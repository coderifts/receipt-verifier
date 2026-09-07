'use strict';

/**
 * cr.exec.v1 optional signed fields — a DELIBERATE widening, recorded (1470).
 *
 * ── REPRODUCED ──────────────────────────────────────────────────────────────────────────────
 *
 * The allowed set was `['v', ...SIGNED_FIELDS]`, so a v1 grant carrying `state_nonce` read
 * MALFORMED / unknown_field. That grant is not malformed: it is what the demo executor issues for
 * the ATOMIC profile, and capability-demo's middleware has signed and accepted it all along. This
 * core is vendored into five consumers, so all five refused a valid ATOMIC grant — fail-closed,
 * and wrong.
 *
 * ── WHAT WIDENING MEANS, AND WHAT IT DOES NOT ───────────────────────────────────────────────
 *
 * BY NAME, not opened. These two fields are SIGNED — appended to the preimage — so a forger cannot
 * add one without breaking the signature. The closed set never protected against injection; it
 * protects against SEMANTIC DRIFT, a future field that RESTRICTS use being silently ignored by an
 * older verifier that then says GRANT_CURRENT. `state_nonce` and `deployment_id` NARROW rather than
 * restrict, so ignoring them is not more permissive than not knowing them.
 *
 * Both halves are pinned here — the admitted names AND the still-refused unknown — so the next
 * change to this set is a decision and not a rediscovery.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { verifyExecutionGrant, V1_OPTIONAL_SIGNED_FIELDS } = require('../verify-grant.js');

const b64 = (o) => Buffer.from(JSON.stringify(o), 'utf8').toString('base64url');
const key = crypto.generateKeyPairSync('ed25519');
const RING = new Map([['I', {
  publicKey: key.publicKey, status: 'active', retired_at: null, compromised_at: null,
}]]);

/** Signed exactly as capability-demo's middleware signs: optional slots appended when non-empty. */
function grant(extra = {}, signWith = key.privateKey) {
  const b = {
    v: 'cr.exec.v1', kid: 'I', receipt_digest: 'sha256:r', scope_hash: 'sha256:s', audience: 'a',
    operation: 'merge', target_id: 't', jti: 'J',
    iat: '2026-01-01T00:00:00Z', exp: '2099-01-01T00:00:00Z', ...extra,
  };
  const p = ['crexec.v1', b.kid, b.receipt_digest, b.scope_hash, b.audience, b.operation,
    b.target_id, b.jti, b.iat, b.exp];
  for (const k of ['state_nonce', 'deployment_id']) {
    if (b[k] != null && String(b[k]).length > 0) p.push(String(b[k]));
  }
  return `${b64(b)}.${crypto.sign(null, Buffer.from(p.join('|'), 'utf8'), signWith).toString('base64url')}`;
}
const ask = (t) => verifyExecutionGrant(t, { ctx: { keyring: RING, expectedKid: null } });

describe('cr.exec.v1 — the optional ATOMIC fields', () => {
  it('the widening is BY NAME: exactly state_nonce and deployment_id', () => {
    assert.deepEqual([...V1_OPTIONAL_SIGNED_FIELDS], ['state_nonce', 'deployment_id']);
  });

  it('a BEARER grant is unchanged — pre-ATOMIC issuances must still verify', () => {
    // The slots are appended only when non-empty, so a grant with neither has a byte-identical
    // signing input to what it had before ATOMIC existed. Widening that broke these would be a
    // silent break for every grant already issued.
    assert.equal(ask(grant()).status, 'GRANT_CURRENT');
  });

  it('REPRODUCED THEN CLOSED: a v1 ATOMIC grant verifies', () => {
    assert.equal(ask(grant({ state_nonce: 'n' })).status, 'GRANT_CURRENT');
    assert.equal(ask(grant({ state_nonce: 'n', deployment_id: 'd' })).status, 'GRANT_CURRENT');
  });

  it('THE SET IS STILL CLOSED: an actually-unknown field is refused', () => {
    const r = ask(grant({ surprise: 'x' }));
    assert.equal(r.valid, false);
    assert.equal(r.reason, 'unknown_field');
  });

  it('the optional fields are SIGNED — a forged one breaks the signature', () => {
    // This is why widening is safe: the closed set was never what stopped injection.
    const honest = grant({ state_nonce: 'n' });
    const [payload, sig] = honest.split('.');
    const body = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    body.state_nonce = 'n-TAMPERED';
    const forged = `${b64(body)}.${sig}`;
    const r = ask(forged);
    assert.equal(r.valid, false);
    assert.equal(r.status, 'INVALID_SIGNATURE');
  });

  it('a non-string optional field is MALFORMED, not coerced', () => {
    const b = JSON.parse(Buffer.from(grant().split('.')[0], 'base64url').toString('utf8'));
    b.state_nonce = 7;
    const r = ask(`${b64(b)}.${grant().split('.')[1]}`);
    assert.equal(r.valid, false);
    assert.equal(r.status, 'MALFORMED');
  });

  it('BYTE-PARITY with capability-demo\'s middleware, when it is beside this repo', (t) => {
    // The two implementations must agree on the SAME token, or a grant that the executor accepts
    // is one the shared core refuses — which is the bug this test exists to keep closed.
    const mw = path.join(process.env.HOME || '', 'capability-demo', 'packages', 'middleware', 'src', 'verify-grant.js');
    if (!fs.existsSync(mw)) {
      t.skip('capability-demo is not checked out beside this repo — core behaviour was verified, '
        + 'cross-implementation parity was not');
      return;
    }
    // eslint-disable-next-line global-require, import/no-dynamic-require
    const demo = require(mw);
    for (const extra of [{}, { state_nonce: 'n' }, { state_nonce: 'n', deployment_id: 'd' }]) {
      const token = grant(extra);
      const mine = ask(token);
      const theirs = demo.verifyExecutionGrant(token, {
        publicKey: key.publicKey, keyKid: 'I', keyStatus: 'active',
      });
      assert.equal(mine.valid, theirs.valid,
        `the core and the middleware disagree on ${JSON.stringify(extra)}: `
        + `${mine.status} vs ${theirs.status}`);
    }
  });
});
