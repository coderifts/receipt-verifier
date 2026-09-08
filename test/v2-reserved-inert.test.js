'use strict';

/**
 * THE RESERVED FIELDS ARE INERT — proved, not intended.
 *
 * `call_hash` and `executor_image_digest` are admitted by the v2 verifier and read by nothing.
 * They exist so that the gate which will eventually use them is not a breaking change: the
 * admitted key set is closed, so a field introduced later would make every deployed verifier
 * refuse the grants that carry it.
 *
 * ── WHAT THIS FILE IS GUARDING AGAINST ──────────────────────────────────────────────────────
 *
 * Not a bug that exists. A future one, of a specific shape: somebody wires a check to
 * `payload.call_hash != null` and a grant becomes "tool-call bound" because a field is set. That
 * is the caller-boolean class this repository has closed twice already (a `signed: true` flag
 * believed because it was set; an `{present: true}` attestation graded on the boolean). A reserved
 * field is the same trap with a longer fuse, so the inertness is pinned the day the slot opens.
 *
 * The day a real gate lands, these tests SHOULD fail — and that failure is the acceptance test
 * for it, not an obstacle to it. What must never happen is presence quietly becoming proof.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const {
  verifyExecutionGrant, V2_REQUIRED_STRINGS, V2_RESERVED_INERT,
} = require('../verify-grant.js');

const KID = 'RESERVED-TEST-KEY';
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const RING = new Map([[KID, { publicKey, status: null }]]);
const NOW = Date.UTC(2026, 8, 9, 12, 0, 0);
const sha = (v) => `sha256:${crypto.createHash('sha256').update(String(v)).digest('hex')}`;

/** Canonical JSON, matching the v2 signing input the verifier rebuilds. */
const canon = (v) => {
  if (v === null) return 'null';
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`;
  if (typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(',')}}`;
  }
  return JSON.stringify(v);
};

const BODY = Object.freeze({
  v: 'cr.exec.v2',
  kid: KID,
  grant_id: 'g-reserved-1',
  receipt_hash: sha('receipt'),
  tenant_id: 'tenant',
  executor_id: 'executor',
  adapter_id: 'adapter',
  operation: 'publish',
  target_uri: 'db://host/table',
  expected_state_token: 'state',
  after_payload_hash: sha('the authorized bytes'),
  nonce_hash: sha('nonce'),
  policy_hash: sha('policy'),
  audience_hash: sha('audience'),
  not_before: new Date(NOW - 1000).toISOString(),
  expires_at: new Date(NOW + 600000).toISOString(),
  max_attempts: 1,
});

const mint = (over = {}) => {
  const body = { ...BODY, ...over };
  const sig = crypto.sign(null, Buffer.from(`crexec.v2|${canon(body)}`, 'utf8'), privateKey);
  return `${Buffer.from(JSON.stringify(body), 'utf8').toString('base64url')}.${sig.toString('base64url')}`;
};
const ask = (token, intended) => verifyExecutionGrant(token, {
  ctx: { keyring: RING, expectedKid: null }, now: NOW + 1, ...(intended ? { intended } : {}),
});
/** The whole answer, so a difference anywhere shows up rather than only in `valid`. */
const verdict = (r) => `${r.valid}/${r.status}/${r.reason || '-'}`;

const INTENDED = { operation: 'publish', target_uri: 'db://host/table', after_payload: 'the authorized bytes' };

describe('the reserved names are the two the schema documents', () => {
  it('exactly call_hash and executor_image_digest, and neither is required', () => {
    assert.deepEqual([...V2_RESERVED_INERT].sort(), ['call_hash', 'executor_image_digest']);
    for (const name of V2_RESERVED_INERT) {
      assert.ok(!V2_REQUIRED_STRINGS.includes(name),
        `${name} is reserved AND required — a reserved field that is mandatory is just a field`);
    }
  });
});

describe('ZERO BEHAVIOUR CHANGE for a grant that does not carry them', () => {
  it('an ordinary grant verifies exactly as before', () => {
    assert.equal(verdict(ask(mint(), INTENDED)), 'true/GRANT_CURRENT/-');
  });

  it('every refusal a grant could already earn is unchanged', () => {
    // The reserved names widened the admitted key set. If that had loosened anything else, these
    // are where it would show.
    assert.equal(verdict(ask(mint({ operation: 'deploy' }), INTENDED)),
      'false/GRANT_UNBOUND/operation_mismatch');
    assert.equal(verdict(ask(mint(), { ...INTENDED, after_payload: 'other bytes' })),
      'false/GRANT_UNBOUND/after_payload_mismatch');
    assert.equal(verdict(ask(mint({ target_uri: 'ftp://host/x' }))),
      'false/MALFORMED/bad_target_uri');
    assert.equal(verdict(ask(mint({ max_attempts: 0 }))), 'false/MALFORMED/bad_max_attempts');
  });

  it('an UNKNOWN field still fails closed — the set is still closed', () => {
    assert.equal(verdict(ask(mint({ surprise: 'x' }))), 'false/MALFORMED/unknown_field');
    // …including one that merely looks like a reserved name.
    assert.equal(verdict(ask(mint({ call_hash_v2: sha('x') }))), 'false/MALFORMED/unknown_field');
  });
});

describe('INERT: carrying them changes no verdict, anywhere', () => {
  const loaded = { call_hash: sha('a tool call'), executor_image_digest: sha('an image') };

  it('the same chain reaches the same verdict with and without them', () => {
    assert.equal(verdict(ask(mint(loaded), INTENDED)), verdict(ask(mint(), INTENDED)));
  });

  it('and the same is true of every refusal — they do not rescue a bad grant', () => {
    // The direction that matters. A field that could not make a passing grant fail might still
    // make a failing grant pass, and that is the one worth proving.
    for (const [name, over, intended] of [
      ['wrong operation', { operation: 'deploy' }, INTENDED],
      ['wrong bytes', {}, { ...INTENDED, after_payload: 'other bytes' }],
      ['expired', { expires_at: new Date(NOW - 60000).toISOString() }, INTENDED],
      ['bad target', { target_uri: 'ftp://host/x' }, INTENDED],
    ]) {
      assert.equal(verdict(ask(mint({ ...over, ...loaded }), intended)),
        verdict(ask(mint(over), intended)),
        `${name}: the reserved fields changed the verdict`);
    }
  });

  it('they reach no `intended` cross-check — asking for them is not a thing a caller can do', () => {
    // If a caller could pass `intended.call_hash` and have it compared, the field would already
    // be a gate. It is not: the extra intent is ignored, and the verdict is unchanged.
    assert.equal(
      verdict(ask(mint(loaded), { ...INTENDED, call_hash: sha('something else entirely') })),
      verdict(ask(mint(loaded), INTENDED)),
    );
  });
});

describe('PRESENCE IS NOT PROOF', () => {
  it('a grant missing a REQUIRED field is refused however many reserved fields it carries', () => {
    const stripped = { ...BODY, call_hash: sha('a tool call') };
    delete stripped.after_payload_hash;
    const sig = crypto.sign(null, Buffer.from(`crexec.v2|${canon(stripped)}`, 'utf8'), privateKey);
    const token = `${Buffer.from(JSON.stringify(stripped), 'utf8').toString('base64url')}.${sig.toString('base64url')}`;
    assert.equal(verdict(ask(token)), 'false/MALFORMED/missing_field');
  });

  it('a grant for the WRONG bytes is refused even carrying both reserved fields', () => {
    const r = ask(mint({ call_hash: sha('c'), executor_image_digest: sha('i') }),
      { ...INTENDED, after_payload: 'bytes nobody authorized' });
    assert.equal(r.valid, false);
    assert.equal(r.reason, 'after_payload_mismatch');
  });

  it('the values are arbitrary — nothing checks that they mean anything', () => {
    // The honest statement, asserted: an issuer can put a lie in these and the verifier cannot
    // tell, because it does not look. That is why presence must never be read as a gate.
    const nonsense = ask(mint({ call_hash: 'not-even-a-digest', executor_image_digest: '' }), INTENDED);
    assert.equal(nonsense.valid, true, 'a nonsense value was rejected — then it is NOT inert');
    assert.equal(nonsense.status, 'GRANT_CURRENT');
  });
});
