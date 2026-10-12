'use strict';

/*
 * 1.1.1 / P66 (2026-10-12).
 *  (a) A receipt used as an authorization (with an envelope, or read off a commit) must be v4. MEASURED
 *      before (audit probe p1b): a signed v1–v3 token + a hand-written envelope → VERIFIED_CURRENT.
 *  (b) A signed field is a string or absent. MEASURED before (audit-2 F6): `expires_at: [...]` skipped the
 *      '|' guard and the v4 expiry check, and an expired receipt verified VERIFIED_CURRENT.
 */
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');
const { verifyReceipt, canonicalJson, sha256hex } = require('../verify.js');

const b64 = (b) => Buffer.from(b).toString('base64url');
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const KID = 'test-p66';
const keyring = new Map([[KID, { kid: KID, status: 'active', publicKey }]]);
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'p66-rv-'));
const KEYS = path.join(dir, 'keys.json');
fs.writeFileSync(KEYS, JSON.stringify({ keys: [{ kid: KID, status: 'active', public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }) }] }));
const sign = (p, input) => `${b64(JSON.stringify(p))}.${b64(crypto.sign(null, Buffer.from(input, 'utf8'), privateKey))}`;
function v2() {
  const p = { v: 2, kid: KID, fp: 'sha256:' + 'a'.repeat(64), prev: 'null', caller: 'anon', ts: '2026-10-01T00:00:00.000Z', reg: 'r'.repeat(64) };
  return sign(p, `crchain.v1|${p.kid}|${p.fp}|${p.prev}|${p.caller}|${p.ts}|${p.reg}`);
}
const bh = (env) => { const r = { ...env }; delete r.receipt; delete r.decision_body_hash; return 'sha256:' + sha256hex(canonicalJson(r)); };
function v4(env, expiresAt) {
  const p = { v: 4, kid: KID, fp: 'sha256:' + 'a'.repeat(64), prev: 'null', caller: 'api', ts: '2026-10-01T00:00:00.000Z', reg: '', ir: '', expires_at: expiresAt, bh: bh(env) };
  return sign(p, `crchain.v1|${p.kid}|${p.fp}|${p.prev}|${p.caller}|${p.ts}|${p.reg}|${p.ir}|${p.expires_at}|${p.bh}`);
}
const cli = (args) => spawnSync(process.execPath, [path.join(__dirname, '..', 'cli.js'), ...args], { encoding: 'utf8', env: { ...process.env, CODERIFTS_API_KEY: '' } });

describe('1.1.1 · a v<4 receipt is not an authorization', () => {
  it('⚠⚠ a signed v2 token + a hand-written envelope → RECEIPT_VERSION_UNSUPPORTED (was VERIFIED_CURRENT)', () => {
    const envFile = path.join(dir, 'env.json');
    fs.writeFileSync(envFile, JSON.stringify({ execution_action: 'CONTINUE', operation: 'merge', decision_id: 'forged' }));
    const r = cli([v2(), '--keys', KEYS, '--envelope', envFile]);
    assert.equal(r.status, 1, r.stdout + r.stderr);
    const out = JSON.parse(r.stdout);
    assert.equal(out.status, 'RECEIPT_VERSION_UNSUPPORTED');
    assert.equal(out.signature_status, 'VERIFIED_CURRENT');
  });

  it('control: the same v2 token pasted bare is still a signature check (VERIFIED_CURRENT)', () => {
    const r = cli([v2(), '--keys', KEYS]);
    assert.equal(JSON.parse(r.stdout).status, 'VERIFIED_CURRENT');
  });

  it('control: a v4 receipt bound to its envelope verifies', () => {
    const env = { execution_action: 'CONTINUE', operation: 'merge' };
    const envFile = path.join(dir, 'env4.json');
    fs.writeFileSync(envFile, JSON.stringify(env));
    const r = cli([v4(env, '2099-01-01T00:00:00.000Z'), '--keys', KEYS, '--envelope', envFile]);
    assert.equal(r.status, 0, r.stdout + r.stderr);
  });
});

describe('1.1.1 · a signed field is a string or absent', () => {
  it('⚠⚠ expires_at as an array → MALFORMED non_string_signed_field (an expired receipt verified before)', () => {
    const env = { execution_action: 'CONTINUE' };
    const res = verifyReceipt(v4(env, ['2020-01-01T00:00:00Z']), { ctx: { keyring, expectedKid: null }, envelope: env });
    assert.equal(res.valid, false);
    assert.equal(res.status, 'MALFORMED');
    assert.equal(res.reason, 'non_string_signed_field');
    assert.equal(res.field, 'expires_at');
  });

  it('Python parity: verify.py refuses the same token the same way', (t) => {
    const env = { execution_action: 'CONTINUE' };
    const tok = v4(env, ['2020-01-01T00:00:00Z']);
    const pem = publicKey.export({ type: 'spki', format: 'pem' });
    const py = `
import json, sys
sys.path.insert(0, ${JSON.stringify(path.join(__dirname, '..'))})
import verify
from cryptography.hazmat.primitives.serialization import load_pem_public_key
k = load_pem_public_key(${JSON.stringify(pem)}.encode())
r = verify.verify_receipt(${JSON.stringify(tok)}, {"keyring": {${JSON.stringify(KID)}: {"kid": ${JSON.stringify(KID)}, "status": "active", "public_key": k}}, "expected_kid": None}, {"envelope": ${JSON.stringify(env)}})
print(json.dumps({"valid": r["valid"], "status": r["status"], "reason": r.get("reason")}))
`;
    let out;
    try { out = execFileSync('python3', ['-c', py], { encoding: 'utf8' }); } catch (e) { t.skip(`python verifier not runnable here: ${String(e.message).split('\n')[0]}`); return; }
    assert.deepEqual(JSON.parse(out.trim()), { valid: false, status: 'MALFORMED', reason: 'non_string_signed_field' });
  });
});
