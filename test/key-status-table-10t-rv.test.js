'use strict';

/*
 * 10t-rv (2026-11-05) — the verifier's key-status table, in its normative order (RECEIPT_FORMAT §7.1).
 * One vector per row, through both CLIs (cli.js and verify.py), with the exit code the README states.
 *
 *   1. a status this verifier does not know              → UNKNOWN_KEY_STATUS, valid:false, exit 1
 *   2. revoked (at every signing time)                   → REVOKED_KEY, valid:false, exit 1, compromised_at in the result
 *   3. retired, signed at or after retired_at            → KEY_RETIRED_AFTER_SIGNING, valid:false, exit 1
 *   4. retired, signed before retired_at, WITH an anchor → RETIRED_KEY_VALID_AT_ISSUE — NOT BUILDABLE: this verifier
 *                                                          reads no independent time anchor (no RFC 3161 token, no
 *                                                          transparency-log inclusion); the test pins that absence
 *   5. retired, signed before retired_at, no anchor      → RETIRED_KEY_UNANCHORED, valid:false, exit 1
 *   6. active                                            → VERIFIED_CURRENT, valid:true, exit 0
 * and a key that is BOTH revoked and retired, signed after retired_at: row 2 wins (REVOKED_KEY).
 *
 * MEASURED on 15fbdc4: row 2 before compromised_at was REVOKED_KEY_UNDECIDABLE; the revoked+retired key after
 * retired_at was KEY_RETIRED_AFTER_SIGNING (retired_at was read before the revoked status); row 5 was
 * RETIRED_KEY_VALID_AT_ISSUE, valid:true, exit 0. Ephemeral key, temp keyrings, no network.
 */

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { canonicalJson, reconstructSignedInput } = require('../verify.js');

const ROOT = path.join(__dirname, '..');
const PYTHON = process.env.PYTHON || 'python3';
const KID = 'status-table-k1';
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const PEM = publicKey.export({ type: 'spki', format: 'pem' });
const HOUR = 3600e3;
const NOW = Math.floor(Date.now() / 1000) * 1000;
const TS = NOW - 6 * HOUR;
const iso = (ms) => new Date(ms).toISOString();
const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');
const made = [];
after(() => { for (const p of made) fs.rmSync(p, { recursive: true, force: true }); });

function keyring(fields) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'status-table-'));
  made.push(d);
  const f = path.join(d, 'keys.json');
  fs.writeFileSync(f, JSON.stringify({ keys: [{ kid: KID, public_key_pem: PEM, valid_from: null, ...fields }] }));
  return f;
}

function mint(ts) {
  const payload = { v: 4, kid: KID, fp: `sha256:${sha256hex('fp')}`, prev: 'null', caller: 'bundle', ts: iso(ts), reg: '', ir: '', expires_at: iso(NOW + 24 * HOUR), bh: `sha256:${sha256hex(canonicalJson({ decision: 'ALLOW' }))}` };
  const sig = crypto.sign(null, Buffer.from(reconstructSignedInput(payload), 'utf8'), privateKey);
  return `${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${sig.toString('base64url')}`;
}

function run(cmd, args) {
  const res = spawnSync(cmd, args, { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  let json = null;
  try { json = JSON.parse(res.stdout); } catch (_) { /* not json */ }
  return { code: res.status, json, stdout: res.stdout, stderr: res.stderr };
}

const COMPROMISED = iso(TS - 30 * 24 * HOUR);
const ROWS = [
  ['1 · unknown status', { status: 'suspended' }, TS, 'UNKNOWN_KEY_STATUS', false, 1],
  ['2 · revoked, signed before compromised_at', { status: 'revoked', compromised_at: iso(TS + HOUR) }, TS, 'REVOKED_KEY', false, 1],
  ['2 · revoked, signed after compromised_at', { status: 'revoked', compromised_at: COMPROMISED }, TS, 'REVOKED_KEY', false, 1],
  ['2 · revoked, no compromised_at', { status: 'revoked' }, TS, 'REVOKED_KEY', false, 1],
  ['2 · revoked AND retired, signed after retired_at → revoked wins', { status: 'revoked', compromised_at: COMPROMISED, retired_at: iso(TS - HOUR) }, TS, 'REVOKED_KEY', false, 1],
  ['3 · retired, signed after retired_at', { status: 'retired', retired_at: iso(TS - HOUR) }, TS, 'KEY_RETIRED_AFTER_SIGNING', false, 1],
  ['5 · retired, signed before retired_at, no anchor', { status: 'retired', retired_at: iso(TS + HOUR) }, TS, 'RETIRED_KEY_UNANCHORED', false, 1],
  ['6 · active', { status: 'active' }, TS, 'VERIFIED_CURRENT', true, 0],
];

describe('10t-rv key-status table (RECEIPT_FORMAT §7.1), cli.js and verify.py', () => {
  for (const [name, fields, ts, status, valid, code] of ROWS) {
    it(`${name} → ${status}, valid:${valid}, exit ${code}`, () => {
      const token = mint(ts);
      const keys = keyring(fields);
      const a = run(process.execPath, [path.join(ROOT, 'cli.js'), token, '--keys', keys]);
      const b = run(PYTHON, [path.join(ROOT, 'verify.py'), token, '--keys', keys]);
      for (const [label, r] of [['cli.js', a], ['verify.py', b]]) {
        assert.equal(r.json && r.json.status, status, `${label}: ${r.stdout}${r.stderr}`);
        assert.equal(r.json.valid, valid, label);
        assert.equal(r.code, code, label);
      }
      assert.equal(a.stdout, b.stdout, 'the two CLIs print the same verdict');
      if (status === 'REVOKED_KEY') assert.equal(a.json.compromised_at, fields.compromised_at || null);
    });
  }

  it('4 · NOT BUILDABLE today: no input carries an independent time anchor, so RETIRED_KEY_VALID_AT_ISSUE is never returned', () => {
    const src = fs.readFileSync(path.join(ROOT, 'verify.js'), 'utf8');
    const body = src.slice(src.indexOf('function deriveStatus('), src.indexOf('\n}\n', src.indexOf('function deriveStatus(')));
    // Any quoted literal counts (15fbdc4 returned it from a ternary: `expired ? 'VERIFIED_EXPIRED' : 'RETIRED_KEY_VALID_AT_ISSUE'`).
    assert.doesNotMatch(body, /'RETIRED_KEY_VALID_AT_ISSUE'/, 'row 4 needs an anchor input before it can be returned');
    for (const f of ['cli.js', 'verify.js', 'verify.py']) {
      assert.doesNotMatch(fs.readFileSync(path.join(ROOT, f), 'utf8'), /--anchor|rfc3161|inclusion_proof/i, `${f} reads no anchor`);
    }
  });
});
