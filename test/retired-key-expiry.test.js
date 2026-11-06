'use strict';

/*
 * 1.1.6 — the expiry rule applies after the retired-key rule (RECEIPT_FORMAT §7). Measured in round 10b:
 * deriveStatus returned RETIRED_KEY_VALID_AT_ISSUE before the expiry check, so an expired v4 receipt under
 * a retired key verified valid:true. Both ports, through both CLIs; --as-of (verify.js only) applies the
 * same window. Ephemeral key, temp keyring files, no network.
 */

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { canonicalJson, reconstructSignedInput, CLOCK_SKEW_LEEWAY_MS } = require('../verify.js');

const ROOT = path.join(__dirname, '..');
const PYTHON = process.env.PYTHON || 'python3';
const KID = 'retired-expiry-k1';
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const PEM = publicKey.export({ type: 'spki', format: 'pem' });
const HOUR = 3600e3;
const NOW = Math.floor(Date.now() / 1000) * 1000;
const iso = (ms) => new Date(ms).toISOString();
const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');
const made = [];
after(() => { for (const p of made) fs.rmSync(p, { recursive: true, force: true }); });

/** A keyring with the test key retired at `retiredAt`. */
function retiredKeys(retiredAt) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'retired-expiry-'));
  made.push(d);
  const f = path.join(d, 'keys.json');
  fs.writeFileSync(f, JSON.stringify({ keys: [{ kid: KID, public_key_pem: PEM, status: 'retired', valid_from: null, retired_at: iso(retiredAt) }] }));
  return f;
}

function mint(ts, exp) {
  const payload = { v: 4, kid: KID, fp: `sha256:${sha256hex('fp')}`, prev: 'null', caller: 'bundle', ts: iso(ts), reg: '', ir: '', expires_at: iso(exp), bh: `sha256:${sha256hex(canonicalJson({ decision: 'ALLOW' }))}` };
  const sig = crypto.sign(null, Buffer.from(reconstructSignedInput(payload), 'utf8'), privateKey);
  return `${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${sig.toString('base64url')}`;
}

function run(cmd, args) {
  const res = spawnSync(cmd, args, { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  let json = null;
  try { json = JSON.parse(res.stdout); } catch (_) { /* not json */ }
  return { code: res.status, json, stdout: res.stdout, stderr: res.stderr };
}
const js = (args) => run(process.execPath, [path.join(ROOT, 'cli.js'), ...args]);
const py = (args) => run(PYTHON, [path.join(ROOT, 'verify.py'), ...args]);

// Signed 6 h ago, key retired 5 h ago (after signing), window 4 h → closed 2 h ago.
const TS = NOW - 6 * HOUR;
const KEYS = () => retiredKeys(TS + HOUR);

// 10t-rv (2026-11-05): RECEIPT_FORMAT §7.1, row 5. A receipt signed before retired_at under a retired key, with
// no independent time anchor (this verifier reads none), is RETIRED_KEY_UNANCHORED — valid:false, exit 1 —
// whatever its window: the signer chooses ts, so ts < retired_at proves nothing. MEASURED on 15fbdc4 for the
// same tokens: VERIFIED_EXPIRED (window closed), RETIRED_KEY_VALID_AT_ISSUE valid:true exit 0 (inside the
// window or the leeway), and under --as-of inside the window RETIRED_KEY_VALID_AT_ISSUE valid_at_as_of:true.
describe('retired key, signed before retired_at, no anchor: RETIRED_KEY_UNANCHORED (row 5)', () => {
  for (const [what, exp] of [
    ['expired v4 (window closed 2 h ago)', () => TS + 4 * HOUR],
    ['inside the leeway (expires_at 10 s ago)', () => NOW - 10e3],
    ['inside the window', () => NOW + HOUR],
  ]) {
    it(`${what} → RETIRED_KEY_UNANCHORED, valid:false, exit 1 — verify.js and verify.py agree`, () => {
      const token = mint(TS, exp());
      const keys = KEYS();
      const a = js([token, '--keys', keys]);
      const b = py([token, '--keys', keys]);
      for (const [name, r] of [['js', a], ['py', b]]) {
        assert.equal(r.json.status, 'RETIRED_KEY_UNANCHORED', `${name}: ${r.stdout}${r.stderr}`);
        assert.equal(r.json.valid, false, name);
        assert.equal(r.code, 1, name);
      }
      assert.equal(a.stdout, b.stdout, 'the two CLIs print the same verdict');
    });
  }

  it('signed after retired_at is still refused, whatever the window (row 3)', () => {
    const token = mint(TS, NOW + HOUR);
    const keys = retiredKeys(TS - HOUR);
    for (const r of [js([token, '--keys', keys]), py([token, '--keys', keys])]) {
      assert.equal(r.json.valid, false, r.stdout);
      assert.equal(r.json.status, 'KEY_RETIRED_AFTER_SIGNING');
    }
  });
});

describe('retired key under --as-of: no as-of rehabilitates an unanchored signature', () => {
  for (const [what, at] of [['as-of after the window', () => TS + 5 * HOUR], ['as-of inside the window', () => TS + 2 * HOUR]]) {
    it(`${what} → RETIRED_KEY_UNANCHORED, valid_at_as_of:false, exit 1`, () => {
      const token = mint(TS, TS + 4 * HOUR);
      const out = js([token, '--keys', KEYS(), '--as-of', iso(at())]);
      assert.equal(out.json.mode, 'audit');
      assert.equal(out.json.status, 'RETIRED_KEY_UNANCHORED', out.stdout + out.stderr);
      assert.equal(out.json.valid, false);
      assert.equal(out.json.valid_at_as_of, false);
      assert.equal(out.code, 1);
    });
  }
});
