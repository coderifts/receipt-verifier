/**
 * ITEM A — the stranger-machine proof.
 *
 * The library verifyReceipt (and CLI --key / --keys <file> / the vendored
 * default) must verify a real receipt with ZERO network. A verifier that needs
 * app.coderifts.com is SaaS, not a CA. Live fetch is opt-in: --refresh-keys,
 * --fetch <url>, or --keys <url>.
 *
 * Named ceiling (unchanged): this verifier is stateless and cannot detect a
 * replayed nonce (README consumeAndCommit; no jti store).
 */
'use strict';

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const doc = require('./vectors.json');
const { verifyReceipt, keyFromPem, loadKeyring } = require('../verify');

const calls = [];
const origFetch = globalThis.fetch;
const http = require('node:http');
const https = require('node:https');
const origHttp = http.request;
const origHttps = https.request;

function trap(name) {
  return function trapped(first) {
    calls.push({ name, first: String(first && first.href ? first.href : first) });
    const err = new Error(`NETWORK_TRAP:${name}`);
    err.code = 'NETWORK_TRAP';
    throw err;
  };
}

globalThis.fetch = trap('fetch');
http.request = trap('http.request');
https.request = trap('https.request');

after(() => {
  globalThis.fetch = origFetch;
  http.request = origHttp;
  https.request = origHttps;
});

function pemFile() {
  const p = path.join(os.tmpdir(), `rv-offline-${process.pid}.pem`);
  fs.writeFileSync(p, doc.public_key_pem);
  return p;
}

describe('offline verify — no network (library)', () => {
  it('verifyReceipt(valid_v4) against a pinned PEM never fetches', () => {
    calls.length = 0;
    const v4 = doc.vectors.find((x) => x.name === 'valid_v4');
    const r = verifyReceipt(v4.token, {
      publicKey: keyFromPem(doc.public_key_pem),
      expectedKid: doc.kid,
    });
    assert.equal(r.valid, true);
    assert.equal(r.status, 'VERIFIED_CURRENT');
    assert.equal(r.payload.kid, doc.kid);
    assert.equal(typeof r.payload.expires_at, 'string');
    assert.deepEqual(calls, [], `library verifyReceipt made network: ${JSON.stringify(calls)}`);
  });

  it('verifyReceipt(expired_v4) is VERIFIED_EXPIRED still offline', () => {
    calls.length = 0;
    const exp = doc.vectors.find((x) => x.name === 'expired_v4');
    const r = verifyReceipt(exp.token, {
      publicKey: keyFromPem(doc.public_key_pem),
      expectedKid: doc.kid,
    });
    assert.equal(r.valid, false);
    assert.equal(r.status, 'VERIFIED_EXPIRED');
    assert.deepEqual(calls, []);
  });

  it('verifyReceipt(wrong_kid) is UNKNOWN_KEY still offline', () => {
    calls.length = 0;
    const w = doc.vectors.find((x) => x.name === 'wrong_kid');
    const r = verifyReceipt(w.token, {
      publicKey: keyFromPem(doc.public_key_pem),
      expectedKid: doc.kid,
    });
    assert.equal(r.valid, false);
    assert.equal(r.status, 'UNKNOWN_KEY');
    assert.deepEqual(calls, []);
  });

  it('loadKeyring from a local file never fetches', async () => {
    calls.length = 0;
    const keysPath = path.join(os.tmpdir(), `rv-keys-${process.pid}.json`);
    fs.writeFileSync(keysPath, JSON.stringify({
      keys: [{ kid: doc.kid, public_key_pem: doc.public_key_pem, status: 'active' }],
    }));
    try {
      const ring = await loadKeyring(keysPath);
      const v4 = doc.vectors.find((x) => x.name === 'valid_v4');
      const r = verifyReceipt(v4.token, { keyring: ring, expectedKid: doc.kid });
      assert.equal(r.valid, true);
      assert.deepEqual(calls, []);
    } finally {
      fs.rmSync(keysPath, { force: true });
    }
  });

  it('BITES: a sneaky fetch in verifyReceipt fails this test', () => {
    assert.equal(calls.some((c) => /coderifts\.com/.test(c.first)), false);
  });
});

describe('offline verify — CLI --key child with network trap preload', () => {
  it('node cli.js --key does not call fetch/http/https', () => {
    const pem = pemFile();
    const preload = path.join(__dirname, 'network-trap-preload.js');
    const v4 = doc.vectors.find((x) => x.name === 'valid_v4');
    let out;
    try {
      out = execFileSync(
        process.execPath,
        ['-r', preload, path.join(ROOT, 'cli.js'), v4.token, '--key', pem, '--kid', doc.kid],
        { cwd: ROOT, encoding: 'utf8' },
      );
    } finally {
      fs.rmSync(pem, { force: true });
    }
    const r = JSON.parse(out);
    assert.equal(r.valid, true);
    assert.equal(r.status, 'VERIFIED_CURRENT');
  });

  it('python3 verify.py --key does not urlopen (stdlib patched in-process)', () => {
    const pem = pemFile();
    const v4 = doc.vectors.find((x) => x.name === 'valid_v4');
    const py = `
import json, runpy, sys, urllib.request
def boom(*a, **k):
    raise RuntimeError("NETWORK_TRAP:urllib")
urllib.request.urlopen = boom
sys.argv = ["verify.py", ${JSON.stringify(v4.token)}, "--key", ${JSON.stringify(pem)}, "--kid", ${JSON.stringify(doc.kid)}]
runpy.run_path(${JSON.stringify(path.join(ROOT, 'verify.py'))}, run_name="__main__")
`;
    try {
      const out = execFileSync('python3', ['-c', py], { cwd: ROOT, encoding: 'utf8' });
      const r = JSON.parse(out.trim().split('\n').pop());
      assert.equal(r.valid, true);
      assert.equal(r.status, 'VERIFIED_CURRENT');
    } finally {
      fs.rmSync(pem, { force: true });
    }
  });
});

describe('1355-default — vendored keys, network is opt-in', () => {
  const fixtureReceipt = fs.readFileSync(path.join(ROOT, 'test', 'fixtures-receipt.txt'), 'utf8').trim();
  const preload = path.join(__dirname, 'network-trap-preload.js');

  it('vendored snapshot sha256 matches the sidecar', () => {
    const { VENDORED_KEYS_PATH } = require('../cli');
    const crypto = require('node:crypto');
    const body = fs.readFileSync(VENDORED_KEYS_PATH);
    const got = crypto.createHash('sha256').update(body).digest('hex');
    const sidecar = fs.readFileSync(`${VENDORED_KEYS_PATH}.sha256`, 'utf8').trim().split(/\s+/)[0];
    assert.equal(got, sidecar);
    assert.equal(got, 'bfe0c898cda3c3a4c8141726d0adb4cdb7eb9762de6264e430eff6469b90422e');
  });

  it('BITES JS: default verify with network trapped PASSES against the vendored key', () => {
    const out = execFileSync(
      process.execPath,
      ['-r', preload, path.join(ROOT, 'cli.js'), fixtureReceipt],
      { cwd: ROOT, encoding: 'utf8' },
    );
    const r = JSON.parse(out);
    assert.equal(r.valid, true);
    assert.equal(r.status, 'VERIFIED_CURRENT');
    assert.equal(r.payload.kid, '2026-07-k1');
  });

  it('BITES JS: --refresh-keys with the trap FAILS at the fetch', () => {
    let err;
    try {
      execFileSync(
        process.execPath,
        ['-r', preload, path.join(ROOT, 'cli.js'), fixtureReceipt, '--refresh-keys'],
        { cwd: ROOT, encoding: 'utf8' },
      );
    } catch (e) {
      err = e;
    }
    assert.ok(err, '--refresh-keys must fail when the network is trapped');
    const combined = `${err.stderr || ''}\n${err.stdout || ''}\n${err.message || ''}`;
    assert.match(combined, /NETWORK_TRAP|could not load public key/);
    assert.notEqual(err.status, 0);
  });

  it('BITES PY: default verify with urlopen trapped PASSES against the vendored key', () => {
    const py = `
import json, runpy, sys, urllib.request
def boom(*a, **k):
    raise RuntimeError("NETWORK_TRAP:urllib")
urllib.request.urlopen = boom
sys.argv = ["verify.py", ${JSON.stringify(fixtureReceipt)}]
runpy.run_path(${JSON.stringify(path.join(ROOT, 'verify.py'))}, run_name="__main__")
`;
    const out = execFileSync('python3', ['-c', py], { cwd: ROOT, encoding: 'utf8' });
    const r = JSON.parse(out.trim().split('\n').pop());
    assert.equal(r.valid, true);
    assert.equal(r.status, 'VERIFIED_CURRENT');
    assert.equal(r.payload.kid, '2026-07-k1');
  });

  it('BITES PY: --refresh-keys with urlopen trapped FAILS at the fetch', () => {
    const py = `
import runpy, sys, urllib.request
def boom(*a, **k):
    raise RuntimeError("NETWORK_TRAP:urllib")
urllib.request.urlopen = boom
sys.argv = ["verify.py", ${JSON.stringify(fixtureReceipt)}, "--refresh-keys"]
runpy.run_path(${JSON.stringify(path.join(ROOT, 'verify.py'))}, run_name="__main__")
`;
    let err;
    try {
      execFileSync('python3', ['-c', py], { cwd: ROOT, encoding: 'utf8' });
    } catch (e) {
      err = e;
    }
    assert.ok(err, 'python --refresh-keys must fail when urlopen is trapped');
    const combined = `${err.stderr || ''}\n${err.stdout || ''}\n${err.message || ''}`;
    assert.match(combined, /NETWORK_TRAP|could not load public key/);
    assert.notEqual(err.status, 0);
  });
});

describe('named ceiling — replayed nonce is NOT this verifier', () => {
  it('verifyReceipt path has no nonce/jti consumption store', () => {
    const src = fs.readFileSync(path.join(ROOT, 'verify.js'), 'utf8');
    assert.equal(/\bnonce\b/.test(src), false);
    assert.equal(/\bjti\b/.test(src), false);
  });
});
