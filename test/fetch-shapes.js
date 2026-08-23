#!/usr/bin/env node
'use strict';

/*
 * ID131 gap 5: default fetch accepts BOTH registry and legacy single-key bodies.
 * Local HTTP only — no live network.
 */

const assert = require('node:assert');
const http = require('node:http');
const { spawn } = require('node:child_process');
const path = require('node:path');
const v = require('../verify.js');
const vectors = require('./vectors.json');

assert.strictEqual(
  v.DEFAULT_FETCH_URL,
  'https://app.coderifts.com/.well-known/coderifts-keys.json',
  'default fetch URL is the key registry',
);

function serve(body) {
  return new Promise((resolve) => {
    const s = http.createServer((_req, res) => {
      res.setHeader('Content-Type', 'application/json');
      res.end(typeof body === 'string' ? body : JSON.stringify(body));
    });
    s.listen(0, '127.0.0.1', () => resolve(s));
  });
}

function urlOf(server) {
  return `http://127.0.0.1:${server.address().port}/`;
}

function runCli(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, { cwd: path.join(__dirname, '..') });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

async function main() {
  // 1. Registry shape: fetchKeyInfo returns a keyring; active kid is the live one.
  {
    const server = await serve(vectors.retired.registry);
    try {
      const info = await v.fetchKeyInfo(urlOf(server));
      assert.ok(info.keyring, 'registry shape exposes keyring');
      assert.strictEqual(info.kid, 'test-k1', 'active kid picked from registry');
      assert.ok(info.keyring.has('test-k1'));
      assert.ok(info.keyring.has('test-retired-k0'));
      assert.strictEqual(info.keyring.get('test-retired-k0').status, 'retired');
    } finally {
      await new Promise((cb) => server.close(cb));
    }
  }

  // 2. Legacy single-key body still works (no keyring).
  {
    const live = vectors.live;
    const server = await serve({ kid: live.kid, alg: 'Ed25519', public_key_pem: live.public_key_pem });
    try {
      const info = await v.fetchKeyInfo(urlOf(server));
      assert.strictEqual(info.kid, live.kid);
      assert.ok(info.publicKey);
      assert.strictEqual(info.keyring, undefined, 'legacy shape has no keyring');
      const token = live.vectors[0].token;
      const result = v.verifyReceipt(token, { publicKey: info.publicKey, expectedKid: info.kid });
      assert.strictEqual(result.valid, true, 'legacy shape verifies the live receipt');
    } finally {
      await new Promise((cb) => server.close(cb));
    }
  }

  // 3. Retired kid via default-fetch (registry) → RETIRED_KEY_VALID_AT_ISSUE, not unknown_kid.
  {
    const server = await serve(vectors.retired.registry);
    const fetchUrl = urlOf(server);
    try {
      const info = await v.fetchKeyInfo(fetchUrl);
      const result = v.verifyReceipt(vectors.retired.token_valid_at_issue, {
        keyring: info.keyring,
        expectedKid: null,
      });
      assert.strictEqual(result.status, 'RETIRED_KEY_VALID_AT_ISSUE', result.reason || result.status);
      assert.strictEqual(result.valid, true);
      assert.notStrictEqual(result.reason, 'unknown_kid');

      const cli = await runCli([
        path.join(__dirname, '..', 'verify.js'),
        vectors.retired.token_valid_at_issue,
        '--fetch', fetchUrl,
      ]);
      assert.strictEqual(cli.code, 0, cli.stderr);
      const parsed = JSON.parse(cli.stdout);
      assert.strictEqual(parsed.status, 'RETIRED_KEY_VALID_AT_ISSUE');
      assert.notStrictEqual(parsed.reason, 'unknown_kid');
    } finally {
      await new Promise((cb) => server.close(cb));
    }
  }

  console.log('fetch-shapes: OK (registry + legacy + retired-via-default-fetch)');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
