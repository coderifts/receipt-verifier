'use strict';

/**
 * 1961/7.2 — "WE COULD NOT ASK" IS NOT "THIS KEY IS NOT OURS".
 *
 * ⚠ THE BUG THIS PINS, measured 2026-09-23 before the fix: a MANDATORY discovery that failed
 * (--refresh-keys / --fetch <url> / --keys <url>) exited through `fail()` — free text on stderr
 * and exit 2, the same shape as a mistyped flag. Nothing on stdout, no status a machine could
 * read. An operator could not tell a registry outage from their own typo, and a pipeline reading
 * the exit code could not either.
 *
 * ⚠ NOTHING IS LOOSENED BY NAMING IT. Both the old and the new answer are refusals. What changes
 * is WHERE the reader is sent: REGISTRY_UNREACHABLE points at the network, UNKNOWN_KEY points at
 * the signer. `REGISTRY_UNREACHABLE` is already normative in RECEIPT_FORMAT.md §7.1 — the code is
 * catching up with the published format, not inventing a state.
 *
 * ⚠ THE NEGATIVE CONTROL IS THE LOAD-BEARING HALF: an operator who pinned a local keyring must
 * NOT get REGISTRY_UNREACHABLE because some registry they never asked for is down.
 *
 * No external network: the unreachable case dials 127.0.0.1 on a closed port, so the refusal is
 * local, immediate and deterministic.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const { registryUnreachableVerdict, discoveryWasMandatory } = require('../cli.js');

const CLI = path.join(__dirname, '..', 'cli.js');
const CLOSED = 'http://127.0.0.1:1/keys.json';

/** Run the CLI and capture stdout + exit code without throwing on a non-zero exit. */
function runCli(args) {
  try {
    const stdout = execFileSync(process.execPath, [CLI, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    return { code: 0, stdout };
  } catch (e) {
    return { code: e.status, stdout: e.stdout || '', stderr: e.stderr || '' };
  }
}

describe('discoveryWasMandatory — did the operator ask for the network?', () => {
  it('⚠ --refresh-keys and --fetch are the network, by definition', () => {
    assert.equal(discoveryWasMandatory({ refreshKeys: true }), true);
    assert.equal(discoveryWasMandatory({ fetchUrl: 'https://example.invalid/k.json' }), true);
  });

  it('⚠ --keys <url> is the network; --keys <file> is not', () => {
    assert.equal(discoveryWasMandatory({ keysSource: 'https://example.invalid/k.json' }), true);
    assert.equal(discoveryWasMandatory({ keysSource: 'http://example.invalid/k.json' }), true);
    assert.equal(discoveryWasMandatory({ keysSource: './keys/registry.json' }), false);
    assert.equal(discoveryWasMandatory({ keysSource: '/abs/registry.json' }), false);
  });

  it('⚠⚠ NEGATIVE CONTROL — the default (vendored snapshot) is NOT mandatory discovery', () => {
    // This is the case that must never be downgraded: verifying offline against pinned keys is a
    // deliberate mode, not a degraded one.
    assert.equal(discoveryWasMandatory({}), false);
    assert.equal(discoveryWasMandatory({ keyFile: 'pub.pem' }), false);
  });
});

describe('the verdict a failed discovery produces', () => {
  it('⚠ it is fail-closed — valid:false, like every other refusal', () => {
    const v = registryUnreachableVerdict(CLOSED, new Error('ECONNREFUSED'));
    assert.equal(v.valid, false);
    assert.equal(v.status, 'REGISTRY_UNREACHABLE');
    assert.equal(v.reason, 'registry_unreachable');
  });

  it('⚠ it names the source and the offline remedy — an operator must not be left guessing', () => {
    const v = registryUnreachableVerdict(CLOSED, new Error('ECONNREFUSED'));
    assert.equal(v.registry_unreachable.source, CLOSED);
    assert.match(v.registry_unreachable.why, /ECONNREFUSED/);
    assert.match(v.registry_unreachable.remedy, /--keys <file>/);
  });

  it('⚠⚠ it is NOT UNKNOWN_KEY — the whole point of the state', () => {
    const v = registryUnreachableVerdict(CLOSED, new Error('x'));
    assert.notEqual(v.status, 'UNKNOWN_KEY');
    assert.notEqual(v.status, 'INVALID_SIGNATURE');
  });
});

describe('the CLI end to end', () => {
  const RECEIPT = fs.readFileSync(path.join(__dirname, 'fixtures-receipt.txt'), 'utf8').trim();

  it('⚠ a mandatory discovery that fails prints a STATUS on stdout and exits 1, not 2', () => {
    const r = runCli([RECEIPT, '--keys', CLOSED]);
    assert.equal(r.code, 1, 'a verdict exit code, not the usage exit code 2');
    const out = JSON.parse(r.stdout);
    assert.equal(out.status, 'REGISTRY_UNREACHABLE');
    assert.equal(out.valid, false);
  });

  it('⚠⚠ NEGATIVE CONTROL — an unreadable LOCAL file is still a usage error, not an outage', () => {
    // Dressing an operator's own missing file as a registry outage would send them to the network
    // to debug a path. The asymmetry is the fix, not an oversight.
    const r = runCli([RECEIPT, '--keys', path.join(__dirname, 'no-such-registry.json')]);
    assert.equal(r.code, 2);
    assert.equal(r.stdout.trim(), '', 'a usage error must not emit a verdict document');
  });

  it('⚠⚠ NEGATIVE CONTROL — the offline default still verifies, unaffected by any registry', () => {
    const r = runCli([RECEIPT, '--keys', path.join(__dirname, 'fixtures-keys.json')]);
    const out = JSON.parse(r.stdout);
    assert.ok(['VERIFIED_CURRENT', 'RETIRED_KEY_VALID_AT_ISSUE', 'VERIFIED_EXPIRED', 'UNKNOWN_KEY'].includes(out.status),
      `offline path produced ${out.status}`);
    assert.notEqual(out.status, 'REGISTRY_UNREACHABLE');
  });
});

describe('the cross-language corpus carries the case', () => {
  const { execFileSync: run } = require('node:child_process');
  const os = require('node:os');

  it('⚠ the generator emits a discovery block with the case AND its negative control', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'xlang-disc-'));
    const out = path.join(dir, 'xlang-vectors.json');
    run(process.execPath, [path.join(__dirname, 'gen-xlang-vectors.js'), '--out', out],
      { cwd: path.join(__dirname, '..'), stdio: ['ignore', 'ignore', 'pipe'] });
    const corpus = JSON.parse(fs.readFileSync(out, 'utf8'));
    const byName = Object.fromEntries(corpus.discovery.cases.map((c) => [c.name, c]));

    const mandatory = byName.REGISTRY_UNREACHABLE_DISCOVERY_MANDATORY;
    assert.equal(mandatory.discovery_mandatory, true);
    assert.equal(mandatory.expected.status, 'REGISTRY_UNREACHABLE');

    const offline = byName.OFFLINE_PINNED_REGISTRY_UNREACHABLE_IS_NOT_A_FAILURE;
    assert.equal(offline.discovery_mandatory, false);
    assert.notEqual(offline.expected.status, 'REGISTRY_UNREACHABLE');
  });

  it('⚠⚠ ADDITIVE — the discovery block is NOT in vectors[], so older consumers are unaffected', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'xlang-disc2-'));
    const out = path.join(dir, 'xlang-vectors.json');
    run(process.execPath, [path.join(__dirname, 'gen-xlang-vectors.js'), '--out', out],
      { cwd: path.join(__dirname, '..'), stdio: ['ignore', 'ignore', 'pipe'] });
    const corpus = JSON.parse(fs.readFileSync(out, 'utf8'));
    // ⚠ A consumer that loops vectors[] through verifyReceipt must never meet a discovery case:
    // it has no keyring to verify against, and would record UNKNOWN_KEY — the exact conflation
    // this case exists to separate.
    assert.ok(!corpus.vectors.some((v) => /REGISTRY_UNREACHABLE|DISCOVERY/.test(v.name)));
    assert.ok(!corpus.vectors.some((v) => v.js && v.js.status === 'REGISTRY_UNREACHABLE'));
  });
});
