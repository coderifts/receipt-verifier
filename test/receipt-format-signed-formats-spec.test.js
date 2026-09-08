'use strict';

/**
 * DOC/CODE DRIFT-GATE for sections 10-13 of RECEIPT_FORMAT.md.
 *
 * Same discipline as receipt-format-dsse-spec.test.js, and for the same reason: the agent-discovery
 * document's `format_spec` points at RECEIPT_FORMAT.md, so an external implementer reads it and
 * writes a verifier against it. A section that drifted from the module it documents is not a stale
 * comment — it is an interoperability bug somebody else ships.
 *
 * THE MODULES ARE THE SOURCE. Every identifier asserted below is read from the code AT RUNTIME and
 * searched for in the prose. Changing a field set without the doc fails here rather than in a
 * stranger's integration. Nothing in this file hard-codes a field name that the code does not also
 * produce — a list typed out twice is a list that drifts in one place.
 *
 * ── SECTION 13 IS DIFFERENT, AND SAYS SO ────────────────────────────────────────────────────
 *
 * `target_state_transition` is produced in the capability-demo sibling, not here. Its gate reads
 * that checkout when it exists and SKIPS LOUDLY when it does not. A silent skip would print a
 * passing comparison that never ran — the fabricated-pass class this repo already refuses in
 * cross-check-no-silent-skip.test.js.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const DOC_PATH = path.join(__dirname, '..', 'RECEIPT_FORMAT.md');
const DOC = fs.readFileSync(DOC_PATH, 'utf8');

const grant = require('../verify-grant.js');
const root = require('../evidence-root.js');
const evidence = require('../verify-evidence.js');

/** The prose of one section, so an assertion cannot be satisfied by a word somewhere else. */
function section(heading) {
  const i = DOC.indexOf(heading);
  assert.notEqual(i, -1, `RECEIPT_FORMAT.md has no section "${heading}"`);
  // INCLUDING the heading. The version string a reader keys on lives in it, and a slice that
  // started after it made "the doc omits cr.evidence.root.v1" true of a doc that names it twice.
  const rest = DOC.slice(i);
  const j = rest.slice(heading.length).search(/\n## /);
  return j === -1 ? rest : rest.slice(0, heading.length + j);
}

/**
 * The same prose with runs of whitespace collapsed.
 *
 * The doc WRAPS. A regex with a literal space in it fails on "does **not**\nauthenticate" while
 * the sentence is right there — the assertion then reports a missing boundary the doc states,
 * which is worse than not checking: it teaches a reader to distrust the gate.
 */
const flat = (heading) => section(heading).replace(/\s+/g, ' ');

describe('RECEIPT_FORMAT.md §10 documents the execution grants the code verifies', () => {
  const S = () => section('## 10. cr.exec.v1 / cr.exec.v2 (execution grants)');
  const F = () => flat('## 10. cr.exec.v1 / cr.exec.v2 (execution grants)');

  it('both signing prefixes are the ones verify-grant.js builds', () => {
    // These are the bytes. An implementer who gets the prefix wrong verifies nothing.
    assert.ok(S().includes(grant.SIGNING_PREFIX), `§10 omits ${grant.SIGNING_PREFIX}`);
    assert.ok(S().includes(grant.SIGNING_PREFIX_V2), `§10 omits ${grant.SIGNING_PREFIX_V2}`);
  });

  it('every v1 SIGNED field is named, in the order the preimage joins them', () => {
    const s = S();
    let at = -1;
    for (const f of grant.SIGNED_FIELDS) {
      const i = s.indexOf(`<${f}>`);
      assert.notEqual(i, -1, `v1 signed field "${f}" is undocumented in §10`);
      assert.ok(i > at, `v1 signed field "${f}" appears out of signing order in §10`);
      at = i;
    }
  });

  it('the OPTIONAL signed fields are named AND their append rule is stated', () => {
    // The fail-closed defect this rule exists to prevent: a verifier that always appended two
    // empty segments rejected every non-ATOMIC v1 grant.
    const s = S();
    for (const f of grant.V1_OPTIONAL_SIGNED_FIELDS) {
      assert.ok(s.includes(`<${f}>`), `optional signed field "${f}" is undocumented in §10`);
    }
    assert.match(s, /only when present and non-empty/i,
      '§10 does not state that the optional fields are appended conditionally');
  });

  it('every v2 required field is named, and the admitted set is stated as closed', () => {
    // Read from the module rather than listed here: the source is a frozen array, and this test
    // must fail when it changes.
    const src = fs.readFileSync(path.join(__dirname, '..', 'verify-grant.js'), 'utf8');
    const block = src.slice(src.indexOf('V2_REQUIRED_STRINGS = Object.freeze(['));
    const fields = [...block.slice(0, block.indexOf(']')).matchAll(/'([a-z_]+)'/g)].map((m) => m[1]);
    assert.ok(fields.length >= 16, `expected the v2 field set, found ${fields.length}`);
    const s = S();
    for (const f of fields) assert.ok(s.includes(f), `v2 required field "${f}" is undocumented in §10`);
    assert.ok(s.includes('max_attempts'), '§10 omits max_attempts');
    assert.match(s, /unknown_field/, '§10 does not state that an unknown key is refused');
  });

  it('the target-URI schemes are the ones canonicalizeTargetUri admits', () => {
    // Measured against the function, not against a list in the source: what an implementer needs
    // is which schemes are ACCEPTED.
    const s = S();
    for (const scheme of ['fs', 'git', 'api', 'db', 'registry', 'deploy']) {
      assert.ok(grant.canonicalizeTargetUri(`${scheme}://host/path`),
        `precondition: ${scheme}:// should canonicalise`);
      assert.ok(s.includes(`\`${scheme}\``), `§10 does not name the admitted scheme ${scheme}`);
    }
    assert.equal(grant.canonicalizeTargetUri('ftp://host/path'), null,
      'precondition: an unlisted scheme must be refused');
  });

  it('the v1 scope_hash recipe in the doc is the one computeScopeHash implements', () => {
    const s = S();
    assert.match(s, /operation ⨝ target_id ⨝ after_payload/, '§10 does not give the scope_hash recipe');
    assert.match(s, /\\x1f|US\b/, '§10 does not name the US separator');
    // …and the recipe is true, computed here rather than only asserted in prose.
    const crypto = require('node:crypto');
    const want = `sha256:${crypto.createHash('sha256').update(['publish', 't', 'body'].join('\x1f')).digest('hex')}`;
    assert.equal(grant.computeScopeHash({ operation: 'publish', target_id: 't', after_payload: 'body' }), want);
  });

  it('the honesty boundary is carried, not paraphrased away', () => {
    assert.match(F(), /does \*\*not\*\* say the operation happened/i,
      '§10 does not state what GRANT_CURRENT fails to prove');
  });
});

describe('RECEIPT_FORMAT.md §11 documents the correlation the code verifies', () => {
  const S = () => section('## 11. cr.exec.correlation.v1');
  const F = () => flat('## 11. cr.exec.correlation.v1');

  it('the version string is the module\'s', () => {
    assert.ok(S().includes(evidence.CORRELATION_V), `§11 omits ${evidence.CORRELATION_V}`);
  });

  it('the preimage in the doc is the one correlationPreimage builds', () => {
    // Built from a probe rather than from the doc's own words, then every field position checked
    // against the prose in order.
    const probe = evidence.correlationPreimage({
      scope_hash: '<scope_hash>',
      contract_commit: '<contract_commit>',
      contract_path: '<contract_path>',
      readback_commit: '<readback_commit>',
    });
    const s = S();
    let at = -1;
    for (const part of probe.split('\x1f')) {
      const i = s.indexOf(part);
      assert.notEqual(i, -1, `§11 omits preimage element ${part}`);
      assert.ok(i > at, `§11 lists preimage element ${part} out of order`);
      at = i;
    }
  });

  it('the hash-before-signature ordering is documented, with the status it produces', () => {
    const s = S();
    assert.match(s, /before the signature/i, '§11 does not document the check order');
    assert.ok(s.includes('CORRELATION_UNBOUND'), '§11 does not name the status a mutated field yields');
  });

  it('the commit-equality requirement and its boundary are both stated', () => {
    const s = S();
    assert.match(s, /must be equal/i, '§11 does not require contract_commit === readback_commit');
    assert.match(F(), /does \*\*not\*\* establish that the observation is true/i,
      '§11 does not state what the correlation fails to prove');
  });
});

describe('RECEIPT_FORMAT.md §12 documents the evidence root the code builds', () => {
  const S = () => section('## 12. cr.evidence.root.v1');
  const F = () => flat('## 12. cr.evidence.root.v1');

  it('the version and signing prefix are the module\'s', () => {
    assert.ok(S().includes(root.ROOT_V), `§12 omits ${root.ROOT_V}`);
    assert.ok(S().includes(root.ROOT_SIGNING_PREFIX), `§12 omits ${root.ROOT_SIGNING_PREFIX}`);
  });

  it('EVERY slot is documented with the right mandatory flag and the right signer', () => {
    // The slot set is closed and signed over; a doc that named five of six would send an
    // implementer looking for a slot they must refuse.
    const s = S();
    for (const name of root.SLOT_NAMES) {
      const row = s.split('\n').find((l) => l.includes(`\`${name}\``) && l.startsWith('|'));
      assert.ok(row, `§12 has no table row for slot ${name}`);
      const want = root.SLOTS[name].mandatory ? 'yes' : 'no';
      assert.ok(row.includes(`| ${want} |`), `§12 records slot ${name} as the wrong mandatory flag`);
      const signer = evidence.SIGNER[name];
      if (signer) assert.ok(row.includes(signer), `§12 records the wrong signer for slot ${name}`);
    }
  });

  it('the doc names no slot the code does not have', () => {
    const s = S();
    for (const bogus of s.matchAll(/^\| `([a-z_]+)` \|/gm)) {
      assert.ok(root.SLOT_NAMES.includes(bogus[1]), `§12 documents slot "${bogus[1]}" which does not exist`);
    }
  });

  it('the absent-is-null rule is stated, and it is what digestToken does', () => {
    assert.ok(S().includes('never `sha256("")`'),
      '§12 does not state that an absent token is null rather than the empty-string hash');
    assert.equal(root.digestToken(null), null);
    assert.equal(root.digestToken(''), null);
    assert.notEqual(root.digestToken('x'), null);
  });

  it('every check the code can emit is documented, and none is invented', () => {
    // THE CLOSED LIST, read from the source rather than from a run. A run only exercises the
    // checks its artifact happens to enable, so measuring the doc against one run would let a
    // check that never fires on that artifact go undocumented forever.
    const src = fs.readFileSync(path.join(__dirname, '..', 'verify-evidence.js'), 'utf8');
    const literal = [...src.matchAll(/note\(\s*'([a-z_0-9]+)'/g)].map((m) => m[1]);
    const templated = [...src.matchAll(/note\(\s*`([a-z_0-9]+)\$\{/g)].map((m) => m[1]);
    assert.ok(literal.length >= 9, `expected the literal check ids, found ${literal.length}`);
    assert.ok(templated.length >= 2, 'expected the per-slot check id prefixes');

    const s = S();
    for (const id of literal) assert.ok(s.includes(id), `check "${id}" runs but is undocumented in §12`);
    for (const prefix of new Set(templated)) {
      assert.ok(s.includes(`${prefix}<slot>`), `the per-slot family "${prefix}<slot>" is undocumented in §12`);
    }
    // …and the doc invents none. Every documented id must be one the code can produce.
    const documented = [...s.matchAll(/^([a-z_0-9]+)\s{2,}/gm)].map((m) => m[1]);
    assert.ok(documented.length >= 9, 'the §12 check table did not parse');
    for (const id of documented) {
      const known = literal.includes(id) || [...templated].some((pre) => id === `${pre}<slot>`.replace('<slot>', ''));
      assert.ok(known || id.endsWith('slot'), `§12 documents check "${id}" which the code never emits`);
    }
  });

  it('the count the doc states is MEASURED on a real capture, not recited', (t) => {
    // 19 is a specific number and a reader trusts a specific number, so it is produced from the
    // artifact it was measured on. A SYNTHETIC probe was tried first and reached 15: several
    // checks need an issuance grant and continuity identities that only a real capture carries.
    // Tuning the probe until it hit 19 would have been fitting the measurement to the answer.
    const capture = path.join(__dirname, '..', '..', 'coderifts-conformance',
      'fixtures', 'recorded', 'end-to-end');
    if (!fs.existsSync(path.join(capture, 'transcript.json'))) {
      t.skip('coderifts-conformance is not checked out beside this repository — the documented '
        + 'check count was NOT measured against a capture. NOT RUN, not passed. (The closed check '
        + 'list and the conditional-count rule were gated above and did run.)');
      return;
    }
    const crypto = require('node:crypto');
    const artifact = JSON.parse(fs.readFileSync(path.join(capture, 'transcript.json'), 'utf8'));
    const keyring = JSON.parse(fs.readFileSync(path.join(capture, 'executor-keys.json'), 'utf8'));
    const r = evidence.verifyEvidenceRootBinding(artifact, {
      executorKey: crypto.createPublicKey(keyring.keys[0].public_key_pem),
      sidecars: { provider_readback: fs.readFileSync(path.join(capture, 'readback.json'), 'utf8') },
    });
    assert.equal(r.present, true, `the capture carries no root: ${(r.failures || []).join('; ')}`);
    assert.ok(F().includes(`**${r.checks.length} checks**`),
      `§12 states a count that is not ${r.checks.length}, which is what the capture runs`);
  });

  it('the count is CONDITIONAL, and the doc says so rather than implying completeness', () => {
    // Provable without any sibling: a thinner artifact runs strictly fewer checks. That is the
    // property the prose has to carry, or "no failures" reads as "everything was checked".
    const minimal = probeBinding({ complete: false });
    const complete = probeBinding({ complete: true });
    assert.ok(complete.checks.length > minimal.checks.length,
      'precondition: a complete artifact must run more checks than a minimal one');
    assert.match(F(), /THE COUNT IS CONDITIONAL/,
      '§12 does not state that the check count depends on what the artifact carries');
    assert.match(F(), /MUST read `checks\[\]`/,
      '§12 does not tell an implementer to read the check list rather than a count');
  });

  it('the boundary is stated: the root does not authenticate a token', () => {
    assert.match(F(), /does \*\*not\*\* authenticate any individual token/i,
      '§12 does not state what the root fails to prove');
  });
});

/**
 * A signed artifact, built here so §12's counts are measured rather than recited.
 *
 * `complete: true` adds everything the conditional checks need — the optional slots, every claim,
 * the issuance grant object and the continuity identities — because the count the doc calls 19 is
 * a property of a COMPLETE capture, not of the format. Measuring it against a minimal artifact
 * produced 13 and would have made the doc's number look wrong when it was the probe that was thin.
 */
function probeBinding({ complete }) {
  const crypto = require('node:crypto');
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const correlation = {
    v: evidence.CORRELATION_V, scope_hash: 'sha256:s', contract_commit: 'c',
    contract_path: 'p', readback_commit: 'c',
  };
  const tokens = {
    chain_receipt: 'receipt-token',
    execution_grant: 'grant-token',
    transcript_token: 'transcript-token',
    correlation,
    atomic_attestation: complete ? 'attestation-token' : null,
    provider_readback: '{"commit":"c"}',
  };
  const claims = complete
    ? {
      grant_id: 'g-1', receipt_hash: `sha256:${crypto.createHash('sha256').update('receipt-token').digest('hex')}`,
      scope_hash: 'sha256:s', policy_hash: 'sha256:p', state_token_hash: 'st',
    }
    : {
      grant_id: null, receipt_hash: null, scope_hash: 'sha256:s', policy_hash: null,
      state_token_hash: null,
    };
  const evidenceRoot = root.buildEvidenceRoot({
    run_id: 'probe-run',
    executor_kid: 'PROBE-KEY',
    producer: { name: 'probe', version: '0', commit: null },
    operation: 'publish',
    target_uri: 'git://probe/repo.git',
    contract_commit: 'c',
    tokens,
    claims,
    privateKey,
  });
  const artifact = {
    run_id: 'probe-run',
    evidence_root: evidenceRoot,
    issuance: {
      chain_receipt: tokens.chain_receipt,
      execution_grant: tokens.execution_grant,
      ...(complete
        ? {
          grant: {
            v: 'cr.exec.v2', grant_id: 'g-1', scope_hash: 'sha256:s', policy_hash: 'sha256:p',
            receipt_hash: claims.receipt_hash, expected_state_token: 'st',
          },
        }
        : {}),
    },
    transcript_token: tokens.transcript_token,
    correlation,
    ...(complete
      ? { continuity: { identities: { issued_jti: 'g-1', consumed_jti: 'g-1', attestation_jti: 'g-1' } } }
      : {}),
  };
  return evidence.verifyEvidenceRootBinding(artifact, {
    executorKey: publicKey,
    sidecars: { provider_readback: tokens.provider_readback },
  });
}

describe('RECEIPT_FORMAT.md §13 documents the target-state transition', () => {
  const S = () => section('## 13. target_state_transition (bare-Git read-after-write)');
  const F = () => flat('## 13. target_state_transition (bare-Git read-after-write)');
  const SIBLING = path.join(__dirname, '..', '..', 'capability-demo');
  const OBSERVER = path.join(SIBLING, 'demo', 'src', 'git-observer.js');
  const GRADER = path.join(SIBLING, 'demo', 'src', 'target-state-transition.js');
  const have = fs.existsSync(OBSERVER) && fs.existsSync(GRADER);

  it('the honesty boundary is stated — and this half needs no sibling', () => {
    // The three tokens that keep a reader from carrying this home as a merged pull request. They
    // are prose in THIS repository, so they are gated unconditionally.
    const s = S();
    assert.ok(s.includes('TRUSTED_EXECUTOR'), '§13 omits proof_scope TRUSTED_EXECUTOR');
    assert.ok(s.includes('NOT_APPLICABLE'), '§13 omits provider_witness NOT_APPLICABLE');
    assert.match(s, /externally_witnessed\s+false/, '§13 omits externally_witnessed false');
    assert.match(F(), /NO PULL REQUEST WAS MERGED/,
      '§13 does not refuse the reading a reader is most likely to take');
    assert.match(F(), /neither established nor disproved/i,
      '§13 does not state that NOT_RUN is unproved rather than refuted');
  });

  it('the six correlations are each named', () => {
    const s = S();
    for (const id of ['after_state_token', 'blob_digest', 'content_sha256', 'state_transition',
      'single_parent', 'observer_mode', 'observation_source']) {
      assert.ok(s.includes(id), `§13 omits the correlation "${id}"`);
    }
  });

  it('the states, the observation version and the input contract match the producer', (t) => {
    if (!have) {
      // LOUD, and it names what did not run. A silent skip here would print a passing comparison
      // against a producer nobody looked at.
      t.skip('capability-demo is not checked out beside this repository — §13\'s prose was gated '
        + 'above, but its field sets were NOT compared against git-observer.js / '
        + 'target-state-transition.js. This is a NOT-RUN comparison, not a passing one.');
      return;
    }
    const observer = require(OBSERVER);
    const { STATE } = require(GRADER);
    const s = S();

    assert.ok(s.includes(observer.READBACK_V), `§13 omits the observation version ${observer.READBACK_V}`);
    for (const state of Object.values(STATE)) {
      assert.ok(s.includes(state), `§13 omits the state ${state}`);
    }
    // THE NUMERAL, and only the numeral. The spelled-out allowance here ("eight") was a hole:
    // a word cannot be compared against a count, so the day a verb was added the doc kept saying
    // eight and this line kept accepting it. It caught the drift only because the count changed
    // AND the word no longer matched — which is luck, not a gate.
    assert.ok(s.includes(`${observer.READ_ONLY_VERBS.length} read-only git verbs`),
      `§13 must state the verb count as a numeral; code has ${observer.READ_ONLY_VERBS.length}`);
    for (const k of observer.ALLOWED_INPUT) {
      assert.ok(s.includes(`\`${k}\``), `§13 omits the accepted observer input ${k}`);
    }
    assert.ok(s.includes(`${observer.FORBIDDEN_INPUT.length} names`)
      || s.includes(`sixteen names`) && observer.FORBIDDEN_INPUT.length === 16,
    `§13 states the wrong count of refused inputs (code has ${observer.FORBIDDEN_INPUT.length})`);
  });

  it('every field the observer emits is documented', (t) => {
    if (!have) {
      t.skip('capability-demo is not checked out beside this repository — the emitted field set '
        + 'was NOT compared. NOT RUN, not passed.');
      return;
    }
    // The SHAPE from a real observation, so what a consumer receives is what the doc describes.
    const { execFileSync } = require('node:child_process');
    const os = require('node:os');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rf13-'));
    try {
      const repo = path.join(dir, 'r.git');
      execFileSync('git', ['init', '-q', '--bare', repo]);
      const work = path.join(dir, 'w');
      execFileSync('git', ['init', '-q', work]);
      for (const [k, v] of [['user.email', 'a@b'], ['user.name', 'a']]) {
        execFileSync('git', ['-C', work, 'config', k, v]);
      }
      fs.writeFileSync(path.join(work, 'c.yaml'), 'x: 1\n');
      execFileSync('git', ['-C', work, 'add', '-A']);
      execFileSync('git', ['-C', work, 'commit', '-q', '-m', 'b']);
      execFileSync('git', ['-C', work, 'push', '-q', repo, 'HEAD:refs/heads/main']);
      const obs = require(OBSERVER).observeGitTarget({
        repoPath: repo, ref: 'refs/heads/main', contractPath: 'c.yaml',
      });
      const s = S();
      for (const key of Object.keys(obs)) {
        assert.ok(s.includes(`\`${key}\``), `the observer emits "${key}" but §13 does not document it`);
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
