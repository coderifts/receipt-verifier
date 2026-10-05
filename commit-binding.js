'use strict';

/**
 * P58 (2026-10-05) — is the receipt found for a commit actually ABOUT that commit?
 *
 * MEASURED (CC-2 T15): `--from-commit <sha>` found a sidecar by the SHA, verified the signature and the
 * envelope's body hash, and stopped there. A sidecar copied from an old commit to a force-pushed one
 * verified VERIFIED_CURRENT: nothing compared the envelope's `head` with the SHA asked about, or the
 * commit's contract files with the envelope's `artifact_digest`.
 *
 * WHAT CAN BE CHECKED, AND WHY ONLY THROUGH THE ENVELOPE. The receipt token signs no commit: its fields
 * are kid, fp, prev, caller, ts, reg, ir, expires_at, bh. The commit lives in the ENVELOPE (`head`,
 * `base`, `artifact_digest`), and v4's `bh` signs the envelope — so once the signature check has passed
 * with the envelope supplied, its `head` and `artifact_digest` are signed facts, and can be compared:
 *
 *   head      envelope.head must name the commit asked about: the full SHA, or — when the envelope
 *             carries an abbreviation of 7 to 39 hex characters — a prefix of it. Otherwise
 *             RECEIPT_COMMIT_MISMATCH, naming both.
 *   content   only with --contract <path> (repeatable): the envelope names no file (the bundle id is a
 *             caller's label, e.g. 'api'), so the operator names the contract file(s). The verifier
 *             reads each at `base` and at the commit (git show), recomputes the app's artifact_digest —
 *             sha256 over each artifact's sha256(before) ‖ sha256(after), joined with U+001F — and
 *             compares. With several files the receipt's artifact order (sorted by type and id) is not
 *             known here, so every order is tried (at most 6 files). Otherwise CONTENT_MISMATCH.
 *             Without --contract the content is reported as not_checked.
 *
 * LIMITS, said rather than hidden:
 *   - a sidecar WITHOUT an envelope carries nothing that names the commit → RECEIPT_NOT_BOUND_TO_COMMIT;
 *   - a TRAILER without an envelope is inside the commit object, but `git commit --amend` keeps the
 *     message (and the trailer) while changing the files, so it binds nothing the verifier can check;
 *     its verdict is left as it was, and stderr says so;
 *   - an envelope without `head` (a receipt issued with no commit in its context) cannot be bound.
 */

const { execFileSync } = require('node:child_process');
const crypto = require('node:crypto');

const US = '\x1f';
const MAX_CONTRACT_FILES = 6;

const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');

function showAt(rev, file, cwd) {
  try {
    return execFileSync('git', ['show', `${rev}:${file}`], { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 64 * 1024 * 1024 });
  } catch (_) {
    return '';   // absent at that revision: the app hashes an absent side as ''
  }
}

function permutations(list) {
  if (list.length <= 1) return [list];
  return list.flatMap((x, i) => permutations([...list.slice(0, i), ...list.slice(i + 1)]).map((p) => [x, ...p]));
}

/** The commit an envelope names matches `sha` (full, or an abbreviation of 7–39 hex characters). */
function headMatches(head, sha) {
  const h = String(head || '').toLowerCase();
  const s = String(sha).toLowerCase();
  if (h.length === 40) return h === s;
  return /^[0-9a-f]{7,39}$/.test(h) && s.startsWith(h);
}

/**
 * @param {{ sha: string, carrier: 'trailer'|'sidecar'|'both', envelope: object|null, cwd: string, contracts?: string[] }} o
 * @returns {{ status: 'BOUND'|'FAILED'|'UNCHECKED', code?: string, reason?: string, head: string, content: string, note?: string }}
 */
function checkCommitBinding({ sha, carrier, envelope, cwd, contracts = [] }) {
  if (!envelope) {
    if (carrier === 'sidecar') {
      return { status: 'FAILED', code: 'RECEIPT_NOT_BOUND_TO_COMMIT', head: 'absent', content: 'not_checked',
        reason: `the sidecar for ${sha} carries no envelope, so nothing in it names that commit; a receipt copied there from any other commit would look the same` };
    }
    return { status: 'UNCHECKED', head: 'not_checked', content: 'not_checked',
      note: 'commit binding: the trailer carries no envelope, so the receipt names no commit and no content to check; '
        + 'an amended commit keeps the trailer while its files change. Attach the envelope in a sidecar to bind it.' };
  }
  if (!envelope.head) {
    return { status: 'FAILED', code: 'RECEIPT_NOT_BOUND_TO_COMMIT', head: 'absent', content: 'not_checked',
      reason: `the envelope names no commit (no head), so it cannot be bound to ${sha}` };
  }
  if (!headMatches(envelope.head, sha)) {
    return { status: 'FAILED', code: 'RECEIPT_COMMIT_MISMATCH', head: 'mismatch', content: 'not_checked',
      reason: `the receipt is for commit ${envelope.head}, and it was asked about ${sha}` };
  }
  if (!contracts.length) {
    return { status: 'BOUND', head: 'match', content: 'not_checked',
      note: 'commit binding: the head matches; the content was not checked (name the contract file with --contract <path>)' };
  }
  if (!envelope.artifact_digest || !envelope.base) {
    return { status: 'FAILED', code: 'CONTENT_MISMATCH', head: 'match', content: 'unverifiable',
      reason: `the envelope carries no ${envelope.artifact_digest ? 'base' : 'artifact_digest'}, so ${contracts.join(', ')} cannot be checked against it` };
  }
  if (contracts.length > MAX_CONTRACT_FILES) {
    throw new Error(`--contract: at most ${MAX_CONTRACT_FILES} files (the artifact order is tried exhaustively)`);
  }
  const arts = contracts.map((f) => ({ file: f, before: showAt(envelope.base, f, cwd), after: showAt(sha, f, cwd) }));
  const match = permutations(arts).some((order) => `sha256:${sha256hex(order.map((a) => `${sha256hex(a.before)}${sha256hex(a.after)}`).join(US))}` === envelope.artifact_digest);
  if (!match) {
    return { status: 'FAILED', code: 'CONTENT_MISMATCH', head: 'match', content: 'mismatch',
      reason: `${contracts.join(', ')} at ${envelope.base.slice(0, 12)}…${sha.slice(0, 12)} do not hash to the receipt's artifact_digest ${envelope.artifact_digest}` };
  }
  return { status: 'BOUND', head: 'match', content: 'match' };
}

module.exports = { checkCommitBinding, headMatches };
