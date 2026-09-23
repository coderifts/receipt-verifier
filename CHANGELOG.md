# Changelog

Versions here are the npm package `@coderifts/receipt-verifier`. Entries land before the release
that carries them; a heading with no tag has not been published.

## Unreleased — next minor

### `--from-commit <sha>` — read the receipt off a commit (1961 TAG 1)

**Added.** Resolves the receipt attached to a commit and verifies it exactly as a pasted token:
the `CodeRifts-Receipt` git trailer, or `.coderifts/receipts/<full-sha>.json`. `--repo <path>`
points at a repository other than the working directory. The convention — both carriers, the
precedence, and what it does not prove — is `docs/receipt-commit-binding.md`.

**Why it did not exist.** Measured 2026-09-23 across `coderifts-app`, this repository and
`coderifts-contract-gate`: zero occurrences of a receipt trailer or sidecar. `commit_observation`
and `after_state_token` already join a receipt to a commit AT DECISION TIME, inside the guard;
nothing answered the other direction — "given this SHA in history, which receipt authorised it".

**The trailer wins, and a disagreement is REFUSED.** The trailer is covered by the commit SHA and
the sidecar is not, so where both exist the immutable one is authoritative. Where they *disagree*,
neither is used: silently preferring the trailer would hide exactly the tampering the precedence
rule exists to expose.

**A missing receipt is a USAGE error (exit 2), not a verdict.** "No receipt is attached" is not a
statement about a receipt — there is none to have an opinion about — so no `valid:false` document
is emitted. And a forged sidecar yields `INVALID_SIGNATURE`, not a false pass: the sidecar is a
pointer, the signature is the authority.

### `--json` — keep `2>&1` parseable (1961 TAG 9)

**Added, and it is not what it sounds like.** stdout was ALREADY pure JSON on every verdict path,
so a flag meaning "print JSON" would be a no-op. What it buys is a clean pair of streams: this CLI
writes human notes to stderr (the legacy-key warning, and `receipt for <sha> via <carrier>`), and a
caller capturing `2>&1` — which people do — gets them mixed into what they are about to parse.

**It never silences an error.** Usage failures still write to stderr and still exit 2. A flag
asking for machine-readable output must not turn a failure into a script that looks like it worked.

### Cross-language corpus: one more grant mutation (1961 TAG 3)

`EG2-OPERATION-MISMATCH` added to `test/gen-grant-vectors.js`. The 9×3 mutation matrix showed
`operation` was covered only INDIRECTLY, through `EG-SCOPE-MISMATCH` (operation feeds
`computeScopeHash`). Indirect coverage proves the hash noticed, not that the verifier names the
dimension a reader should look at — and measured against `verify-grant.js`, it already had a
dedicated `operation_mismatch` reason that no vector exercised. `test/grant-kernel-verdicts.json`
regenerated as a consequence (11/11 still agree with the app kernel).

Version unchanged; the next minor carries all of this.

### `REGISTRY_UNREACHABLE` is now reachable from the CLI (1961/7.2)

**Added, additive.** A MANDATORY key discovery that fails — `--refresh-keys`, `--fetch <url>`, or
`--keys <url>` — now emits a structured verdict on stdout and exits `1`:

```json
{ "valid": false, "status": "REGISTRY_UNREACHABLE", "reason": "registry_unreachable",
  "registry_unreachable": { "source": "…", "why": "…", "remedy": "…" } }
```

Previously that path exited through the CLI's usage handler: free text on stderr and exit `2`, the
same shape as a mistyped flag. A caller parsing stdout got no status at all, and a caller reading
only the exit code could not tell a registry outage from its own typo. Where a stale or empty
keyring did reach the verifier, the receipt came back `UNKNOWN_KEY` — which reads as "signed by a
key we do not publish", i.e. forgery-shaped, when the truth was "we could not ask".

**Nothing is loosened.** Both the old and the new answer are `valid: false`. What changes is where
an operator is sent: `REGISTRY_UNREACHABLE` points at the network, `UNKNOWN_KEY` at the signer.
The status has been normative in `RECEIPT_FORMAT.md` §7.1 the whole time — this is the code
catching up with the published format, not a new state.

**Older verifiers treat it as unknown → fail-closed.** A consumer pinned to the previous status
list does not recognise `REGISTRY_UNREACHABLE`, and an unrecognised status is not valid: every
implementation names its accepting statuses explicitly rather than denying a blacklist. The
addition cannot turn anything green anywhere.

**The offline path is deliberately untouched.** An unreadable *local* `--key` / `--keys <file>`,
or a corrupt vendored snapshot, remains a usage error (exit `2`). Dressing an operator's own bad
path as a registry outage would send them to the network to debug a filename. The cross-language
corpus carries that negative control as
`OFFLINE_PINNED_REGISTRY_UNREACHABLE_IS_NOT_A_FAILURE`.

**Cross-language corpus.** `test/gen-xlang-vectors.js` now emits a top-level `discovery` block,
alongside the existing `dsse` block and *outside* `vectors[]`. Discovery cases are not token
verdicts — there is no keyring to verify against, because discovery itself failed — so filing one
as a vector would make every consumer record `UNKNOWN_KEY` for it, the exact conflation the case
exists to separate. Because the block is top-level, `structureOf` in
`test/xlang-corpus-sync.test.js` is unaffected and every existing copy of the corpus still
matches: a consumer that does not know the block simply does not run those cases.
