# Changelog

Versions here are the npm package `@coderifts/receipt-verifier`. Entries land before the release
that carries them; a heading with no tag has not been published.

## Unreleased — next minor

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
