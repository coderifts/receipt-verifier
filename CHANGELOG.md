# Changelog

Versions here are the npm package `@coderifts/receipt-verifier`. Entries land before the release
that carries them; a heading with no tag has not been published.

## 1.1.7 — unreleased

### Strict parse: parser differentials are rejected

**Added.** `parseJsonStrict(text)` in `verify.js`, exported beside `canonicalJson`. It parses RFC 8259 text and
throws a `SyntaxError` with `.code` and an RFC 6901 `.pointer` on a duplicate member name at any depth
(`duplicate_key`), an unpaired UTF-16 surrogate (`lone_surrogate`) or a number that is not finite as binary64
(`non_finite`); anything else that is not one JSON text is `invalid_json`. On valid input it returns what
`JSON.parse` returns. Existing callers are unchanged: `canonicalJson` and `--envelope` still use `JSON.parse`.
The policy (reject, not pick a reading) is RECEIPT_FORMAT §2.2. Measured against purysho/mcp-digest-vectors
(4ec1041): `JSON.parse` keeps the last duplicate, so a full-object pin over a duplicate `description` with the
malicious value first pins the safe text; `parseJsonStrict` rejects all six parse-level reject vectors there.
The CodeRifts MCP lock does not use this canonicalizer (its input is parsed in the app's `packages/cli`), so
nothing here changes the lock.

### Canonicalization vectors: NFC/NFD and `_meta`/`annotations` churn

**Added.** `RFC8785-17` (the same visible "café" in NFC and NFD: different canonical strings, no Unicode
normalization) and `RFC8785-18` (a tool whose `_meta` and `annotations` changed: the full-object digest changes),
each with a `label` and the two `differ` members. 18 vectors; `verify.py` agrees on 18 of 18. The README now
states the lone-surrogate policy: `canonicalJson` passes an unpaired surrogate through and writes `\udxxx`.

### Fixes

- RECEIPT_FORMAT §7: a receipt at or after a retired key's `retired_at` is `KEY_RETIRED_AFTER_SIGNING` in both
  verifiers, not `INVALID_SIGNATURE` as the key-registry bullet said.
- Release workflow: the post-publish registry readback waits 30 × 20 s (was 18 × 10 s, which failed the 1.1.6
  job after a successful publish). It passes as soon as `npm view <pkg>@<version> version` prints the version.

## 1.1.6 — 2026-10-29

### `--as-of`: was the receipt inside its window at a stated instant?

**Added.** `--as-of <ISO 8601>` on the CLI and `asOf` in `verifyReceipt(token, { ctx, asOf })` (beside `ctx`, where `envelope` sits; audit mode). The expiry
comparison uses the given instant instead of now; the signature, the key lookup, every key-status rule
(RECEIPT_FORMAT §7.1 — a revoked key is `valid:false` at any as-of; a retired key as before, with the
same window), the envelope
binding and the chain rule are unchanged. The verdict adds `mode: "audit"`, `as_of`, `valid_at_as_of`,
`expired_now` and `window {ts, expires_at}`; status `VERIFIED_AT_AS_OF` inside the window,
`NOT_YET_VALID_AT_AS_OF` (`valid:false`) before the receipt's `ts`, `VERIFIED_EXPIRED` after the window.
Exit 0 when `valid_at_as_of`, 1 otherwise; an unparsable instant or one later than now + 30s is exit 2
(`as_of_in_future`). A v1–v3 receipt keeps its result, with `as_of_note`. Works with `--from-commit` and
`--envelope`; not with `--chain`. `does_not_prove` gains, in audit mode only: "that the window was still
open when you read this: as-of evaluates a stated instant, not now". `verify.py` has no as-of.

Why: a v4 merge receipt expires after 4 h, so the ordinary answer to "was the action inside the grant at
the time?" became `VERIFIED_EXPIRED` once the TTL had passed (asked about the public coderifts/demo #36
receipt).

### RFC 8785 canonicalization vectors

**Added.** `test/vectors/rfc8785.json` (16 vectors, computed by `verify.js` `canonicalJson`, with
`test/gen-rfc8785-vectors.js`) and `test/rfc8785-vectors.test.js`.

### `verify.py` canonical JSON is RFC 8785, byte-identical to `verify.js`

**Fixed.** Measured on the vectors above: `verify.py` `canonical_json` agreed on 11 of 16. It sorted keys
by code point, not UTF-16 code units (an astral-plane key against a BMP key above the surrogates), and
wrote numbers as Python does (`1e+20`, `1e-07`, `-0.0`, `100.0`, an integer above 2^53 kept exact). It now
sorts by UTF-16 code units and writes numbers as ECMAScript `Number::toString`, and strings as
`JSON.stringify` (lone surrogates escaped). 16 of 16, checked by `test/test_rfc8785_vectors.py`. An integer
too large for a double is now refused as non-finite, as in `verify.js`. `verify.py` uses this for the
`--envelope` body hash; every envelope fixture in this tree hashes the same before and after (measured).
`verify.js` is unchanged.

### Expiry applies under a retired key

**Fixed.** A v4 receipt signed by a retired key before `retired_at` returned `RETIRED_KEY_VALID_AT_ISSUE`
before the expiry check, so once its window had closed it still verified `valid: true`. The expiry rule now
applies after the retired-key rule, in `verify.js` and `verify.py`: past `expires_at + 30s` it is
`VERIFIED_EXPIRED` (`valid: false`); inside the window it is `RETIRED_KEY_VALID_AT_ISSUE` as before; `--as-of`
evaluates the same window at the stated instant (RECEIPT_FORMAT §7). v1–v3 receipts, including the
`2026-07-k1` fixture, are unaffected.

## 1.1.5 — 2026-10-25

### The pinned keyring is the live registry

**Changed.** `keys/coderifts-keys.json` is the bytes of `https://app.coderifts.com/.well-known/coderifts-keys.json`
as served on 2026-10-25: `2026-10-k1` active and `2026-07-k1` retired at `2026-10-21T00:00:00.000Z`, with
`valid_from` and `retired_at` carried. A receipt signed by `2026-07-k1` before that date (the fixture, signed
2026-08-26) is now `RETIRED_KEY_VALID_AT_ISSUE` (`valid: true`) with no flags, where 1.1.4's pin still said the
key was active (`VERIFIED_CURRENT`).

### Only an Ed25519 key verifies a receipt, in both ports

**Changed.** The key algorithm is read from the PEM's SPKI AlgorithmIdentifier, by the same few lines in
`verify.js` and `verify.py`. Any other algorithm, or a registry entry that declares an `alg` other than
Ed25519 (even over an Ed25519 PEM), is `valid: false`, `INVALID_SIGNATURE`, reason
`unsupported key algorithm: <alg>`. No new status.

**Why.** Measured 2026-10-25 on 1.1.4 with Node 24.12: a receipt signed with ML-DSA-65 under a registry entry
carrying an ML-DSA-65 PEM was `{ valid: true, VERIFIED_CURRENT }` in JS; `verify.py` refused the same keyring
by raising at load time.

### A bad registry entry is skipped, not fatal

**Changed.** A registry entry with an unparseable PEM, no `public_key_pem` or no `kid` is skipped, and the
verdict names it in `keyring_warnings`; the other keys still verify. A registry with no usable key at all is
still an error (exit 2). Measured on 1.1.4: one such entry made the whole keyring fail to load
(`could not load public key`, exit 2), so the good key beside it verified nothing.

### The verdict names the key that verified it

**Added.** A valid receipt verdict carries `verified_with: { kid, key_sha256, keyring_source }` — the sha256
of the verifying key's SPKI DER, and `file`, `url` or `pinned-snapshot`, decided where the CLI loads the
keys. `does_not_prove` gains a fifth sentence: that the keyring is authentic — the output names the key and
where the keyring came from, not who published it. Both are additive; JS and Python print the same bytes.

**Docs.** README: what `KEY_RETIRED_AFTER_SIGNING` means (the key was already retired when the receipt says
it was signed; the name is kept).

## 1.1.4 — 2026-10-18

### A receipt verified beside an envelope must be v4, in the core

**Changed.** A receipt verified beside an envelope must be v4. The rule moves from the CLI into
`verifyReceipt`, so every consumer of the core gets it. With `opts.envelope` present (any object, `{}`
included) and a receipt that verifies at a version other than 4, `verifyReceipt` returns
`RECEIPT_VERSION_UNSUPPORTED`, with `signature_status` set to the bare verdict and the same reason
text the CLI printed. A bare token with no envelope is still a signature check, and `verifyChain` is
unchanged. `verify.py` gets the same rule in `verify_receipt` and in its CLI.

**Why.** Measured 2026-10-17: two public gateways that vendored this core (v1.0.3) admitted a real,
production-signed v2 receipt beside a forged ALLOW envelope, because `verifyReceipt` answered
`valid: true`. The 1.1.1 entry below says `verify.js`, `verify.py` and the CLI report
`RECEIPT_VERSION_UNSUPPORTED`; measured on 1.1.3, only `cli.js` did.

### The receipt verdict carries `does_not_prove`

**Added.** The receipt verdict carries `does_not_prove`: `cli.js <token>` (and `verify.py`) end the
verdict with the published limits of a verified receipt token, verbatim (README "What it does NOT
prove", and the receipt scope the app and the SDK publish). The array is appended, so no other field
moves. A `--chain` verdict and the bundle, attestation and DSSE verdicts are unchanged.

## 1.1.3 — 2026-10-12

### Test-only release: the release workflow runs on a bare checkout

**Changed.** Nothing at run time. `test/xlang-corpus-sync.test.js` failed on the release runner because
a bare checkout has no sibling corpus copies; it now skips that case by name ("nothing was compared")
and still fails when a present copy disagrees. The `v1.1.1` and `v1.1.2` tags name no npm package:
every earlier run of the release workflow, including `v1.1.0`, stopped at its test step, and 1.1.0
was published by hand. This version carries the 1.1.1 change below.

## 1.1.2 — 2026-10-12

### Test-only release

**Changed.** Nothing at run time. `test/release-check.test.js` pinned the version `1.1.0` by hand, so
the `v1.1.1` release run failed at its own test step and published nothing; the test now reads the
version from `package.json`. The `v1.1.1` tag stays in the repository and names no npm package.
The 1.1.1 entry below is what this version carries.

## 1.1.1 — 2026-10-12

### A receipt below v4 is not authorization (P66, 2026-10-12)

**Changed.** `verify.js`, `verify.py` and the CLI report `RECEIPT_VERSION_UNSUPPORTED` for a receipt
whose version is below 4: those versions do not bind the request envelope and carry no expiry, so a
valid signature on them proves that the server signed something, not what was asked. A signed field
that is not a string (for example `expires_at` given as an array) is `MALFORMED`. Tests:
`test/p66-version-and-field-types.test.js`. Trust-center entry P66 (2026-10-12).

## 1.1.0 — 2026-10-06

### The usage text names the bin (T19, 2026-10-06)

**Changed.** `--help` and every usage error print `coderifts-receipt-verifier …`, the command the npm
package installs, instead of `node cli.js …`, which exists only in a clone (where it still works).

### Published on npm (T18, 2026-10-06)

**Added.** The package is installable: `npx @coderifts/receipt-verifier <receipt>` (or
`npm i -g @coderifts/receipt-verifier`, then `coderifts-receipt-verifier`). Until now it was
`"private": true` and npm answered 404 for its name, while every CodeRifts App comment printed
`npx @coderifts/receipt-verifier` as the command to run. `package.json`: the
`coderifts-receipt-verifier` bin (`cli.js`), `main`/`exports` for every library module and the vendored
keyring, a `files` allowlist (no tests, no Python), `engines.node >= 18`, public with provenance.
Published from `.github/workflows/release.yml` on a `v*` tag, after `scripts/release-check.js`:
the keyring against its `.sha256`, the tag against the version, the packed tarball against the files
the CLI loads, and the installed package against the fixture receipt and the P58 repro.
`test/release-check.test.js`.


### `--from-commit`: the receipt must be about that commit (P58, 2026-10-05)

**Fixed.** An old receipt's sidecar copied beside a force-pushed SHA verified `VERIFIED_CURRENT`
(measured in CC-2 T15): nothing compared the envelope's `head` with the SHA asked about. Now, after the
signature verifies, `--from-commit` requires the signed envelope's `head` to name that commit
(`RECEIPT_COMMIT_MISMATCH` otherwise), and with `--contract <path>` (repeatable) recomputes
`artifact_digest` from the file(s) at `base` and at the commit (`CONTENT_MISMATCH` otherwise). A sidecar
without an envelope is `RECEIPT_NOT_BOUND_TO_COMMIT`. A trailer without an envelope keeps its verdict
and says on stderr that it binds no content. The output carries `commit_binding`; on a failure
`signature_status` keeps the signature's own verdict. `commit-binding.js`;
`test/from-commit-p58-binding.test.js`.

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
