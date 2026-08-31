# CodeRifts receipt-verifier

**Verify the receipt yourself — offline, no live CodeRifts API call needed.**

Every CodeRifts verdict response can carry a signed `chain_receipt`. This repo is
a tiny, independent verifier -- one file in Node, one in Python -- that checks a
receipt's signature (and, optionally, a whole chain of them) against the
published Ed25519 public key. If verification passes, the verdict provably came
from the holder of the CodeRifts signing key and, in a chain, follows an unbroken
link from the previous receipt. You do not have to take our word for it, and you
do not need any API key to check.

The exact byte format is frozen in [RECEIPT_FORMAT.md](RECEIPT_FORMAT.md).

## What it checks

- The receipt is a well-formed `base64url(body).base64url(signature)` token.
- The `body.kid` matches the active published key id.
- The raw Ed25519 signature verifies over the exact signed bytes
  (`crchain.v1|kid|fp|prev|caller|ts`; v2 appends `|reg`; v3 appends `|reg|ir`;
  v4 appends `|reg|ir|expires_at|bh`). The `crchain.v1` prefix is the signed-format
  tag (not the envelope version) and does not change for v4 — see
  RECEIPT_FORMAT.md section 3. Version nesting is v1 ⊂ v2 ⊂ v3 ⊂ v4: a
  lower-version verifier never accepts a higher-version receipt.
- For a chain: every receipt's signature is valid AND each non-genesis link's
  `prev` equals `sha256:` + SHA-256 of the previous token string.
- **v4 envelope binding** (optional `--envelope <file>`): the verifier recomputes
  `sha256:` + SHA-256 of the RFC 8785 (JCS) canonical decision envelope with
  `receipt` and `decision_body_hash` removed, and requires it to equal `bh`.
  Mismatch ⇒ reason `body_hash_mismatch`. Independently, when `expires_at` is
  present and `expires_at + 30s` (clock-skew leeway; `CLOCK_SKEW_LEEWAY_MS`) is
  in the past, `status` is `VERIFIED_EXPIRED` (signature may still be authentic;
  `valid` is false for that status). 0s leeway for destructive operations in
  production when the intended context declares them — this offline verifier has
  `environment` (envelope / `--environment`) but no destructive / operation_class
  field, so it always uses the 30s default (never guessed from operation labels).
  v4 is issued only on
  envelope-bearing paths (bundle + MCP single-spec); see RECEIPT_FORMAT.md.

It does NOT recompute the verdict fingerprint `fp` from a verdict payload; `fp`
is verified as an opaque, signed binding (see RECEIPT_FORMAT.md section 2).

## Requirements

- Node: >= 20 (zero dependencies; uses `node:crypto` only).
- Python: >= 3.10 with the `cryptography` package (`pip install cryptography`).

## Quickstart (Node)

```
# Get a verdict and its receipt (this endpoint needs no API key), then verify.
RECEIPT=$(curl -s -X POST https://app.coderifts.com/api/v1/action-verdict \
  -H 'Content-Type: application/json' \
  -d '{"action_type":"tool_call","provenance":{"channel":"ci_manifest","issuer_trust":"trusted"},"tool":{"name":"get_customer","capabilities":["read"]},"memory":{"op":"read","namespace":"working","staleness_hours":1}}' \
  | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>process.stdout.write(JSON.parse(s).chain_receipt))")

# The public key is discovered from the attestation endpoint automatically.
node verify.js "$RECEIPT"
```

Output (exit code 0 = valid, 1 = invalid, 2 = usage error). The `action-verdict`
endpoint issues `v:2` receipts (they carry `reg`):

```
{"valid":true,"payload":{"v":2,"kid":"2026-07-k1","fp":"sha256:...","prev":"null","caller":"anon","ts":"...","reg":"..."}}
```

Receipts from the `/diff` endpoint and the GitHub PR-check webhook are `v:3` — they
additionally carry `ir` (the Change-IR hash), e.g. the demo receipt below.

## Quickstart (Python)

```
RECEIPT=$(curl -s -X POST https://app.coderifts.com/api/v1/action-verdict \
  -H 'Content-Type: application/json' \
  -d '{"action_type":"tool_call","provenance":{"channel":"ci_manifest","issuer_trust":"trusted"},"tool":{"name":"get_customer","capabilities":["read"]},"memory":{"op":"read","namespace":"working","staleness_hours":1}}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['chain_receipt'])")

python3 verify.py "$RECEIPT"
```

## Offline verification (no network)

Pin a public key you trust and pass it with `--key`; nothing is fetched:

```
# Save the current public key once (or commit a PEM you have pinned).
curl -s https://app.coderifts.com/api/v1/attestation/public-key \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['public_key_pem'])" > pub.pem

node verify.js "$RECEIPT" --key pub.pem --kid 2026-07-k1
python3 verify.py "$RECEIPT" --key pub.pem --kid 2026-07-k1
```

## Verifying a chain

Put one token per line, oldest first, then:

```
node verify.js --chain receipts.txt --key pub.pem --kid 2026-07-k1
python3 verify.py --chain receipts.txt --key pub.pem --kid 2026-07-k1
```

The first receipt is reported as `genesis` (its `prev` is the literal `null`) or
`continuation` (it links to a token you did not supply). Every later link is
checked against the SHA-256 of the token before it.

## Verify the live demo receipt

The demo pull request (`coderifts/demo` PR #4) carries a live `v:3` receipt in its
CodeRifts check comment. Copy that token and verify it — keys are fetched from
the published registry automatically, so this is the one command a reader
runs to confirm the demo verdict is genuine:

```
node verify.js "<paste the receipt token from the PR comment>"
# or, fully offline against the key registry:
node verify.js "<token>" --keys https://app.coderifts.com/.well-known/coderifts-keys.json
```

Both print `{"valid":true,...}` and exit `0` for a genuine receipt.

## Key registry (verify across rotation)

Instead of a single pinned key, resolve the signing key by the receipt's `kid`
from the published append-only registry. This keeps receipts issued under a
now-retired key verifiable:

```
node verify.js "$RECEIPT" --keys https://app.coderifts.com/.well-known/coderifts-keys.json
python3 verify.py "$RECEIPT" --keys https://app.coderifts.com/.well-known/coderifts-keys.json

# or against a local copy of the registry:
node verify.js "$RECEIPT" --keys coderifts-keys.json
```

The registry is `{ "keys": [ { "kid", "public_key_pem", "status", "valid_from" } ] }`.
`--key` and `--keys` are mutually exclusive.

## Evidencing a REFUSAL

Every artifact in this family attests something that happened — a decision, a grant, a commit, a
coverage observation. A refusal can look like it produces nothing, so an operator wanting to show
*"the agent tried to deploy and the gate stopped it"* assumes they have only their word for it.

**They do not.** A `BLOCK` mints a signed receipt exactly like an `ALLOW`, and this verifier already
checks it — no extra tooling, no separate artifact family.

The receipt payload alone will not tell you which it was: an `ALLOW` receipt and a `BLOCK` receipt
have the **same field set**, and neither carries the verdict. What carries the verdict is the
`decision_result` envelope, and `payload.bh` binds it. So refusal evidence is **two files**:

```bash
# the receipt, plus the envelope it was minted for
node verify.js "$(cat receipt.txt)" --envelope decision_result.json
# -> {"valid":true,"status":"VERIFIED_CURRENT", ...}
```

The verifier recomputes the envelope's canonical body hash (RFC 8785, with `receipt` and
`decision_body_hash` removed) and requires it to equal `payload.bh`. Passing means the envelope in
front of you is the one that receipt was issued for. Read the verdict from that envelope:
`decision`, `execution_action`, `operation`, and `blocking_reasons`.

Editing the envelope breaks the binding — flipping `"decision":"BLOCK"` to `"ALLOW"` returns
`INVALID_SIGNATURE` / `body_hash_mismatch`. That is what makes it evidence rather than a claim.

**What this proves:** at the signed timestamp, a caller presented this change set under this
intended operation, the gate returned this verdict, and the envelope has not been altered since.

**What it does NOT prove** — and the distinction matters more here than anywhere else in this
document: **it does not prove the agent then stopped.** It is evidence about a decision we issued,
never about what the caller did next. An agent that received `STOP` and shipped anyway through some
other path produces exactly this same receipt. Nothing in this family observes execution that did
not come back through us; a refusal receipt is proof of what the gate *said*, not of what the world
*did*. If you need evidence that the guarded path is the only path, that is a different question —
see `@coderifts/bypass-probe`, which measures it at your own installation and reports what it could
not reach.

## Verifying an execution grant

A `cr.exec.v1` grant is the short-lived, mutation-bound sibling of a chain
receipt. This repo ships `verify-grant.js` / `verify_grant.py` as the public,
dependency-light verifiers (same CLI feel as `verify.js` / `verify.py`).

**What `GRANT_CURRENT` proves / does not prove** (from
`coderifts-app/docs/cr-exec-v1.md`):

- Proves: an Ed25519 signature under a published `kid` covers the grant body;
  the grant names a `receipt_digest` (sha256 of a receipt token) — it is
  *derived from* a receipt, not a replacement; `exp` has not passed (30s
  clock-skew leeway); if you supplied intended audience / operation /
  target_id / after-payload (or `scope_hash`), those match.
- Does **not** prove: that any gateway, agent host, or CI check *enforced* the
  grant; that the underlying receipt is currently authorized (re-check the
  receipt with `verify.js`); one-use / atomic consumption; proof-of-possession
  (`cnf` is reserved, unimplemented).
- **Bearer / replay / TTL.** Within TTL, a stolen grant authorizes the same
  operation/target/after-shape for any presenter. Replay against the same
  target is possible for bearer grants; deploy one-use profiles where atomicity
  is required. Default TTL is 300s.
- Retired `kid` → `UNKNOWN_KEY`. Grants are live execution permission;
  receipts may forensically verify a retired key, grants must not.

```
# Node (zero deps). --keys is the registry; --key pins a PEM like verify.js.
node verify-grant.js "$GRANT" --keys https://app.coderifts.com/.well-known/coderifts-keys.json \
  --intended-operation merge --intended-target "$TARGET" --intended-audience "$AUD" \
  --intended-after-file after.txt --receipt "$RECEIPT"

# Python (cryptography, same as verify.py).
python3 verify_grant.py "$GRANT" --keys https://app.coderifts.com/.well-known/coderifts-keys.json \
  --intended-operation merge --intended-target "$TARGET" --intended-audience "$AUD" \
  --intended-after-file after.txt --receipt "$RECEIPT"
```

Exit `0` iff `status` is `GRANT_CURRENT`. JSON on stdout matches across JS and
Python (`valid`, `status`, `reason?`, decoded `payload`).

## Verifying an execution attestation

A `cr.exec.attest.v1` token is the executor's signed commit statement — the
fourth chain artifact. Public verifiers: `verify-attest.js` / `verify_attest.py`.
Format freeze: [RECEIPT_FORMAT.md](RECEIPT_FORMAT.md) (attestation section) and
`coderifts-app/docs/cr-exec-attest-v1.md`.

Executor keys are **CUSTOMER-HELD**. `--keys` is **REQUIRED** (a registry file
or URL). There is no default fetch — CodeRifts does not hold these keys.

**Honesty (verbatim class from the spec):**

The attestation proves:

> a holder of the executor key asserts this commit

It does **NOT** prove:

- that the executor's code is unmodified (**deploy attestation is out of
  scope**, named as such — a later artifact, not this one);
- that a human saw anything;
- that the underlying grant is currently `GRANT_CURRENT` (re-check the grant
  if live permission is required; this statement is historical);
- that `result_digest` is a CodeRifts fingerprint, a receipt digest, or an
  after-payload hash — `result_digest` is the executor's choice of bytes.

Retired `kid` uses the **receipt-class historical rule**:
`ATTEST_RETIRED_KEY_VALID_AT_ISSUE` when `committed_at` is inside
`[valid_from, retired_at)`. Grants must not (live permission → `UNKNOWN_KEY`).

```
# --keys is required (customer-pinned executor registry). No default fetch.
node verify-attest.js "$ATTEST" --keys executor-keys.json
python3 verify_attest.py "$ATTEST" --keys executor-keys.json

# Optional cross-checks against the grant / receipt digest held by the caller:
node verify-attest.js "$ATTEST" --keys executor-keys.json \
  --grant "$GRANT" --receipt-digest sha256:…
```

Exit `0` iff `status` is `ATTEST_VALID` or `ATTEST_RETIRED_KEY_VALID_AT_ISSUE`.
JSON on stdout matches across JS and Python.

Statuses: `ATTEST_VALID`, `ATTEST_INVALID_SIGNATURE`, `ATTEST_UNKNOWN_KEY`,
`ATTEST_RETIRED_KEY_VALID_AT_ISSUE`, `ATTEST_MALFORMED`, `ATTEST_UNBOUND`.

## DSSE / in-toto export (`to-dsse.js`)

A compact receipt or execution attestation can be exported as a **DSSE envelope**
carrying an in-toto Statement, so a system that already speaks in-toto (SLSA
tooling, policy engines, admission controllers) can accept it without learning
the compact format. Format freeze:
[RECEIPT_FORMAT.md](RECEIPT_FORMAT.md) section 9.

```js
const { toDSSE, fromDSSE } = require('./to-dsse.js');

const envelope = toDSSE(token);          // wrap — nothing is signed or checked here
const back = fromDSSE(envelope);         // unwrap — byte-exact: back === token
verifyReceipt(back, { keyring });        // the SAME verifier decides, unchanged
```

| field | value |
| --- | --- |
| `payloadType` | `application/vnd.in-toto+json` |
| `predicateType` | `https://coderifts.com/attestations/agent-action-authorization/v1` |

The export is **optional**; the compact form stays primary. `signatures[0].sig`
is the artifact's own signature, copied rather than recomputed, and the predicate
carries the original base64url payload segment verbatim — which is why the
round-trip is byte-exact and the existing verifier accepts the result unchanged.

**Honesty (verbatim class from the spec):**

The DSSE envelope proves:

> exactly what the compact artifact proves

It does **NOT** prove:

- that anything was re-verified — **no signature is checked** while building or
  reading an envelope. `toDSSE` wraps a known-invalid artifact just as happily;
- anything the compact artifact does not already establish — a standard
  container does not strengthen a claim.

Verification stays with `verify.js` / `verify-attest.js`. A tampered envelope is
caught in one of two places, never silently: a rewritten decoded predicate field
is refused by `fromDSSE` (`PREDICATE_MISMATCH`), and a rewritten payload segment
unpacks but fails signature verification. RECEIPT_FORMAT.md section 9 states the
full invariant table an external verifier can rely on.

## Verifier signatures — unified `(token, opts)` (1129)

All seven verifiers accept **`(token, opts)`** with `opts.ctx` (keyring / publicKey / registry)
and `opts.intended` (cross-check bindings):

```js
verifyReceipt(token, { ctx, envelope })
verifyChain(tokens, { ctx })
verifyExecutionGrant(token, { ctx, intended })
verifyExecutionAttestation(token, { ctx: { registry }, intended })
verifyToolsetAttestation(token, { ctx: { registry, entries }, intended })
verifyMonitoringAttestation(token, { ctx: { registry }, intended })
verifyBundle(bundle, { ctx, perSlot })
```

The former 3-ary signatures remain as **deprecated wrappers**: they warn
**once** (`DeprecationWarning`) and forward into the unified shape:

```js
verifyReceipt(token, ctx, opts)               // deprecated wrapper
verifyChain(tokens, ctx, opts)                // deprecated wrapper
verifyExecutionGrant(token, ctx, opts)        // deprecated wrapper
verifyBundle(bundle, ctx, opts)               // deprecated wrapper
verifyExecutionAttestation(token, opts)       // 2-ary; throws on a 3rd (1128)
verifyToolsetAttestation(token, opts)         // 2-ary; throws on a 3rd (1128)
verifyMonitoringAttestation(token, opts)      // 2-ary; throws on a 3rd (1128)
```

**1128 still throws** on a third argument to the original 2-ary verifiers
(`verifyExecutionAttestation`, `verifyToolsetAttestation`, `verifyMonitoringAttestation`).
A dropped third argument used to skip the cross-check and grade a mismatch valid.

Python mirrors: `verify_receipt` / `verify_execution_grant` / `verify_chain` accept a unified
dict as the second argument; a second+third positional pair warns once. Attest / monitor already
opts-based. The Python toolset verifier remains keyword-based —
`verify_toolset_attestation(token, registry, entries, intended, now_ms)` — and also accepts a
unified opts dict as the second argument. Extra positionals raise `TypeError`. Unifying the
remaining keyword-only spelling is a later versioned wave.

Do not detect the shape with `Function.length`. Parameters with defaults are not counted.

## CLI reference

```
verify.js <receipt> [--key pub.pem | --keys <url|file>] [--kid <kid>] [--fetch <url>] [--envelope <file>]
verify.js --chain receipts.txt [--key pub.pem | --keys <url|file>] [--kid <kid>] [--fetch <url>]

verify.py <receipt> [--key pub.pem | --keys <url|file>] [--kid <kid>] [--fetch <url>] [--envelope <file>]
verify.py --chain receipts.txt [--key pub.pem | --keys <url|file>] [--kid <kid>] [--fetch <url>]

verify-attest.js <token> --keys <file|url> [--grant <token>] [--receipt-digest sha256:…]
verify_attest.py <token> --keys <file|url> [--grant <token>] [--receipt-digest sha256:…]

verify-bundle.js <bundle.json> --slot-keys <file> [--ctx <file>]
```

- `--key <pem>`         verify against a local SPKI PEM public key (offline).
- `--keys <src>`        resolve the key by `kid` from a registry (URL or file); accepts
  active and retired keys. Mutually exclusive with `--key`.
- `--kid <kid>`         expected key id; mismatch yields `unknown_kid`.
- `--fetch <url>`       key-discovery URL (default:
  `https://app.coderifts.com/.well-known/coderifts-keys.json`), used only when
  `--key`/`--keys` are absent. Accepts the registry array (active + retired)
  and the legacy single-key body from `/api/v1/attestation/public-key`.
- `--envelope <file>`   (v4) path to a JSON decision-envelope file. The verifier
  recomputes the RFC 8785 (JCS) canonical body hash (with `receipt` and
  `decision_body_hash` stripped) and requires it to equal the receipt's `bh`.
  Mismatch ⇒ `body_hash_mismatch`. Both `verify.js` and `verify.py` read a
  **file path** (not an inline JSON string).

Example (v4 body-hash binding — use a real envelope file from an authorize /
bundle path; do not invent a receipt token):

```
node verify.js "$RECEIPT" --envelope decision.json
python3 verify.py "$RECEIPT" --envelope decision.json
```

Error reasons (signature/structure failures; see RECEIPT_FORMAT.md section 6):
`malformed_structure`, `bad_json`, `unknown_kid`, `signature_error`,
`signature_mismatch`, `delimiter_in_field`, `body_hash_mismatch`,
`retired_key_after_issue`, `KEY_REVOKED`, `KEY_RETIRED_AFTER_SIGNING`.

Live `status` values include `VERIFIED_CURRENT` and, for v4 when
`expires_at + 30s` is in the past, `VERIFIED_EXPIRED` (signature authentic but
expired — `valid` is false). 30s clock-skew leeway on expiry; 0s for destructive
operations in production when the intended context declares them (this surface
has no destructive field, so the 30s default always applies). Full 12-status
taxonomy: RECEIPT_FORMAT.md section 6.

## Proof bundle (`verify-bundle.js`)

Verifies a `cr.bundle.v1` document: several signed artifacts presented together, each graded in its
own slot, with the whole reported as VERIFIED / INVALID / EMPTY.

```bash
node verify-bundle.js bundle.json --slot-keys slot-keys.json
```

**`--slot-keys`, not `--keys`, and the difference is not cosmetic.** The slots are signed by
different parties, and the slot verifiers do not take key material in the same shape: `verifyReceipt`
and `verifyExecutionGrant` read `ctx.publicKey` / `ctx.expectedKid`, while the attestation verifiers
read `opts.registry`. There is therefore no single registry to hand the bundle. This flag takes the
library's own `opts` object, unchanged:

```json
{
  "perSlot": {
    "receipt": { "ctx": { "publicKey": "-----BEGIN PUBLIC KEY-----…", "expectedKid": "2026-07-k1" }, "opts": {} },
    "execution_grant": { "ctx": { "publicKey": "…", "expectedKid": "…" }, "opts": { "intended": { } } }
  }
}
```

The CLI adds no key handling of its own, so it cannot disagree with the library about what a slot
was checked against.

**Exit codes:** `0` VERIFIED · `1` INVALID or EMPTY · `2` usage or load error. A file that cannot be
read or parsed is a load error, never a verdict about someone's proof.

**Note on EMPTY:** a bundle whose only present slot is INVALID reports `EMPTY`, because the verdict
asks "did anything verify?" first (`verify-bundle.js:239`). The exit code is `1` either way; read
the `slots` array for what actually failed.

**This is not `coderifts verify-proof-bundle`.** That spelling is the future *app*-CLI verb
(roadmap 1107) and lives in the `coderifts` package. This repository ships no `coderifts` command
and has no `package.json`; like every other verifier here, it is invoked as `node <file>.js`.

## Key rotation

There is a single *active* signing kid at any time. When CodeRifts rotates the
key, the previous kid is marked `retired` (never removed) in the append-only
registry at `/.well-known/coderifts-keys.json`. Default key discovery (no
`--key`/`--keys`) fetches that registry, so a receipt signed under a retired
kid resolves as `RETIRED_KEY_VALID_AT_ISSUE` when `ts` predates `retired_at`.
A single pinned `--key`, or `--fetch` of the legacy
`/api/v1/attestation/public-key` body, still sees only the active kid —
receipts signed under a previous kid then fail as `unknown_kid`. `--keys`
remains the explicit registry pin (URL or file).

## Key lifecycle

`retired_at` is planned rotation: a receipt whose `ts` predates it still
verifies; `ts >= retired_at` is `KEY_RETIRED_AFTER_SIGNING`. `revoked_at` is
compromise: every receipt under that key is `KEY_REVOKED`, including those
signed before the timestamp — revocation cannot retroactively prove a receipt
was signed by an honest holder, it can only invalidate. Entries without either
field are unchanged (this verifier's reading; the app registry does not mint
`revoked_at` on key entries yet — follow-up).

## consumeAndCommit contract (EP-2 — not shipped)

`test/consume-and-commit-vectors.json` pins the **contract** a future
`consumeAndCommit(grant, state_nonce, expected_state, mutation)` service
must satisfy: `committed` | `refused` | `indeterminate`, with error codes
`NONCE_EXPIRED`, `NONCE_ALREADY_CONSUMED`, `NONCE_GRANT_BINDING_MISMATCH`,
`NONCE_WRONG_EXECUTOR`, `TARGET_STATE_CONFLICT`, `PAYLOAD_HASH_MISMATCH`,
`EXECUTION_INDETERMINATE`, `ATTESTATION_PENDING`.

These are input/expected fixtures, not signed tokens. There is **no**
`verify-consume.js` / `verify_consume.py`. The public verifier is
stateless and cannot detect a replayed nonce. The production consumer is
the stateful data plane (EP-2) and is not this repository. Do not treat
the presence of the JSON file as a verifier.

## Tests

```
node test/gen-vectors.js         # regenerate receipt vectors with a fresh EPHEMERAL key
node test/gen-grant-vectors.js    # regenerate cr.exec.v1 grant vectors (ephemeral key)
node test/gen-attest-vectors.js   # regenerate cr.exec.attest.v1 EG-A-* vectors (ephemeral key)
bash test/run.sh                 # every vector through JS and Python (receipts + grants)
```

`test/run.sh` fails if the two implementations ever disagree, if any vector does
not match its expected `{valid, reason}`, or if exit codes diverge. It covers v1,
v2, and v3 vectors (including v3 tamper cases: flipped `ir`, flipped `reg`, wrong
field order), the `--keys` registry-resolution path, and one **real production
v3 receipt** captured from `coderifts/demo` PR #4 (the `live` block in
`vectors.json`, verified against the live prod PUBLIC key). The regenerated
ephemeral-key vectors never use the production key; the `live` block is a frozen
captured artifact and is not regenerated. Implementations also support v4
(`expires_at`, `bh`, `--envelope`); see RECEIPT_FORMAT.md for the frozen byte
layout and status taxonomy.

## Contract attestation (`contract-verify/`)

A second, independent reference verifier lives in
[`contract-verify/`](contract-verify/). It is the **verify half of the contract
discovery and attestation protocol**: an agent fetches a small signed bundle
describing a tool's current API contract, checks it, and gets a verdict *before
any tool code runs*.

It is a sibling, not a duplicate. The two verify different objects:

| | This repo (root) | `contract-verify/` |
|---|---|---|
| Object verified | `chain_receipt` — a signed record that a verdict **was** issued | A signed **contract bundle** advertised at a well-known endpoint |
| When it runs | After a decision, to prove provenance | Before a tool call, to gate execution |
| Checks | Ed25519 signature, `kid`, chain `prev` linkage, v4 envelope binding | Signature, contract hash pin, freshness/TTL, rollback, verdict gate |
| Trust input | Published CodeRifts signing key | Caller-supplied trusted signer set |

Both are dependency-free and offline: root needs `cryptography` for Python,
`contract-verify/` needs nothing but `python3`.

```
cd contract-verify
python3 -m unittest          # 24 tests
python3 check_vectors.py     # 9 cross-implementation conformance vectors
python3 demo_loop.py         # full fetch + verify round trip on a local stdlib server
```

Its own README, schema (`bundle.schema.json`, `SCHEMA.md`) and conformance
vectors (`test-vectors.json`) travel with it. `test/run.sh` at the repo root does
not reach into `contract-verify/`; the two suites are run separately.

## License

MIT.
