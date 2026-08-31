# CodeRifts chain-receipt format -- public freeze spec (crchain.v1 prefix; envelopes v1/v2/v3/v4)

This document is the public contract for the CodeRifts Ed25519 chain-receipt
(the `chain_receipt` field on verdict responses). It is FROZEN: for a given
envelope version (`body.v`) the field order and separators of the signed
byte-string never change. New fields are only ever APPENDED under a new envelope
version (`body.v` increments: v1 -> v2 added `reg`, v2 -> v3 added `ir`), which
keeps every version's signed bytes distinct so an older verifier can never accept
a newer body. The signed-format prefix tag stays the literal `crchain.v1`; a
change to the prefix tag (`crchain.vN`) is reserved for a breaking reformat, not
an appended field.

An external party can verify any receipt with only the public key -- no access to
CodeRifts internals or state is required. The chain lives entirely in the
request/response; nothing is stored server-side.

## 1. Token

```
token = base64url( JSON(body) ) + "." + base64url( signature )
```

- Exactly two segments joined by a single `.`; both segments are non-empty
  base64url (no padding, alphabet `A-Za-z0-9-_`).
- `signature` is the raw Ed25519 signature (see section 4).

## 2. Body

`body` is a JSON object. Field order in the JSON is not significant for
verification (the signed bytes are reconstructed from the parsed fields, not from
the JSON text), but issuers emit these keys in this order:

| field    | type              | value                                                                 |
|----------|-------------------|-----------------------------------------------------------------------|
| `v`      | number            | `1`, `2`, `3`, or `4` (envelope version)                              |
| `kid`    | string            | key id; must match the active published key                           |
| `fp`     | string            | verdict fingerprint, format `sha256:<64 lowercase hex>`               |
| `prev`   | string            | `sha256:<64 lowercase hex>` of the previous token, or the literal `null` at genesis |
| `caller` | string            | caller id recorded at issuance (e.g. `api`, `anon`, `v:<hash>`, `webhook`, `bundle`, `mcp`) |
| `ts`     | string            | issuance time, ISO 8601 (e.g. `2026-07-15T00:00:00.000Z`)             |
| `reg`    | string (v2, v3, v4) | evidence-trust-registry hash, bare `<64 lowercase hex>` (NO `sha256:` prefix) |
| `ir`     | string (v3, v4)   | Change-IR (`CRIR.v1`) hash, format `sha256:<64 lowercase hex>`        |
| `expires_at` | string (v4 only) | authorization TTL bound, ISO 8601. Producer sets `evaluated_at + per-operation TTL` then **signs** it (v4). Re-checkable: a verifier compares it to now (time-window only — see §2.1). |
| `bh`     | string (v4 only)  | `decision_body_hash`: `sha256:<64 hex>` of the RFC 8785-canonical decision envelope MINUS `receipt` MINUS `decision_body_hash`. Re-checkable via `--envelope`. |

Notes:
- `reg` is present when `v === 2` or `v === 3`. It is signed-but-INFORMATIONAL: a
  verifier never compares it to any live registry, so a registry change never
  invalidates a previously issued receipt. In `v:3` bodies the issuer ALWAYS emits
  `reg`; when the request carried no registry it is the empty string `""` (the
  signed bytes then contain an empty segment `...|<ts>||<ir>`).
- `ir` is present only when `v === 3`. Like `reg` it is signed-but-INFORMATIONAL:
  it binds the Change-IR that the verdict was computed over, but the verifier does
  not recompute it.
- `fp` is verified here as a signed binding: this verifier confirms the signed bytes
  containing `fp` were signed by the key. It does not recompute `fp` itself.
  **But `fp` is not opaque, and an earlier version of this document said it was.**
  Which recipe produced it depends on the path — see §2.0.

### 2.0 Recomputing `fp` (what the earlier "opaque binding" note got wrong)

Two producers mint the `fp` that appears in a chain receipt. Neither is the
"verdict-core canonical encoder" this document previously named: that module is not
on the path that produces a receipt's `fp`.

**Change-set / authorize path — `crbundle.v1`. RECOMPUTABLE TODAY.**

Every input is something the caller already holds; there is no internal id, no
server-side timestamp and no score anywhere in the preimage. Fields are joined with
US (`\x1f`), artifacts sorted by `(type, id)` so submission order is not significant:

```
crbundle.v1
<artifactCount>
for each sorted artifact:  <type> \x1f <id> \x1f sha256hex(before) \x1f sha256hex(after)
<operation> \x1f <environment> \x1f <repository> \x1f <branch> \x1f <pull_request> \x1f <policy_profile>
```

**Separator: `\x1f` (US, U+001F).** `sha256hex` is hex over the raw UTF-8 bytes; a
non-string artifact side is `JSON.stringify`-ed first; an absent side is the empty
string; an absent context field is the empty string. Output is `sha256:<hex>`. The
result is time-free: the same inputs always give the same digest.

*Re-verified live after guard 11.0.0 shipped* — the vector below still reproduces
from a receipt minted against the deployed server.

`computeBundleFingerprint(artifacts, context)` in `@coderifts/agent-guard`
implements exactly this **from 11.0.0**, which is published and verified against the
vector below. **Versions up to and including 10.0.0 did not** — that build omitted
the count and the whole context block and returned a different digest. If you pinned
a value from it, recompute rather than migrate.

*Cross-check vector* — one artifact, `context.operation = "merge"`:

```
before: {"openapi":"3.0.0","info":{"title":"t","version":"1.0.0"},"paths":{"/u":{"get":{"responses":{"200":{"description":"ok"}}}}}}
after:  {"openapi":"3.0.0","info":{"title":"t","version":"1.0.0"},"paths":{}}
artifact: { id: "openapi.yaml", type: "openapi" }
context:  { operation: "merge" }

fp = sha256:049650f2d0496f39ad0ec09e57fa1841e9636255f031e99751435b1bc70443df
```

That value was taken from a live authorize response, where it appears identically as
`chain_receipt.fp`, `decision_result.fingerprint`, `verdict_fingerprint` and
`bundle_fingerprint`.

**Single-spec path (`/api/v1/agent/preflight`, `/api/v1/mcp-diff`) — RECOMPUTABLE.**

```
fp = sha256( normalizeSpec(before) ‖ normalizeSpec(after) ‖ normalizePolicy(policy) ‖ scorer_version )
```

**Separator: `\x00` (NUL, U+0000). This is NOT the `\x1f` used above** — the two
paths genuinely differ, and joining this preimage with `\x1f` produces a wrong
digest.

- `normalizeSpec(s)`: trim; if the text starts with `{` or `[` parse it as JSON,
  otherwise as YAML; on a successful object parse emit `JSON.stringify` of the value
  with **object keys sorted at every depth** (arrays keep order); on any parse
  failure emit the trimmed raw text. `null`/empty → `""`.
- `normalizePolicy(p)`: a non-object → the literal `{}`; otherwise the same
  sorted-key `JSON.stringify`.
- `scorer_version`: **returned in the response**, e.g. `59ed151:active`. It is the
  server's scoring-configuration hash plus its mode. You do not compute it — read it
  from the same response that carried the fingerprint.

*Cross-check vector* — taken from a live `POST /api/v1/agent/preflight`:

```
old_spec: {"openapi":"3.0.0","info":{"title":"t","version":"1.0.0"},"paths":{"/u":{"get":{"responses":{"200":{"description":"ok"}}}}}}
new_spec: {"openapi":"3.0.0","info":{"title":"t","version":"1.0.0"},"paths":{}}
policy:   {}                       (none supplied)
response scorer_version: 59ed151:active

fp = sha256:b4faaacad943012438d784c8da34594538b9e5883adc341aa10b7bbfca9d921c
```

**Corrections this section has had to make.** Both are recorded rather than quietly
edited, because a document that silently repairs itself teaches you its history
cannot be trusted:

1. An earlier revision called `fp` an **opaque binding** requiring the "verdict-core
   canonical encoder". That module is not on the path that produces a receipt's `fp`
   at all, and both real recipes are reproducible from what a caller already holds.
2. A revision published **on the same day as this one** gave `\x1f` as the separator
   for **both** recipes. That is correct for `crbundle.v1` and **wrong for the
   single-spec path**, which uses `\x00`. Anyone who followed that revision computed
   a wrong digest for the single-spec path — the precise failure mode this section
   was rewritten to eliminate.

   The cause is worth keeping, because it is the reason a wrong value survived review.
   **At the time**, three separator constants were all *named* `NUL` and only one of
   them was: `change-set.js` and `execution-grant.js` each held `'\x1f'` under that
   name, and `core/verdict-fingerprint.js` held a **raw U+0000 control byte** rather
   than the `'\x00'` escape — so `grep 'const NUL'` failed silently on the one file
   that really did hold NUL, and a reader saw an apparently blank value.
   **A name is not a measurement.**

   **Fixed at the source since.** The 0x1F constants are now named `US` and the NUL
   one is written as an escape, in the app (`coderifts-app` 90c39cc) and in every
   public mirror that carries the same preimage — `@coderifts/agent-guard`
   (`execution-time-fingerprint.ts`, `enforcement-gate.ts`) and this repository's own
   `verify-grant.js`. **No mirror is still lagging.** Every rename was proved
   digest-neutral by recomputing a real vector before and after; not one byte of any
   preimage moved.

**What recomputing an `fp` proves — and what it does not.**

A matching `fp` proves the receipt corresponds to that content and that context, and
that neither has changed since it was issued. It does **not** prove that any
particular agent call went through the gate: a receipt is evidence about the change
it was minted for, never about traffic it never saw.

### 2.1 Per-operation `expires_at` TTL (authorization window)

Producer computes `expires_at = evaluated_at + TTL(operation)` from a **closed** map,
then signs the value on v4 receipts (`signingInputV4` appends `|expires_at|bh`). The
operation is the existing envelope field (`context.operation` on authorize →
`decision_result.operation`); issuers do not invent operations.

| operation | TTL | rationale |
|-----------|-----|-----------|
| `tool_call` | **15 minutes** | Fast agent mutate; short window is correct. |
| `merge` | **4 hours** | Human/CI PR review sits longer than 15m; flat 15m caused gate death by friction. |
| `deploy` | **4 hours** | Deploy pipelines outlast a tool call; same class as merge. |
| `publish` | **4 hours** | Publish pipelines outlast a tool call; same class as merge. |
| unknown / null / missing | **15 minutes** | Shortest, fail-safe — never the longest window on an unrecognized operation. |

**TTL is not freshness.** The `expires_at` TTL is the *authorization time-window*
(how long the permission is valid). Content-identity (is the spec you authorized the
same one you are shipping) is a **separate axis**: the `fp` fingerprint. A longer TTL
does NOT loosen the fingerprint check — a `merge` receipt valid for hours still fails
closed if the content drifted (`fingerprint_mismatch`).

## 3. Signed bytes (FROZEN)

The bytes covered by the signature are a UTF-8 pipe-delimited string:

```
v1:  crchain.v1|<kid>|<fp>|<prev>|<caller>|<ts>
v2:  crchain.v1|<kid>|<fp>|<prev>|<caller>|<ts>|<reg>
v3:  crchain.v1|<kid>|<fp>|<prev>|<caller>|<ts>|<reg>|<ir>
v4:  crchain.v1|<kid>|<fp>|<prev>|<caller>|<ts>|<reg>|<ir>|<expires_at>|<bh>
```

- The prefix tag is the literal `crchain.v1` for `v:1`..`v:4` bodies. It is the
  signed-format tag, not the envelope version number, and does NOT change for v4 —
  decision-envelope consumers fail closed on an unknown `format_version`, so the
  prefix must stay `crchain.v1`.
- The separator is a single pipe `|`.
- Field order is exactly: prefix, `kid`, `fp`, `prev`, `caller`, `ts`, then (v2+)
  `reg`, then (v3+) `ir`, then (v4) `expires_at`, `bh`.
- The trailing segments keep the versions' signed bytes distinct (nesting
  v1 ⊂ v2 ⊂ v3 ⊂ v4): a lower-version verifier can never accept a higher-version
  body, and vice versa. A signed field MUST NOT contain `|`; verifiers reject any
  that does (`delimiter_in_field`), closing the cross-version re-split attack.

Verifiers MUST reconstruct this string from the receipt's own body fields,
dispatching on `body.v`:
- `4` => append `|<reg>|<ir>|<expires_at>|<bh>`
- `3` => append `|<reg>|<ir>`
- `2` => append `|<reg>`
- otherwise => the v1 string.

A v4 receipt is issued only on envelope-bearing paths (bundle + MCP single-spec);
HTTP-only verdict paths keep issuing v1/v2/v3. `bh` binds the entire decision
envelope: given the envelope, a verifier recomputes `sha256:` + sha256 of its
RFC 8785 (JCS) canonical form with `receipt` and `decision_body_hash` removed, and
requires it to equal `bh` (`--envelope`; mismatch => `body_hash_mismatch`).

## 4. Signature

- Algorithm: raw Ed25519 (RFC 8032, PureEdDSA, NO pre-hash).
- Length: 64 bytes.
- Verified over the exact UTF-8 bytes from section 3.
- Interoperable primitives: Node `crypto.verify(null, msg, publicKey, sig)`;
  Python `cryptography` `Ed25519PublicKey.verify(sig, msg)`; libsodium /
  PyNaCl `VerifyKey.verify`.

## 5. Chain rule

For a sequence of receipts (oldest first):

```
prev(receipt[i])  ==  "sha256:" + sha256hex( entire token string of receipt[i-1] )
```

- `sha256hex(...)` is the lowercase hex SHA-256 of the previous token's full
  string (`base64url(body).base64url(sig)`), encoded as UTF-8.
- Genesis (first receipt in a chain): `prev` is the literal string `null`.
- A chain segment whose first receipt has a `sha256:...` `prev` is a
  continuation of a chain the verifier does not hold; this verifier reports it as
  `continuation` and cannot check that first link's predecessor.

## 6. Error taxonomy (FROZEN order) + status taxonomy

`reason` (FROZEN order) — the first applicable failure of the signature/structure check:

1. `malformed_structure` -- not a string, empty, or not exactly two non-empty
   `.`-joined segments.
2. `bad_json` -- the body segment does not base64url/UTF-8/JSON-decode to an object.
3. `unknown_kid` -- `body.kid` does not match a known key.
4. `signature_error` -- the signature could not be evaluated (e.g. malformed sig bytes).
5. `signature_mismatch` -- the signature did not verify against the reconstructed bytes.
6. `delimiter_in_field` -- a signed field contains `|` (cross-version re-split guard).
7. `body_hash_mismatch` -- (`--envelope`, v4) the envelope's recomputed body hash != `bh`.
8. `retired_key_after_issue` -- signed by a key already retired at the receipt's `ts`.

`status` (15-status taxonomy) — the verdict a caller branches on. `valid === (status is
VERIFIED_CURRENT or RETIRED_KEY_VALID_AT_ISSUE)`. **11 live, 4 dormant** (fire only when the
envelope carries the field AND a `--audience`/`--environment`/… check input is supplied):

| status | live? | fires when |
|--------|-------|------------|
| `VERIFIED_CURRENT` | live | signature authentic; not expired; all supplied checks pass |
| `VERIFIED_EXPIRED` | live | v4 signature authentic but `expires_at + 30s` (`CLOCK_SKEW_LEEWAY_MS`) < now. 0s leeway for destructive operations in production when the intended context declares them; this verifier has `environment` but no destructive / operation_class field, so the 30s default always applies. |
| `UNKNOWN_KEY` | live | `body.kid` not in the key set |
| `UNKNOWN_KEY_STATUS` | live | the registry entry carries a `status` this verifier does not understand — fail closed, never valid. See §7.1. |
| `REVOKED_KEY` | live | signed by a **revoked** key, `ts` at or after `compromised_at`. Signature authentic; the KEY is repudiated. See §7.1. |
| `REVOKED_KEY_UNDECIDABLE` | live | signed by a **revoked** key, `ts` before `compromised_at`, or the entry carries no `compromised_at`. See §7.1. |
| `RETIRED_KEY_VALID_AT_ISSUE` | live | signed by a retired key, `ts` < that key's `retired_at` |
| `INVALID_SIGNATURE` | live | signature/delimiter/body-hash failure, or retired-at-issue |
| `MALFORMED` | live | structure / JSON failure |
| `UNSUPPORTED_VERSION` | live | `body.v` > the verifier's max supported version |
| `REGISTRY_UNREACHABLE` | live | the key registry / attestation endpoint could not be reached |
| `VERIFIED_WRONG_AUDIENCE` | dormant | `--audience` supplied and envelope `audience` differs |
| `VERIFIED_WRONG_ENVIRONMENT` | dormant | `--environment` supplied and envelope `environment` differs |
| `VERIFIED_SUPERSEDED` | dormant | a later decision supersedes this one (no check input defined yet) |
| `VERIFIED_SCOPE_MISMATCH` | dormant | authorization scope differs (no check input defined yet) |

An authentic, fresh receipt returns `{ valid: true, status: "VERIFIED_CURRENT", payload }`.

## 7.1 Revocation (NORMATIVE)

A key registry entry has a `status`. Two values are long-standing — `active` and `retired` — and a
third is defined here: **`revoked`**.

**`retired` is not `revoked`, and conflating them is the bug this section exists to correct.** A
retired key stopped signing at a known time and nothing bad happened; a receipt whose `ts` predates
`retired_at` is still good (`RETIRED_KEY_VALID_AT_ISSUE`). A **revoked** key is one we believe an
attacker held. The distinction matters because **the attacker chooses `ts`**. Under the retirement
rule, a thief holding a stolen key backdates the timestamp to just before `retired_at` and the
verifier returns `RETIRED_KEY_VALID_AT_ISSUE` — valid. **No timestamp may ever rehabilitate a
revoked key's signature.**

### The rule

A registry entry MAY carry `compromised_at` (ISO 8601). For `status: "revoked"`:

| condition | status | `valid` |
|---|---|---|
| `ts` >= `compromised_at` | `REVOKED_KEY` | **false** |
| `ts` < `compromised_at` | `REVOKED_KEY_UNDECIDABLE` | **false** |
| entry carries no `compromised_at` | `REVOKED_KEY_UNDECIDABLE` | **false** |

**`UNDECIDABLE` is not a softer `valid`.** It reports that we cannot tell a legitimate
pre-compromise receipt from a backdated forgery — which is the honest answer, and it is still
`valid: false`. A verifier MUST NOT treat `REVOKED_KEY_UNDECIDABLE` as acceptable evidence.

### Why `compromised_at` is the earliest unruled-out time, not the discovery time

`compromised_at` is **the earliest time we cannot rule out attacker control** — not the moment we
found out. Those are different, and the gap is not academic. In the OpenAI incident of this week,
agents read a service's token-signing key and forged administrator credentials; **six days later**
they recovered key material left in a cache and minted fresh ones. Discovery time would have been
the wrong boundary by six days, and every forgery inside that window would have verified.

If the earliest unruled-out time is genuinely unknown, the field MUST be omitted rather than
guessed. Omission means the whole key history is suspect, which is why it maps to
`REVOKED_KEY_UNDECIDABLE` rather than to a permissive default.

### What a revoked verdict does and does not say

It says: this signature is cryptographically authentic, and the key that produced it is repudiated,
so the signature is not evidence of anything. It does **not** say the receipt was forged — a
legitimate receipt minted before the compromise is indistinguishable from a backdated one, and
saying which would be a claim we cannot support.

### Unknown statuses fail closed

A verifier that meets a `status` it does not understand MUST return `UNKNOWN_KEY_STATUS` with
`valid: false`. It MUST NOT fall through to the healthy path. Measured 2026-08-26: two verifiers
did fall through, so a key marked `revoked` verified as `VERIFIED_CURRENT` — an operator would have
believed they had acted while nothing changed. This rule is what makes it safe to publish a new
status before every implementation has learned it.

## 7. Key discovery

Single active key (current signer):

```
GET https://app.coderifts.com/api/v1/attestation/public-key
-> { "kid": "...", "alg": "Ed25519", "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n" }
```

- Match the receipt's `body.kid` against the returned `kid`.
- When the server has no signing key configured, this endpoint returns `503
  { "error": "attestation_not_configured" }` and verdict responses omit the chain
  fields entirely.

Key registry (all keys, active and retired):

```
GET https://app.coderifts.com/.well-known/coderifts-keys.json
-> { "keys": [ { "kid": "...", "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n",
                 "status": "active" | "retired", "valid_from": "<ISO 8601>",
                 "retired_at": "<ISO 8601>" | null } ] }
```

- `retired_at` is `null` for an active key. For a retired key it is the instant the key
  stopped signing: a receipt whose `ts` predates `retired_at` is `RETIRED_KEY_VALID_AT_ISSUE`
  (still trustworthy — it was signed while the key was live); a receipt at/after `retired_at`
  is rejected (`INVALID_SIGNATURE`). Verifiers pass the registry with `--keys`.

- The registry is append-only: a rotated key is marked `retired` and a new `active`
  key is added; entries are never removed. This lets a verifier resolve the right
  key for a receipt's `body.kid` even after rotation, so previously issued receipts
  stay verifiable.
- Both verifiers accept `--keys <url|file>` to resolve by kid from this registry.
  A retired key still verifies (that is the point); an unlisted kid yields
  `unknown_kid`.
- Default discovery (no `--key`/`--keys`) fetches this registry, so a retired
  kid resolves as `RETIRED_KEY_VALID_AT_ISSUE` when `ts` predates `retired_at`.
  A single pinned `--key`, or `--fetch` of the legacy single-key body, still
  sees only the active kid — receipts signed under a previous kid then fail as
  `unknown_kid`. Pin the `public_key_pem` active at issuance, or pass `--keys`.

## 8. cr.exec.attest.v1 (execution attestation)

The executor's signed commit statement. Public verifiers: `verify-attest.js` /
`verify_attest.py`. Spec: `coderifts-app/docs/cr-exec-attest-v1.md`.

Token:

```
cr.exec.attest.v1|{executor_kid}|{payload_b64}|{sig_b64}
```

`--keys` is **required** (customer-held executor registry). There is no default
fetch. Retired-key rule is receipt-class historical
(`ATTEST_RETIRED_KEY_VALID_AT_ISSUE`), not the grant `UNKNOWN_KEY` rule.

Honesty: the attestation proves a holder of the executor key asserts this
commit. It does **not** prove unmodified executor code, human review, live
`GRANT_CURRENT`, or that `result_digest` is a CodeRifts fingerprint.

## 9. DSSE / in-toto export (OPTIONAL)

Source of truth: `to-dsse.js` (`toDSSE` / `fromDSSE`). This section documents what
that module **does**, measured from it — not a format we intend to build.

The compact forms above stay primary. This is an **export**, so a system that
already speaks in-toto (SLSA tooling, policy engines, admission controllers) can
accept a CodeRifts artifact without learning the compact format.

### 9.1 Stable identifiers

External systems key on these. They do not change without a version bump.

| field | value |
| --- | --- |
| `payloadType` | `application/vnd.in-toto+json` |
| Statement `_type` | `https://in-toto.io/Statement/v1` |
| `predicateType` | `https://coderifts.com/attestations/agent-action-authorization/v1` |

The same `predicateType` is advertised as `in_toto_predicate_type` in the agent
discovery document, so a consumer can discover it before fetching anything.

### 9.2 Envelope

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<base64 of the in-toto Statement below>",
  "signatures": [{ "keyid": "<the artifact's kid>", "sig": "<the artifact's own signature>" }]
}
```

`signatures` carries **exactly one** entry, and its `sig` is the compact token's
own signature segment — copied, never recomputed. `fromDSSE` refuses an envelope
with zero, two, or a signature-less entry rather than picking one.

### 9.3 Statement

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "<compact form>", "digest": { "sha256": "<sha256 of the compact token>" } }],
  "predicateType": "https://coderifts.com/attestations/agent-action-authorization/v1",
  "predicate": {
    "compact": {
      "form": "crchain.v1" | "cr.exec.attest.v1",
      "tag": "<envelope tag, attestation form only>",
      "kid": "<envelope kid, attestation form only>",
      "encoded_payload": "<the ORIGINAL base64url payload segment, verbatim>"
    },
    "fields": { "<the decoded payload, verbatim>": "..." },
    "proves": "...",
    "does_not_prove": ["...", "..."],
    "verify_with": "..."
  }
}
```

The **subject is the compact token itself** — that is the artifact the envelope is
about, and its sha256 is what a consumer pins.

`predicate.fields` carries the payload's own fields **verbatim**, whatever the
artifact signed. It is not a curated list: a curated list is where a field gets
silently dropped and the export ends up describing a document the envelope does
not contain.

### 9.4 Why `encoded_payload` is preserved, not re-encoded

`predicate.compact.encoded_payload` is the **original** base64url segment, byte
for byte. It is not a re-serialisation of `predicate.fields`.

A signature is over bytes, not over meaning. Re-encoding JSON is not byte-stable
— key order and whitespace are free — so a rebuilt payload would fail to verify
for a reason that has nothing to do with authenticity. Preserving the segment is
what makes the round-trip below exact.

### 9.5 Round-trip

```
fromDSSE(toDSSE(token)) === token                        (byte-exact)
verify(fromDSSE(toDSSE(token))) === verify(token)        (identical verdict)
```

The second line holds for artifacts that FAIL verification too. A wrapper that
quietly repaired a bad artifact would be worse than one that broke a good one.

`fromDSSE` reassembles:

* receipt form — `` `${encoded_payload}.${sig}` ``
* attestation form — `` `${tag}|${kid}|${encoded_payload}|${sig}` ``

### 9.6 What this proves, and what it does not

> **Proves:** exactly what the compact CodeRifts artifact proves — this envelope
> is packaging, and the signature is the artifact's own, over its own bytes.

> **Does not prove:**
> * that anything was re-verified: **no signature is checked** while building or
>   reading this envelope;
> * anything the compact artifact does not already establish — a standard
>   container does not strengthen a claim.

`toDSSE` deliberately does **not** verify. A known-invalid artifact wraps
successfully, because a packaging function that also validated would invite a
caller to read "it wrapped" as "it is good". Verification stays with
`verify.js` / `verify-attest.js`.

### 9.7 Forgery detection — the invariants an external verifier can rely on

The predicate carries the payload twice: preserved bytes and decoded fields.
Both directions of tampering are detected, by **different** mechanisms.

| tampering | detected by | result |
| --- | --- | --- |
| a decoded `predicate.fields` value is rewritten | `fromDSSE` | throws `DsseError` with `code: 'PREDICATE_MISMATCH'` |
| `predicate.compact.encoded_payload` is rewritten | the signature | `fromDSSE` returns the bytes; **`verify` fails** |
| the signature is swapped for another artifact's | the signature | **`verify` fails** |
| unknown `payloadType` / `predicateType` / compact `form` | `fromDSSE` | throws `DsseError` with `code: 'UNSUPPORTED'` |
| missing / duplicated signature, absent `encoded_payload` | `fromDSSE` | throws `DsseError` with `code: 'MALFORMED'` |

The `PREDICATE_MISMATCH` check exists because an in-toto consumer reads the
predicate, not our base64. Without it the readable half could describe something
the verifiable half does not contain, and a reader with no CodeRifts verifier
would believe the readable half. The comparison is on **meaning** (stable key
order), so non-canonical spacing in the preserved segment is not itself a
mismatch.

**An implementer's minimum:** treat `fromDSSE` as unpacking only. Nothing in this
section establishes authenticity — run the CodeRifts verifier on the reassembled
compact token, and take its verdict as the answer.

### 9.8 Scope

Phase 1 of roadmap 1224 is the format module and this specification. Publishing
the predicate as a standalone open spec, multi-language verifiers for it, and the
four target verifiers (GitHub merge, Kubernetes admission, API gateway, tool
registry) are later phases and are **not** shipped.
