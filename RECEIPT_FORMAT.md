# CodeRifts chain-receipt format -- public freeze spec (crchain.v1 prefix; envelopes v1/v2/v3)

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
| `v`      | number            | `1`, `2`, or `3` (envelope version)                                    |
| `kid`    | string            | key id; must match the active published key                           |
| `fp`     | string            | verdict fingerprint, format `sha256:<64 lowercase hex>`               |
| `prev`   | string            | `sha256:<64 lowercase hex>` of the previous token, or the literal `null` at genesis |
| `caller` | string            | caller id recorded at issuance (e.g. `api`, `anon`, `v:<hash>`, `webhook`) |
| `ts`     | string            | issuance time, ISO 8601 (e.g. `2026-07-15T00:00:00.000Z`)             |
| `reg`    | string (v2, v3)   | evidence-trust-registry hash, bare `<64 lowercase hex>` (NO `sha256:` prefix) |
| `ir`     | string (v3 only)  | Change-IR (`CRIR.v1`) hash, format `sha256:<64 lowercase hex>`        |

Notes:
- `reg` is present when `v === 2` or `v === 3`. It is signed-but-INFORMATIONAL: a
  verifier never compares it to any live registry, so a registry change never
  invalidates a previously issued receipt. In `v:3` bodies the issuer ALWAYS emits
  `reg`; when the request carried no registry it is the empty string `""` (the
  signed bytes then contain an empty segment `...|<ts>||<ir>`).
- `ir` is present only when `v === 3`. Like `reg` it is signed-but-INFORMATIONAL:
  it binds the Change-IR that the verdict was computed over, but the verifier does
  not recompute it.
- `fp` is verified as an opaque binding. This verifier confirms that the signed
  bytes containing `fp` were signed by the key; it does NOT recompute `fp` from a
  verdict payload. Recomputing `fp` requires the verdict-core canonical encoder
  and is out of scope for a receipt verifier.

## 3. Signed bytes (FROZEN)

The bytes covered by the signature are a UTF-8 pipe-delimited string:

```
v1:  crchain.v1|<kid>|<fp>|<prev>|<caller>|<ts>
v2:  crchain.v1|<kid>|<fp>|<prev>|<caller>|<ts>|<reg>
v3:  crchain.v1|<kid>|<fp>|<prev>|<caller>|<ts>|<reg>|<ir>
```

- The prefix tag is the literal `crchain.v1` for `v:1`, `v:2`, and `v:3` bodies. It
  is the signed-format tag, not the envelope version number.
- The separator is a single pipe `|`.
- Field order is exactly: prefix, `kid`, `fp`, `prev`, `caller`, `ts`, then (v2/v3)
  `reg`, then (v3 only) `ir`.
- The trailing segments are what keep the versions' signed bytes distinct: a v1
  verifier can never accidentally accept a v2/v3 body, and a v2 verifier can never
  accept a v3 body, and vice versa.

Verifiers MUST reconstruct this string from the receipt's own body fields,
dispatching on `body.v`:
- `3` => append `|<reg>|<ir>`
- `2` => append `|<reg>`
- otherwise => the v1 string.

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

## 6. Error taxonomy (FROZEN order)

Verification proceeds in this order and returns the first applicable reason:

1. `malformed_structure` -- not a string, empty, or not exactly two non-empty
   `.`-joined segments.
2. `bad_json` -- the body segment does not base64url/UTF-8/JSON-decode to an
   object.
3. `unknown_kid` -- `body.kid` does not match the expected (published) kid.
4. `signature_error` -- the signature could not be evaluated (e.g. malformed
   signature bytes).
5. `signature_mismatch` -- the signature did not verify against the reconstructed
   bytes.

A valid receipt returns `{ valid: true, payload }`.

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
                 "status": "active" | "retired", "valid_from": "<ISO 8601>" } ] }
```

- The registry is append-only: a rotated key is marked `retired` and a new `active`
  key is added; entries are never removed. This lets a verifier resolve the right
  key for a receipt's `body.kid` even after rotation, so previously issued receipts
  stay verifiable.
- Both verifiers accept `--keys <url|file>` to resolve by kid from this registry.
  A retired key still verifies (that is the point); an unlisted kid yields
  `unknown_kid`.
- Rotation caveat when you do NOT use the registry: with a single pinned `--key` /
  the discovery endpoint, receipts signed under a previous kid fail as
  `unknown_kid`. Pin the `public_key_pem` active at issuance, use `--keys`, or
  verify promptly.
