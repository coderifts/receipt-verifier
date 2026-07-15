# CodeRifts chain-receipt format (v1) -- public freeze spec

This document is the public contract for the CodeRifts Ed25519 chain-receipt
(the `chain_receipt` field on verdict responses). It is FROZEN: the field order
and the separators of the signed byte-string are fixed. Any change to them is a
new prefix version (a new `crchain.vN` tag), never an in-place edit of this one.

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
| `v`      | number            | `1` or `2` (envelope version)                                          |
| `kid`    | string            | key id; must match the active published key                           |
| `fp`     | string            | verdict fingerprint, format `sha256:<64 lowercase hex>`               |
| `prev`   | string            | `sha256:<64 lowercase hex>` of the previous token, or the literal `null` at genesis |
| `caller` | string            | caller id recorded at issuance (e.g. `api`, `anon`, `v:<hash>`)       |
| `ts`     | string            | issuance time, ISO 8601 (e.g. `2026-07-15T00:00:00.000Z`)             |
| `reg`    | string (v2 only)  | evidence-trust-registry hash, bare `<64 lowercase hex>` (NO `sha256:` prefix) |

Notes:
- `reg` is present only when `v === 2`. It is signed-but-INFORMATIONAL: a
  verifier never compares it to any live registry, so a registry change never
  invalidates a previously issued receipt.
- `fp` is verified as an opaque binding. This verifier confirms that the signed
  bytes containing `fp` were signed by the key; it does NOT recompute `fp` from a
  verdict payload. Recomputing `fp` requires the verdict-core canonical encoder
  and is out of scope for a receipt verifier.

## 3. Signed bytes (FROZEN)

The bytes covered by the signature are a UTF-8 pipe-delimited string:

```
v1:  crchain.v1|<kid>|<fp>|<prev>|<caller>|<ts>
v2:  crchain.v1|<kid>|<fp>|<prev>|<caller>|<ts>|<reg>
```

- The prefix tag is the literal `crchain.v1` for BOTH `v:1` and `v:2` bodies. It
  is the signed-format tag, not the envelope version number.
- The separator is a single pipe `|`.
- Field order is exactly: prefix, `kid`, `fp`, `prev`, `caller`, `ts`, and (v2
  only) `reg`.
- The trailing `|<reg>` is what makes v1 and v2 signed bytes distinct, so a v1
  verifier can never accidentally accept a v2 body and vice versa.

Verifiers MUST reconstruct this string from the receipt's own body fields,
dispatching on `body.v` (2 => append `|<reg>`; otherwise the v1 string).

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

```
GET https://app.coderifts.com/api/v1/attestation/public-key
-> { "kid": "...", "alg": "Ed25519", "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n" }
```

- Match the receipt's `body.kid` against the returned `kid`.
- There is a SINGLE active kid. Key rotation replaces it; receipts signed under a
  previous kid then fail as `unknown_kid`. This is a documented limitation: there
  is no historical/multi-key registry. Pin the `public_key_pem` you trust, or
  verify receipts promptly after issuance.
- When the server has no signing key configured, this endpoint returns `503
  { "error": "attestation_not_configured" }` and verdict responses omit the chain
  fields entirely.
