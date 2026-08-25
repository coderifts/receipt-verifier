# Contract Attestation Bundle

The canonical, implementation-agnostic shape of the signed bundle a tool
publishes at its well-known endpoint. Any issuer (guard, CI, signer) can produce
a conformant bundle, and any agent can verify one, without sharing code.

Machine-readable schema: [`bundle.schema.json`](bundle.schema.json) (JSON Schema
2020-12). The pure-Python checker in `schema_validate.py` enforces this same
schema with no dependencies.

## Fields

| Field          | Type    | Notes                                                                 |
| -------------- | ------- | --------------------------------------------------------------------- |
| `ref`          | string  | Git ref the contract lives on, e.g. `refs/heads/main`.                |
| `commit_sha`   | string  | Commit the contract came from. SHA-1 (40) or SHA-256 (64) hex.        |
| `content_hash` | string  | `sha256:<hex>` of the canonical contract bytes. The verify side pins this. |
| `issued_at`    | integer | Unix seconds the bundle was issued.                                   |
| `ttl_seconds`  | integer | Freshness window. Valid while `now <= issued_at + ttl_seconds`.       |
| `version`      | integer | Monotonic. Agents reject any version below the last accepted one.     |
| `verdict`      | string  | One of `PASS`, `REQUIRE_APPROVAL`, `BLOCK`.                            |
| `key_id`       | string  | Identity that signed the bundle, e.g. `ed25519:guard-ci`.             |
| `signature`    | string  | Hex signature over all fields except `signature`.                     |

## What is signed

The signature covers the canonical serialization of every field except
`signature`: the fields are taken in a fixed key order and serialized as compact
JSON with sorted keys. The issuer signs those bytes; the agent recomputes them
and checks the signature. Changing any signed field invalidates the signature.

## Verdict vocabulary

The guard that produces the verdict is a black box. Only the vocabulary is
fixed, so an agent can act on any conformant bundle:

- `PASS` the change is safe, the agent may call the tool.
- `REQUIRE_APPROVAL` valid but held, escalate before calling.
- `BLOCK` do not call the tool.

## Verifying a bundle

Structural conformance:

```
from schema_validate import validate_bundle_schema
errors = validate_bundle_schema(bundle)   # [] means it conforms
```

Full trust check (signature, hash pin, freshness, gate) is `verify_bundle` in
`coderifts_verify.py`. Conformance is necessary but not sufficient: a bundle can
be well-formed and still fail signature, hash pin, freshness, or carry a `BLOCK`.

## Scope

This schema is the wire contract for the discovery and attestation protocol. It
says nothing about how a guard decides a verdict, only how a decided verdict is
packaged, signed, and carried. Git provenance and hash-pinned attestations,
per repo, with no central authority.
