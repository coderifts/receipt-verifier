# example-contract-verify

A tiny, dependency-free reference for the **verify side** of a discovery and
attestation protocol for AI tool contracts.

An agent fetches a small signed bundle that describes a tool's current API
contract, verifies it, and gets a verdict before any tool code runs. This repo
implements the verify half: signature check, hash pin, freshness, and the
verdict gate. It runs on plain `python3` with no installs.

It is the companion to the protocol sketch:
https://coderifts.com/blog/contract-discovery-attestation-protocol/

The design was worked out in the open. The fetch-flow half (well-known endpoint
plus the signed ref advertisement) is being sketched separately; this is the
verify half, meant to wire together into one reference loop. The combined round
trip (fetch plus verify) now runs end to end in `demo_loop.py`.

## The bundle

A bundle is a small JSON object. The signature covers every field except `signature`. The canonical, machine
readable schema is [`bundle.schema.json`](bundle.schema.json) with a
human-readable reference in [`SCHEMA.md`](SCHEMA.md). Any issuer can produce a
conformant bundle and any agent can verify one without sharing code.

The well-known document carries the `bundle` plus the contract, delivered either
inline as `contract` (small specs, single round trip) or as a `contract_url` the
agent fetches separately (large specs). `fetcher.py` handles both.

Cross-implementation conformance vectors live in
[`test-vectors.json`](test-vectors.json): signed bundles, contracts, and
expected outcomes, plus the guard public key, covering every gate. Any verify
side can be checked against them with `python3 check_vectors.py`.

```
{
  "ref": "refs/heads/main",
  "commit_sha": "<40 hex>",
  "content_hash": "sha256:<hex>",
  "issued_at": 1000000,
  "ttl_seconds": 300,
  "version": 7,
  "verdict": "PASS",            // PASS | REQUIRE_APPROVAL | BLOCK
  "key_id": "ed25519:guard-ci",
  "signature": "<hex>"
}
```

## The verify pipeline

Order matters:

1. **Signature.** Verify the bundle signature against a trusted guard key.
2. **Hash pin.** `content_hash` must equal `sha256` of the contract bytes.
3. **Freshness.** `ref` matches, `version` is not lower than the last accepted
   version (rollback protection), and the bundle is inside its TTL.
4. **Gate.** Map the verdict to an action: `PASS` allows, `REQUIRE_APPROVAL`
   holds for escalation, `BLOCK` denies. The agent acts on this before calling
   the tool.

Freshness rides on the signed bundle itself, so the agent never walks git
history and makes no extra roundtrips. The version plus TTL is the timestamp
role from TUF, scoped to a single repo, with no central authority.

## Run it

No dependencies. Ed25519 is a small pure-Python implementation in `_ed25519.py`.

```
python3 demo.py
python3 -m unittest -v
```

For the full round trip (fetch side plus verify side), `demo_loop.py` serves a
well-known endpoint from a local stdlib HTTP server, fetches it, and runs the
verify pipeline end to end. Still zero dependencies.

```
python3 demo_loop.py
```

Expected round-trip trace:

```
GET /.well-known/contract      | bundle v7, contract 72 bytes
verify_bundle                  | ok=True verdict=PASS action=allow
last_seen bump                 | -1 -> 7
revalidate at v7               | ok=True action=allow
tampered contract served       | ok=False reason=hash pin mismatch
```

For the zero-config agent path, `contract_guard` wraps any tool so the live
contract verdict gates every call. The tool body runs only on PASS. Stack it
under a framework tool decorator (LangGraph, LangChain) or use it on a plain
function.

```
python3 demo_decorator.py
```

Expected decorator trace:

```
PASS                         | tool ran -> 'order A1: shipped'  (ran=1)
BLOCK                        | raised ContractGuardBlocked(BLOCK), body skipped (ran=1)
REQUIRE_APPROVAL             | raised ContractGuardHold(REQUIRE_APPROVAL), body skipped (ran=1)
tampered contract            | raised ContractGuardError(hash pin mismatch), body skipped (ran=1)
```

Expected demo trace:

```
fresh PASS                 | ACCEPT | verdict=PASS             | action=allow | ok
revalidate at v7           | ACCEPT | verdict=PASS             | action=allow | ok
fresh BLOCK                | ACCEPT | verdict=BLOCK            | action=deny  | ok
fresh REQUIRE_APPROVAL     | ACCEPT | verdict=REQUIRE_APPROVAL | action=hold  | ok
tampered contract          | REJECT | verdict=-                | action=-     | hash pin mismatch
rollback to v5             | REJECT | verdict=-                | action=-     | rollback: version 5 < last seen 7
expired (past TTL)         | REJECT | verdict=-                | action=-     | expired: now 1000301 > issued_at+ttl 1000300
wrong ref (dev)            | REJECT | verdict=-                | action=-     | ref mismatch: refs/heads/dev
untrusted signer           | REJECT | verdict=-                | action=-     | signature invalid
```

## What this is, and is not

- This is the **protocol** verify layer. The guard that decides
  `PASS / REQUIRE_APPROVAL / BLOCK` is a black box here. Any guard that emits a
  deterministic, signable verdict fits.
- `issuer.py` is a local signer that stands in for the guard so the example runs
  end to end. In a real deployment the verdict is signed by the guard identity
  in CI: keyless OIDC workload identity, or a guard public key anchored in the
  signed repo so git history is the root of trust.
- Provenance stays with the author commit signature. The verdict is a separate
  signature from the guard. Two roles, two keys.

## Files

- `coderifts_verify.py` verify pipeline and the gate
- `_ed25519.py` dependency-free Ed25519
- `bundle.schema.json` canonical bundle schema (JSON Schema 2020-12)
- `SCHEMA.md` human-readable reference for the bundle
- `schema_validate.py` dependency-free schema checker
- `issuer.py` test signer (stands in for the guard in CI)
- `fetcher.py` minimal reference fetch side: one GET of the well-known endpoint
- `decorator.py` zero-config `contract_guard` for any agent tool
- `demo.py` verify-side scenarios, prints the trace, asserts every outcome
- `demo_loop.py` full round trip: serves a well-known endpoint, fetches, verifies
- `demo_decorator.py` guarded tool: runs on PASS, skipped on BLOCK or hold or tamper
- `test_verify.py` verify-side unit tests
- `test_schema.py` schema conformance tests
- `test_fetcher.py` envelope tests (inline contract and contract_url)
- `test_decorator.py` decorator gate tests
- `test-vectors.json` cross-implementation conformance vectors (with guard public key)
- `check_vectors.py` runs any verify side against the vectors
- `test_vectors.py` runs the vectors in the test suite

## License

MIT. See `LICENSE`.
