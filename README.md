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
  present and in the past, `status` is `VERIFIED_EXPIRED` (signature may still
  be authentic; `valid` is false for that status). v4 is issued only on
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
CodeRifts check comment. Copy that token and verify it — the public key is fetched
from the attestation endpoint automatically, so this is the one command a reader
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

## CLI reference

```
verify.js <receipt> [--key pub.pem | --keys <url|file>] [--kid <kid>] [--fetch <url>] [--envelope <file>]
verify.js --chain receipts.txt [--key pub.pem | --keys <url|file>] [--kid <kid>] [--fetch <url>]

verify.py <receipt> [--key pub.pem | --keys <url|file>] [--kid <kid>] [--fetch <url>] [--envelope <file>]
verify.py --chain receipts.txt [--key pub.pem | --keys <url|file>] [--kid <kid>] [--fetch <url>]
```

- `--key <pem>`         verify against a local SPKI PEM public key (offline).
- `--keys <src>`        resolve the key by `kid` from a registry (URL or file); accepts
  active and retired keys. Mutually exclusive with `--key`.
- `--kid <kid>`         expected key id; mismatch yields `unknown_kid`.
- `--fetch <url>`       key-discovery URL (default:
  `https://app.coderifts.com/api/v1/attestation/public-key`), used only when
  `--key`/`--keys` are absent.
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
`retired_key_after_issue`.

Live `status` values include `VERIFIED_CURRENT` and, for v4 when `expires_at` is
in the past, `VERIFIED_EXPIRED` (signature authentic but expired — `valid` is
false). Full 12-status taxonomy: RECEIPT_FORMAT.md section 6.

## Key rotation

There is a single *active* signing kid at any time. When CodeRifts rotates the
key, the previous kid is marked `retired` (never removed) in the append-only
registry at `/.well-known/coderifts-keys.json`. To verify receipts across a
rotation, pass `--keys <registry-url|file>` so the verifier resolves each
receipt's key by its `kid`. Without the registry (a single pinned `--key` or the
discovery endpoint), receipts signed under a previous kid fail as `unknown_kid` —
pin the `public_key_pem` active at issuance, or verify promptly.

## Tests

```
node test/gen-vectors.js   # regenerate vectors with a fresh EPHEMERAL key
bash test/run.sh           # run every vector through BOTH verify.js and verify.py
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

## License

MIT.
