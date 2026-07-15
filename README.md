# CodeRifts receipt-verifier

Verify CodeRifts Ed25519 chain-receipts **without trusting CodeRifts**.

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
  (`crchain.v1|kid|fp|prev|caller|ts` and, for v2 receipts, `|reg`).
- For a chain: every receipt's signature is valid AND each non-genesis link's
  `prev` equals `sha256:` + SHA-256 of the previous token string.

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

Output (exit code 0 = valid, 1 = invalid, 2 = usage error):

```
{"valid":true,"payload":{"v":2,"kid":"2026-07-k1","fp":"sha256:...","prev":"null","caller":"anon","ts":"...","reg":"..."}}
```

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

## CLI reference

```
verify.js <receipt> [--key pub.pem] [--kid <kid>] [--fetch <url>]
verify.js --chain receipts.txt [--key pub.pem] [--kid <kid>] [--fetch <url>]

verify.py <receipt> [--key pub.pem] [--kid <kid>] [--fetch <url>]
verify.py --chain receipts.txt [--key pub.pem] [--kid <kid>] [--fetch <url>]
```

- `--key <pem>`   verify against a local SPKI PEM public key (offline).
- `--kid <kid>`   expected key id; mismatch yields `unknown_kid`.
- `--fetch <url>` key-discovery URL (default:
  `https://app.coderifts.com/api/v1/attestation/public-key`), used only when
  `--key` is absent.

Error reasons: `malformed_structure`, `bad_json`, `unknown_kid`,
`signature_error`, `signature_mismatch` (see RECEIPT_FORMAT.md section 6).

## Key rotation limitation

There is a single active signing kid. When CodeRifts rotates the key, receipts
signed under the previous kid fail as `unknown_kid`. If you need to verify old
receipts, pin the `public_key_pem` that was active at issuance, or verify
promptly.

## Tests

```
node test/gen-vectors.js   # regenerate vectors with a fresh EPHEMERAL key
bash test/run.sh           # run every vector through BOTH verify.js and verify.py
```

`test/run.sh` fails if the two implementations ever disagree, if any vector does
not match its expected `{valid, reason}`, or if exit codes diverge. The generated
`test/vectors.json` uses an ephemeral key -- never the production key.

## License

MIT.
