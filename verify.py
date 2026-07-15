#!/usr/bin/env python3
"""CodeRifts chain-receipt verifier -- Python 3.10+, depends only on `cryptography`.

Verifies an Ed25519-signed CodeRifts chain_receipt WITHOUT trusting the CodeRifts
service. The reference format is frozen in ./RECEIPT_FORMAT.md.

Usage:
  python3 verify.py <receipt> [--key pub.pem] [--kid <kid>] [--fetch <url>]
  python3 verify.py --chain receipts.txt [--key pub.pem] [--kid <kid>] [--fetch <url>]

Key discovery: with no --key, the public key is fetched from
  https://app.coderifts.com/api/v1/attestation/public-key  (override with --fetch <url>).

Output: JSON { valid, reason?, payload?, chain? } to stdout.
Exit codes: 0 valid, 1 invalid, 2 usage error.

Verification order (matches the reference taxonomy exactly):
  structure -> json -> kid -> signature
Reasons: malformed_structure | bad_json | unknown_kid | signature_error | signature_mismatch
"""

import base64
import hashlib
import json
import sys
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DEFAULT_FETCH_URL = "https://app.coderifts.com/api/v1/attestation/public-key"
SIGNING_PREFIX = "crchain.v1"
USAGE = (
    "usage: python3 verify.py <receipt> [--key pub.pem] [--kid <kid>] [--fetch <url>]\n"
    "       python3 verify.py --chain receipts.txt [--key pub.pem] [--kid <kid>] [--fetch <url>]\n"
)


def b64url_decode(seg):
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def sha256hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def reconstruct_signed_input(payload):
    """Byte-identical to verify.js reconstructSignedInput."""
    base = "{p}|{kid}|{fp}|{prev}|{caller}|{ts}".format(
        p=SIGNING_PREFIX,
        kid=payload["kid"],
        fp=payload["fp"],
        prev=payload["prev"],
        caller=payload["caller"],
        ts=payload["ts"],
    )
    if payload.get("v") == 2:
        return base + "|" + str(payload["reg"])
    return base


def verify_receipt(token, public_key, expected_kid):
    """Return an ordered dict {valid, reason?, payload?} matching verify.js."""
    # 1. structure
    if not isinstance(token, str) or len(token) == 0:
        return {"valid": False, "reason": "malformed_structure"}
    segments = token.split(".")
    if len(segments) != 2 or any(len(s) == 0 for s in segments):
        return {"valid": False, "reason": "malformed_structure"}

    # 2. json
    try:
        payload = json.loads(b64url_decode(segments[0]).decode("utf-8"))
    except Exception:
        return {"valid": False, "reason": "bad_json"}
    if not isinstance(payload, dict):
        return {"valid": False, "reason": "bad_json"}

    # 3. kid -- enforced only when an expected kid is known (from --kid or discovery).
    if expected_kid is not None and payload.get("kid") != expected_kid:
        return {"valid": False, "reason": "unknown_kid", "payload": payload}

    # 4. signature (raw Ed25519 over the reconstructed UTF-8 bytes)
    message = reconstruct_signed_input(payload).encode("utf-8")
    try:
        sig = b64url_decode(segments[1])
    except Exception:
        return {"valid": False, "reason": "signature_error", "payload": payload}
    try:
        public_key.verify(sig, message)
    except InvalidSignature:
        return {"valid": False, "reason": "signature_mismatch", "payload": payload}
    except Exception:
        return {"valid": False, "reason": "signature_error", "payload": payload}

    return {"valid": True, "payload": payload}


def verify_chain(tokens, public_key, expected_kid):
    links = []
    all_valid = True
    first = None

    for i, token in enumerate(tokens):
        res = verify_receipt(token, public_key, expected_kid)
        link = {"index": i, "signature_valid": res["valid"]}
        if not res["valid"]:
            link["reason"] = res["reason"]
        prev = res.get("payload", {}).get("prev") if res.get("payload") else None
        if res.get("payload"):
            link["prev"] = prev

        if i == 0:
            first = "genesis" if prev == "null" else "continuation"
            link["role"] = first
            link["prev_ok"] = True if prev == "null" else None
        else:
            expected = "sha256:" + sha256hex(tokens[i - 1])
            link["expected_prev"] = expected
            link["prev_ok"] = prev == expected
            if not link["prev_ok"]:
                all_valid = False

        if not res["valid"]:
            all_valid = False
        links.append(link)

    return {"valid": all_valid, "chain": {"length": len(tokens), "first": first, "links": links}}


def key_from_pem(pem_text):
    key = load_pem_public_key(pem_text.encode("utf-8"))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("public key is not Ed25519")
    return key


def fetch_key_info(url):
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 (explicit --fetch/default only)
        info = json.loads(resp.read().decode("utf-8"))
    if not info or not info.get("public_key_pem"):
        raise ValueError("no public_key_pem at " + url)
    return key_from_pem(info["public_key_pem"]), info.get("kid")


def fail(msg):
    sys.stderr.write(msg + "\n" + USAGE)
    sys.exit(2)


def parse_args(argv):
    opts = {"receipt": None, "chain_file": None, "key_file": None, "kid": None, "fetch_url": None, "help": False}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--chain":
            i += 1
            opts["chain_file"] = argv[i] if i < len(argv) else None
        elif a == "--key":
            i += 1
            opts["key_file"] = argv[i] if i < len(argv) else None
        elif a == "--kid":
            i += 1
            opts["kid"] = argv[i] if i < len(argv) else None
        elif a == "--fetch":
            i += 1
            opts["fetch_url"] = argv[i] if i < len(argv) else None
        elif a in ("-h", "--help"):
            opts["help"] = True
        elif a.startswith("--"):
            raise ValueError("unknown flag: " + a)
        elif opts["receipt"] is None:
            opts["receipt"] = a
        else:
            raise ValueError("unexpected argument: " + a)
        i += 1
    return opts


def main():
    try:
        opts = parse_args(sys.argv[1:])
    except ValueError as e:
        fail(str(e))
    if opts["help"]:
        sys.stdout.write(USAGE)
        sys.exit(2)
    if not opts["chain_file"] and not opts["receipt"]:
        fail("no receipt provided")

    # Resolve the verification key + expected kid.
    try:
        if opts["key_file"]:
            with open(opts["key_file"], "r", encoding="utf-8") as fh:
                public_key = key_from_pem(fh.read())
            expected_kid = opts["kid"]
        else:
            public_key, discovered_kid = fetch_key_info(opts["fetch_url"] or DEFAULT_FETCH_URL)
            expected_kid = opts["kid"] or discovered_kid
    except Exception as e:
        fail("could not load public key: " + str(e))

    if opts["chain_file"]:
        with open(opts["chain_file"], "r", encoding="utf-8") as fh:
            tokens = [ln.strip() for ln in fh.read().split("\n") if ln.strip()]
        if not tokens:
            fail("chain file is empty")
        result = verify_chain(tokens, public_key, expected_kid)
    else:
        result = verify_receipt(opts["receipt"], public_key, expected_kid)

    sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
    sys.exit(0 if result["valid"] else 1)


if __name__ == "__main__":
    main()
