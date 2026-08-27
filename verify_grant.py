#!/usr/bin/env python3
"""CodeRifts cr.exec.v1 execution-grant verifier -- Python 3.10+, depends only on `cryptography`.

Sibling of verify.py; a user who knows verify.py should feel at home.

Usage:
  python3 verify_grant.py <grant> --keys <url|file>
       [--intended-operation X --intended-target Y --intended-audience Z]
       [--intended-after-file PATH | --intended-scope-hash sha256:…]
       [--receipt <token>]
  python3 verify_grant.py <grant> --key pub.pem [--kid <kid>]

Key discovery: --keys resolves by kid from a registry
  ({keys: [{kid, public_key_pem, status, valid_from, retired_at}]}).
--key pins a single SPKI PEM. --key and --keys are mutually exclusive.
With neither, the public key is fetched from
  https://app.coderifts.com/api/v1/attestation/public-key  (override --fetch).

Output: JSON { valid, status, reason?, payload? } to stdout — byte-identical to verify-grant.js.
Exit codes: 0 GRANT_CURRENT, 1 otherwise, 2 usage error.

Retired kid → UNKNOWN_KEY. Grants are live execution permission; receipts may
forensically verify a retired key inside [valid_from, retired_at), grants must not
(see coderifts-app/docs/cr-exec-v1.md).
"""

import json
import sys

from cryptography.exceptions import InvalidSignature

from verify import (
    CLOCK_SKEW_LEEWAY_MS,
    b64url_decode,
    canonical_json,
    expiry_leeway_ms,
    fetch_key_info,
    is_expired_at,
    key_from_pem,
    load_keyring,
    sha256hex,
)

GRANT_VERSION = "cr.exec.v1"
GRANT_VERSION_V2 = "cr.exec.v2"
SIGNING_PREFIX = "crexec.v1"
SIGNING_PREFIX_V2 = "crexec.v2"
NUL = "\x1f"
SIGNED_FIELDS = [
    "kid", "receipt_digest", "scope_hash", "audience", "operation", "target_id", "jti", "iat", "exp",
]
V2_REQUIRED_STRINGS = [
    "v", "kid", "grant_id", "receipt_hash", "tenant_id", "executor_id", "adapter_id",
    "operation", "target_uri", "expected_state_token", "after_payload_hash",
    "nonce_hash", "policy_hash", "audience_hash", "not_before", "expires_at",
]
TARGET_SCHEMES = ("fs", "git", "api", "db", "registry", "deploy")
DEFAULT_FETCH_URL = "https://app.coderifts.com/api/v1/attestation/public-key"

USAGE = (
    "usage: python3 verify_grant.py <grant> [--key pub.pem | --keys <url|file>] [--kid <kid>] [--fetch <url>]\n"
    "                             [--intended-operation X] [--intended-target Y] [--intended-audience Z]\n"
    "                             [--intended-after-file PATH | --intended-scope-hash sha256:…]\n"
    "                             [--receipt <token>]\n"
)


def is_issued_in_future(issued_at_ms, now_ms, context=None):
    if issued_at_ms is None or now_ms is None:
        return False
    try:
        issued_at_ms = float(issued_at_ms)
        now_ms = float(now_ms)
    except (TypeError, ValueError):
        return False
    if not (issued_at_ms == issued_at_ms) or not (now_ms == now_ms):
        return False
    return issued_at_ms > (now_ms + expiry_leeway_ms(context))


def scalar(v):
    return "" if v is None else str(v)


def sha256pref(s):
    return "sha256:" + sha256hex(str(s))


def canonicalize_target_uri(raw):
    import re
    if not isinstance(raw, str) or len(raw) == 0:
        return None
    m = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*)://([^?#]*)$", raw)
    if not m:
        return None
    scheme = m.group(1).lower()
    if scheme not in TARGET_SCHEMES:
        return None
    rest = m.group(2)
    if re.match(r"^[^\s/]*:", rest) and "@" in rest and scheme != "git":
        return None
    if ".." in rest or "//" in rest or re.search(r"\s", rest):
        return None
    if rest.endswith("/") and len(rest) > 1:
        rest = rest.rstrip("/")
    return scheme + "://" + rest


def signing_input_v2(body):
    return SIGNING_PREFIX_V2 + "|" + canonical_json(body)


def reconstruct_signed_input(payload):
    return "|".join(
        [
            SIGNING_PREFIX,
            scalar(payload.get("kid")),
            scalar(payload.get("receipt_digest")),
            scalar(payload.get("scope_hash")),
            scalar(payload.get("audience")),
            scalar(payload.get("operation")),
            scalar(payload.get("target_id")),
            scalar(payload.get("jti")),
            scalar(payload.get("iat")),
            scalar(payload.get("exp")),
        ]
    )


def compute_scope_hash(operation=None, target_id=None, after_payload=None):
    preimage = NUL.join(
        [
            "" if operation is None else str(operation),
            "" if target_id is None else str(target_id),
            "" if after_payload is None else str(after_payload),
        ]
    )
    return "sha256:" + sha256hex(preimage)


def receipt_digest(token):
    return "sha256:" + sha256hex(str(token))


def resolve_entry(ctx, payload):
    kid = payload.get("kid")
    if ctx.get("keyring") is not None:
        entry = ctx["keyring"].get(kid)
        if entry is None:
            return None
        if ctx.get("expected_kid") is not None and kid != ctx["expected_kid"]:
            return None
        return entry
    if ctx.get("expected_kid") is not None and kid != ctx["expected_kid"]:
        return None
    return {"public_key": ctx["public_key"], "status": None, "retired_at": None}


def _parse_iso_ms(ts):
    from datetime import datetime

    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp() * 1000
    except Exception:
        return None


def _verify_execution_grant_v2(payload, sig_b64, ctx, opts):
    opts = opts or {}
    for k in V2_REQUIRED_STRINGS:
        v = payload.get(k)
        if not isinstance(v, str) or len(v) == 0:
            return {"valid": False, "status": "MALFORMED", "reason": "missing_field", "payload": payload}
    if not isinstance(payload.get("max_attempts"), int) or payload["max_attempts"] < 1:
        return {"valid": False, "status": "MALFORMED", "reason": "bad_max_attempts", "payload": payload}
    allowed = set(V2_REQUIRED_STRINGS + ["max_attempts"])
    for k in payload.keys():
        if k not in allowed:
            return {"valid": False, "status": "MALFORMED", "reason": "unknown_field", "payload": payload}
    if canonicalize_target_uri(payload.get("target_uri")) is None:
        return {"valid": False, "status": "MALFORMED", "reason": "bad_target_uri", "payload": payload}

    entry = resolve_entry(ctx, payload)
    if entry is None:
        return {"valid": False, "status": "UNKNOWN_KEY", "reason": "unknown_kid", "payload": payload}
    if entry.get("status") == "retired":
        return {"valid": False, "status": "UNKNOWN_KEY", "reason": "retired_kid", "payload": payload}

    message = signing_input_v2(payload).encode("utf-8")
    try:
        sig = b64url_decode(sig_b64)
    except Exception:
        return {"valid": False, "status": "INVALID_SIGNATURE", "reason": "signature_error", "payload": payload}
    try:
        entry["public_key"].verify(sig, message)
    except InvalidSignature:
        return {"valid": False, "status": "INVALID_SIGNATURE", "reason": "signature_mismatch", "payload": payload}
    except Exception:
        return {"valid": False, "status": "INVALID_SIGNATURE", "reason": "signature_error", "payload": payload}

    from datetime import datetime, timezone
    now = opts["now"] if opts.get("now") is not None else (datetime.now(timezone.utc).timestamp() * 1000)
    exp_ms = _parse_iso_ms(payload.get("expires_at"))
    nbf_ms = _parse_iso_ms(payload.get("not_before"))
    if exp_ms is None or nbf_ms is None:
        return {"valid": False, "status": "MALFORMED", "reason": "bad_timestamp", "payload": payload}
    intended = opts.get("intended") if isinstance(opts.get("intended"), dict) else {}
    if is_expired_at(exp_ms, now, intended):
        return {"valid": False, "status": "GRANT_EXPIRED", "reason": "expired", "payload": payload}
    if is_issued_in_future(nbf_ms, now, intended):
        return {"valid": False, "status": "GRANT_EXPIRED", "reason": "nbf_in_future", "payload": payload}

    if intended.get("executor_id") and payload.get("executor_id") != str(intended["executor_id"]):
        return {"valid": False, "status": "GRANT_UNBOUND", "reason": "executor_mismatch", "payload": payload}
    if intended.get("adapter_id") and payload.get("adapter_id") != str(intended["adapter_id"]):
        return {"valid": False, "status": "GRANT_UNBOUND", "reason": "adapter_mismatch", "payload": payload}
    if intended.get("target_uri"):
        want = canonicalize_target_uri(str(intended["target_uri"])) or str(intended["target_uri"])
        if payload.get("target_uri") != want:
            return {"valid": False, "status": "GRANT_UNBOUND", "reason": "target_mismatch", "payload": payload}
    if intended.get("audience"):
        if payload.get("audience_hash") != sha256pref(intended["audience"]):
            return {"valid": False, "status": "GRANT_UNBOUND", "reason": "audience_mismatch", "payload": payload}
    if intended.get("audience_hash") and payload.get("audience_hash") != str(intended["audience_hash"]):
        return {"valid": False, "status": "GRANT_UNBOUND", "reason": "audience_mismatch", "payload": payload}
    if intended.get("after_payload") is not None:
        if payload.get("after_payload_hash") != sha256pref(intended["after_payload"]):
            return {"valid": False, "status": "GRANT_UNBOUND", "reason": "after_payload_mismatch", "payload": payload}
    if intended.get("operation") and payload.get("operation") != str(intended["operation"]):
        return {"valid": False, "status": "GRANT_UNBOUND", "reason": "operation_mismatch", "payload": payload}
    if intended.get("receipt_token"):
        if sha256pref(intended["receipt_token"]) != payload.get("receipt_hash"):
            return {"valid": False, "status": "GRANT_UNBOUND", "reason": "receipt_hash_mismatch", "payload": payload}
    return {"valid": True, "status": "GRANT_CURRENT", "payload": payload}


def verify_execution_grant(token, ctx=None, opts=None):
    from arity import split3
    c, o = split3("verify_execution_grant", ctx, opts)
    return _verify_execution_grant(token, c, o)


def _verify_execution_grant(token, ctx, opts=None):
    """10-step algorithm from docs/cr-exec-v1.md. Return key-for-key match of verify-grant.js."""
    opts = opts or {}
    # 1. structure
    if not isinstance(token, str) or len(token) == 0:
        return {"valid": False, "status": "MALFORMED", "reason": "malformed_structure"}
    segments = token.split(".")
    if len(segments) != 2 or any(len(s) == 0 for s in segments):
        return {"valid": False, "status": "MALFORMED", "reason": "malformed_structure"}

    # 2. json
    try:
        payload = json.loads(b64url_decode(segments[0]).decode("utf-8"))
    except Exception:
        return {"valid": False, "status": "MALFORMED", "reason": "bad_json"}
    if not isinstance(payload, dict):
        return {"valid": False, "status": "MALFORMED", "reason": "bad_json"}
    if payload.get("v") == GRANT_VERSION_V2:
        return _verify_execution_grant_v2(payload, segments[1], ctx, opts)
    if payload.get("v") != GRANT_VERSION:
        return {"valid": False, "status": "MALFORMED", "reason": "unsupported_version", "payload": payload}
    for k in SIGNED_FIELDS:
        if not isinstance(payload.get(k), str):
            return {"valid": False, "status": "MALFORMED", "reason": "missing_field", "payload": payload}
    allowed = set(["v"] + SIGNED_FIELDS)
    for k in payload.keys():
        if k not in allowed:
            return {"valid": False, "status": "MALFORMED", "reason": "unknown_field", "payload": payload}

    # 3. delimiter
    for k in SIGNED_FIELDS:
        if "|" in payload[k]:
            return {"valid": False, "status": "INVALID_SIGNATURE", "reason": "delimiter_in_field", "payload": payload}

    # 4. kid — unknown OR retired → UNKNOWN_KEY.
    # Grants are live execution permission. Receipts may forensically verify a
    # retired key inside [valid_from, retired_at); grants must not.
    entry = resolve_entry(ctx, payload)
    if entry is None:
        return {"valid": False, "status": "UNKNOWN_KEY", "reason": "unknown_kid", "payload": payload}
    if entry.get("status") == "retired":
        return {"valid": False, "status": "UNKNOWN_KEY", "reason": "retired_kid", "payload": payload}

    # KEY STATUS GATE -- RECEIPT_FORMAT 7.1 (normative); mirrors verify-grant.js exactly.
    # Grants KEEP their own vocabulary (UNKNOWN_KEY + reason), see the JS sibling for why.
    if entry.get("status") == "revoked":
        _at = entry.get("compromised_at")
        _b = None
        if isinstance(_at, str) and _at:
            try:
                from datetime import datetime
                _b = datetime.fromisoformat(_at.replace("Z", "+00:00")).timestamp() * 1000.0
            except Exception:
                _b = None
        # iat is an ISO STRING in cr.exec.v1; numeric epoch accepted defensively.
        _i = None
        _raw = payload.get("iat")
        if isinstance(_raw, str) and _raw:
            try:
                from datetime import datetime as _dt
                _i = _dt.fromisoformat(_raw.replace("Z", "+00:00")).timestamp() * 1000.0
            except Exception:
                _i = None
        else:
            try:
                _i = float(_raw) * 1000.0
            except Exception:
                _i = None
        _decided = _b is not None and _i is not None and _i >= _b
        return {"valid": False, "status": "UNKNOWN_KEY",
                "reason": "revoked_kid" if _decided else "revoked_kid_undecidable", "payload": payload}
    if entry.get("status") is not None and entry.get("status") != "active":
        return {"valid": False, "status": "UNKNOWN_KEY", "reason": "unknown_key_status", "payload": payload}

    # 5. Ed25519 over crexec.v1|… pipe input
    message = reconstruct_signed_input(payload).encode("utf-8")
    try:
        sig = b64url_decode(segments[1])
    except Exception:
        return {"valid": False, "status": "INVALID_SIGNATURE", "reason": "signature_error", "payload": payload}
    try:
        entry["public_key"].verify(sig, message)
    except InvalidSignature:
        return {"valid": False, "status": "INVALID_SIGNATURE", "reason": "signature_mismatch", "payload": payload}
    except Exception:
        return {"valid": False, "status": "INVALID_SIGNATURE", "reason": "signature_error", "payload": payload}

    # 6. timestamps
    from datetime import datetime, timezone

    now = opts["now"] if opts.get("now") is not None else (datetime.now(timezone.utc).timestamp() * 1000)
    exp_ms = _parse_iso_ms(payload.get("exp"))
    iat_ms = _parse_iso_ms(payload.get("iat"))
    if exp_ms is None or iat_ms is None:
        return {"valid": False, "status": "MALFORMED", "reason": "bad_timestamp", "payload": payload}
    intended = opts.get("intended") if isinstance(opts.get("intended"), dict) else {}
    if is_expired_at(exp_ms, now, intended):
        return {"valid": False, "status": "GRANT_EXPIRED", "reason": "expired", "payload": payload}
    if is_issued_in_future(iat_ms, now, intended):
        return {"valid": False, "status": "GRANT_EXPIRED", "reason": "iat_in_future", "payload": payload}

    # 7. receipt_digest
    if not payload.get("receipt_digest") or not str(payload["receipt_digest"]).startswith("sha256:"):
        return {"valid": False, "status": "GRANT_UNBOUND", "reason": "missing_receipt_digest", "payload": payload}
    if intended.get("receipt_token"):
        if receipt_digest(intended["receipt_token"]) != payload["receipt_digest"]:
            return {"valid": False, "status": "GRANT_UNBOUND", "reason": "receipt_digest_mismatch", "payload": payload}

    # 8. audience / operation / target
    if intended.get("audience") not in (None, "") and payload.get("audience") != str(intended["audience"]):
        return {"valid": False, "status": "GRANT_WRONG_AUDIENCE", "reason": "audience_mismatch", "payload": payload}
    if intended.get("operation") not in (None, "") and payload.get("operation") != str(intended["operation"]):
        return {"valid": False, "status": "GRANT_SCOPE_MISMATCH", "reason": "operation_mismatch", "payload": payload}
    if intended.get("target_id") not in (None, "") and payload.get("target_id") != str(intended["target_id"]):
        return {"valid": False, "status": "GRANT_SCOPE_MISMATCH", "reason": "target_mismatch", "payload": payload}

    # 9. scope_hash
    expected_scope = None
    if intended.get("scope_hash"):
        expected_scope = str(intended["scope_hash"])
    elif intended.get("after_payload") is not None:
        expected_scope = compute_scope_hash(
            operation=intended["operation"] if intended.get("operation") is not None else payload.get("operation"),
            target_id=intended["target_id"] if intended.get("target_id") is not None else payload.get("target_id"),
            after_payload=intended["after_payload"],
        )
    if expected_scope is not None and expected_scope != payload.get("scope_hash"):
        return {"valid": False, "status": "GRANT_SCOPE_MISMATCH", "reason": "scope_hash_mismatch", "payload": payload}

    # 10.
    return {"valid": True, "status": "GRANT_CURRENT", "payload": payload}


def fail(msg):
    sys.stderr.write(msg + "\n" + USAGE)
    sys.exit(2)


def parse_args(argv):
    opts = {
        "grant": None,
        "key_file": None,
        "keys_source": None,
        "kid": None,
        "fetch_url": None,
        "intended_operation": None,
        "intended_target": None,
        "intended_audience": None,
        "intended_executor": None,
        "intended_adapter": None,
        "intended_after_file": None,
        "intended_scope_hash": None,
        "receipt": None,
        "help": False,
    }
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--key":
            i += 1
            opts["key_file"] = argv[i] if i < len(argv) else None
        elif a == "--keys":
            i += 1
            opts["keys_source"] = argv[i] if i < len(argv) else None
        elif a == "--kid":
            i += 1
            opts["kid"] = argv[i] if i < len(argv) else None
        elif a == "--fetch":
            i += 1
            opts["fetch_url"] = argv[i] if i < len(argv) else None
        elif a == "--intended-operation":
            i += 1
            opts["intended_operation"] = argv[i] if i < len(argv) else None
        elif a == "--intended-target":
            i += 1
            opts["intended_target"] = argv[i] if i < len(argv) else None
        elif a == "--intended-audience":
            i += 1
            opts["intended_audience"] = argv[i] if i < len(argv) else None
        elif a == "--intended-executor":
            i += 1
            opts["intended_executor"] = argv[i] if i < len(argv) else None
        elif a == "--intended-adapter":
            i += 1
            opts["intended_adapter"] = argv[i] if i < len(argv) else None
        elif a == "--intended-after-file":
            i += 1
            opts["intended_after_file"] = argv[i] if i < len(argv) else None
        elif a == "--intended-scope-hash":
            i += 1
            opts["intended_scope_hash"] = argv[i] if i < len(argv) else None
        elif a == "--receipt":
            i += 1
            opts["receipt"] = argv[i] if i < len(argv) else None
        elif a in ("-h", "--help"):
            opts["help"] = True
        elif a.startswith("--"):
            raise ValueError("unknown flag: " + a)
        elif opts["grant"] is None:
            opts["grant"] = a
        else:
            raise ValueError("unexpected argument: " + a)
        i += 1
    if opts["key_file"] and opts["keys_source"]:
        raise ValueError("--key and --keys are mutually exclusive")
    if opts["intended_after_file"] and opts["intended_scope_hash"]:
        raise ValueError("--intended-after-file and --intended-scope-hash are mutually exclusive")
    return opts


def main():
    try:
        opts = parse_args(sys.argv[1:])
    except ValueError as e:
        fail(str(e))
    if opts["help"]:
        sys.stdout.write(USAGE)
        sys.exit(2)
    if not opts["grant"] or not str(opts["grant"]).strip():
        fail("no grant provided")

    try:
        if opts["keys_source"]:
            ctx = {"keyring": load_keyring(opts["keys_source"]), "expected_kid": opts["kid"]}
        elif opts["key_file"]:
            with open(opts["key_file"], "r", encoding="utf-8") as fh:
                public_key = key_from_pem(fh.read())
            ctx = {"public_key": public_key, "expected_kid": opts["kid"]}
        else:
            public_key, discovered_kid = fetch_key_info(opts["fetch_url"] or DEFAULT_FETCH_URL)
            ctx = {"public_key": public_key, "expected_kid": opts["kid"] or discovered_kid}
    except Exception as e:
        fail("could not load public key: " + str(e))

    intended = {}
    if opts["intended_operation"] is not None:
        intended["operation"] = opts["intended_operation"]
    if opts["intended_target"] is not None:
        intended["target_id"] = opts["intended_target"]
        intended["target_uri"] = opts["intended_target"]
    if opts["intended_audience"] is not None:
        intended["audience"] = opts["intended_audience"]
    if opts["intended_executor"] is not None:
        intended["executor_id"] = opts["intended_executor"]
    if opts["intended_adapter"] is not None:
        intended["adapter_id"] = opts["intended_adapter"]
    if opts["intended_scope_hash"] is not None:
        intended["scope_hash"] = opts["intended_scope_hash"]
    if opts["receipt"] is not None:
        intended["receipt_token"] = opts["receipt"]
    if opts["intended_after_file"]:
        try:
            with open(opts["intended_after_file"], "r", encoding="utf-8") as fh:
                intended["after_payload"] = fh.read()
        except Exception as e:
            fail("could not read --intended-after-file: " + str(e))

    result = _verify_execution_grant(opts["grant"], ctx, {"intended": intended})
    sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
    sys.exit(0 if result["valid"] else 1)


if __name__ == "__main__":
    main()
