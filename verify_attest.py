#!/usr/bin/env python3
"""CodeRifts cr.exec.attest.v1 execution-attestation verifier -- Python 3.10+,
depends only on `cryptography`. Sibling of verify.py / verify_grant.py.

Usage:
  python3 verify_attest.py <token> --keys <file|url>
       [--grant <token>] [--receipt-digest sha256:…]

--keys is REQUIRED. Executor keys are CUSTOMER-HELD; this verifier never
fetches CodeRifts. The registry is the same JSON shape as
.well-known/coderifts-keys.json.

Output: JSON { valid, status, reason?, payload? } to stdout — byte-identical
to verify-attest.js. Exit codes: 0 valid (ATTEST_VALID |
ATTEST_RETIRED_KEY_VALID_AT_ISSUE), 1 otherwise, 2 usage error.

Retired-key rule is HISTORICAL (receipt class): retired kid + committed_at
inside [valid_from, retired_at) → ATTEST_RETIRED_KEY_VALID_AT_ISSUE.
Contrast grants: retired → UNKNOWN_KEY (live permission).

Honesty: a valid attestation proves a holder of the executor key asserts
this commit. It does NOT prove that the executor's code is unmodified
(deploy attestation is out of scope, named as such — a later artifact, not
this one); that a human saw anything; that the underlying grant is currently
GRANT_CURRENT (re-check the grant if live permission is required; this
statement is historical); that result_digest is a CodeRifts fingerprint, a
receipt digest, or an after-payload hash — result_digest is the executor's
choice of bytes.
"""

import json
import sys
import urllib.request
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature

from verify import (
    CLOCK_SKEW_LEEWAY_MS,
    b64url_decode,
    expiry_leeway_ms,
    key_from_pem,
)

ATTEST_VERSION = "cr.exec.attest.v1"
SIGNING_PREFIX = "crexecattest.v1"
ENVELOPE_TAG = "cr.exec.attest.v1"
GRANT_VERSION = "cr.exec.v1"
GRANT_SIGNED_FIELDS = [
    "kid", "receipt_digest", "scope_hash", "audience", "operation", "target_id", "jti", "iat", "exp",
]
REQUIRED_FIELDS = [
    "executor_kid", "grant_jti", "receipt_digest", "scope_hash", "committed_at",
]
OPTIONAL_STRINGS = ["state_nonce", "result_digest"]
ALLOWED_KEYS = set(["v"] + REQUIRED_FIELDS + OPTIONAL_STRINGS + ["meta"])
_MISSING = object()

USAGE = (
    "usage: python3 verify_attest.py <token> --keys <file|url> [--grant <token>] [--receipt-digest sha256:…]\n"
    "\n"
    "--keys is REQUIRED (customer-held executor registry). There is no default fetch.\n"
)


def is_issued_in_future(issued_at_ms, now_ms, context=None):
    if issued_at_ms is None or now_ms is None:
        return False
    try:
        issued_at_ms = float(issued_at_ms)
        now_ms = float(now_ms)
    except (TypeError, ValueError):
        return False
    if issued_at_ms != issued_at_ms or now_ms != now_ms:
        return False
    return issued_at_ms > (now_ms + expiry_leeway_ms(context))


def scalar(v):
    return "" if v is None else str(v)


def canonical_meta(meta):
    o = {k: meta[k] for k in sorted(meta.keys())}
    return json.dumps(o, separators=(",", ":"), ensure_ascii=False)


def meta_ok(meta):
    if meta is None:
        return True
    if not isinstance(meta, dict):
        return False
    keys = list(meta.keys())
    if len(keys) > 8:
        return False
    for k in keys:
        if not isinstance(k, str) or len(k) == 0 or len(k) > 64 or "|" in k:
            return False
        v = meta[k]
        if isinstance(v, bool):
            continue
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            continue
        if isinstance(v, str):
            if len(v) > 256 or "|" in v:
                return False
            continue
        return False
    return True


def signing_input(body):
    sn = body.get("state_nonce")
    rd = body.get("result_digest")
    parts = [
        SIGNING_PREFIX,
        scalar(body.get("executor_kid")),
        scalar(body.get("grant_jti")),
        scalar(body.get("receipt_digest")),
        scalar(body.get("scope_hash")),
        str(sn) if sn not in (None, "") else "",
        scalar(body.get("committed_at")),
        str(rd) if rd not in (None, "") else "",
    ]
    if isinstance(body.get("meta"), dict):
        parts.append(canonical_meta(body["meta"]))
    return "|".join(parts)


def field_has_delimiter(body):
    for k in list(REQUIRED_FIELDS) + list(OPTIONAL_STRINGS):
        v = body.get(k)
        if isinstance(v, str) and "|" in v:
            return True
    return False


def fail(status, reason, payload=_MISSING):
    out = {"valid": False, "status": status, "reason": reason}
    if payload is not _MISSING:
        out["payload"] = payload
    return out


def ok_status(status, payload):
    return {"valid": True, "status": status, "reason": None, "payload": payload}


def _parse_iso_ms(ts):
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp() * 1000
    except Exception:
        return None


def is_issue_time_within_key_window(ts, key_meta):
    if not key_meta or key_meta.get("status") == "active":
        return True
    if key_meta.get("status") != "retired":
        return False
    retired_at = key_meta.get("retired_at")
    if not isinstance(retired_at, str) or len(retired_at) == 0:
        return False
    if not isinstance(ts, str) or len(ts) == 0:
        return False
    issue_ms = _parse_iso_ms(ts)
    if issue_ms is None:
        return False
    valid_from = key_meta.get("valid_from")
    if valid_from:
        from_ms = _parse_iso_ms(valid_from)
        if from_ms is not None and issue_ms < from_ms:
            return False
    retired_ms = _parse_iso_ms(retired_at)
    if retired_ms is None:
        return False
    if issue_ms >= retired_ms:
        return False
    return True


def resolve_executor_key(registry, kid):
    if not registry or not isinstance(registry.get("keys"), list) or not isinstance(kid, str) or not kid:
        return None
    matches = [
        k for k in registry["keys"]
        if k and k.get("kid") == kid and isinstance(k.get("public_key_pem"), str)
    ]
    if not matches:
        return None
    entry = next((k for k in matches if k.get("status") == "active"), matches[0])
    try:
        public_key = key_from_pem(entry["public_key_pem"])
    except Exception:
        return None
    return {
        "public_key": public_key,
        # PASS THE REAL STATUS THROUGH -- normalising non-retired to "active" LAUNDERED a
        # revoked key into a healthy one before any gate could see it (mirrors verify-attest.js).
        "status": entry.get("status") or "active",
        "compromised_at": entry.get("compromised_at"),
        "valid_from": entry.get("valid_from") or None,
        "retired_at": entry.get("retired_at") or None,
    }


def parse_attest_token(token):
    if not isinstance(token, str) or len(token) == 0:
        return {"ok": False, "status": "ATTEST_MALFORMED", "reason": "malformed_structure"}
    segments = token.split("|")
    if len(segments) != 4 or any(len(s) == 0 for s in segments):
        return {"ok": False, "status": "ATTEST_MALFORMED", "reason": "malformed_structure"}
    if segments[0] != ENVELOPE_TAG:
        return {"ok": False, "status": "ATTEST_MALFORMED", "reason": "unsupported_version"}
    envelope_kid = segments[1]
    try:
        payload = json.loads(b64url_decode(segments[2]).decode("utf-8"))
    except Exception:
        return {"ok": False, "status": "ATTEST_MALFORMED", "reason": "bad_json"}
    if not isinstance(payload, dict):
        return {"ok": False, "status": "ATTEST_MALFORMED", "reason": "bad_json"}
    if payload.get("v") != ATTEST_VERSION:
        return {"ok": False, "status": "ATTEST_MALFORMED", "reason": "unsupported_version", "payload": payload}
    for k in REQUIRED_FIELDS:
        if not isinstance(payload.get(k), str) or len(payload[k]) == 0:
            return {"ok": False, "status": "ATTEST_MALFORMED", "reason": "missing_field", "payload": payload}
    for k in OPTIONAL_STRINGS:
        if payload.get(k) is not None and not isinstance(payload.get(k), str):
            return {"ok": False, "status": "ATTEST_MALFORMED", "reason": "bad_optional", "payload": payload}
    if payload.get("executor_kid") != envelope_kid:
        return {"ok": False, "status": "ATTEST_MALFORMED", "reason": "kid_mismatch", "payload": payload}
    for k in payload.keys():
        if k not in ALLOWED_KEYS:
            return {"ok": False, "status": "ATTEST_MALFORMED", "reason": "unknown_field", "payload": payload}
    if not meta_ok(payload.get("meta")):
        return {"ok": False, "status": "ATTEST_MALFORMED", "reason": "meta_bounds", "payload": payload}
    rd = payload.get("result_digest")
    if rd is not None and rd != "" and not str(rd).startswith("sha256:"):
        return {"ok": False, "status": "ATTEST_MALFORMED", "reason": "bad_result_digest", "payload": payload}
    if payload.get("receipt_digest") and not str(payload["receipt_digest"]).startswith("sha256:"):
        return {"ok": False, "status": "ATTEST_MALFORMED", "reason": "bad_receipt_digest", "payload": payload}
    return {"ok": True, "payload": payload, "sig": segments[3], "envelopeKid": envelope_kid}


def parse_grant_token(token):
    if not isinstance(token, str) or len(token) == 0:
        return {"ok": False}
    segments = token.split(".")
    if len(segments) != 2 or any(len(s) == 0 for s in segments):
        return {"ok": False}
    try:
        payload = json.loads(b64url_decode(segments[0]).decode("utf-8"))
    except Exception:
        return {"ok": False}
    if not isinstance(payload, dict):
        return {"ok": False}
    if payload.get("v") != GRANT_VERSION:
        return {"ok": False}
    for k in GRANT_SIGNED_FIELDS:
        if not isinstance(payload.get(k), str):
            return {"ok": False}
    return {"ok": True, "payload": payload}


def grant_fields_from_intended(intended):
    if not isinstance(intended, dict):
        return None
    gf = intended.get("grant_fields")
    if isinstance(gf, dict):
        return gf
    grant = intended.get("grant")
    if isinstance(grant, str) and len(grant) > 0:
        parsed = parse_grant_token(grant)
        if not parsed.get("ok"):
            return {"unparseable": True}
        return parsed["payload"]
    return None


def nonce_of(obj):
    if not obj:
        return ""
    sn = obj.get("state_nonce") if isinstance(obj, dict) else None
    return str(sn) if isinstance(sn, str) and len(sn) > 0 else ""


def verify_execution_attestation(token, opts=None):
    opts = opts or {}
    if opts.get("ctx") and opts.get("registry") is None and isinstance(opts["ctx"], dict):
        opts = dict(opts)
        opts["registry"] = opts["ctx"].get("registry")
    parsed = parse_attest_token(token)
    if not parsed.get("ok"):
        if "payload" in parsed:
            return fail(parsed["status"], parsed["reason"], parsed["payload"])
        return fail(parsed["status"], parsed["reason"])
    payload = parsed["payload"]
    if field_has_delimiter(payload):
        return fail("ATTEST_INVALID_SIGNATURE", "delimiter_in_field", payload)

    resolved = resolve_executor_key(opts.get("registry"), payload.get("executor_kid"))
    if not resolved:
        return fail("ATTEST_UNKNOWN_KEY", "unknown_kid", payload)

    # KEY STATUS GATE -- RECEIPT_FORMAT 7.1 (normative); mirrors the JS sibling exactly.
    _st = (resolved or {}).get("status")
    if _st is not None and _st not in ("active", "retired", "revoked"):
        return fail("ATTEST_UNKNOWN_KEY", "unknown_key_status", payload)
    if _st == "revoked":
        _at = (resolved or {}).get("compromised_at")
        _b = _parse_iso_ms(_at) if isinstance(_at, str) and _at else None
        _i = _parse_iso_ms(payload.get("committed_at") or payload.get("declared_at") or payload.get("ts"))
        _decided = _b is not None and _i is not None and _i >= _b
        return fail("ATTEST_UNKNOWN_KEY", "revoked_key" if _decided else "revoked_key_undecidable", payload)


    try:
        sig = b64url_decode(parsed["sig"])
    except Exception:
        return fail("ATTEST_INVALID_SIGNATURE", "signature_error", payload)
    try:
        resolved["public_key"].verify(sig, signing_input(payload).encode("utf-8"))
    except InvalidSignature:
        return fail("ATTEST_INVALID_SIGNATURE", "signature_mismatch", payload)
    except Exception:
        return fail("ATTEST_INVALID_SIGNATURE", "signature_error", payload)

    now = opts["now"] if opts.get("now") is not None else (datetime.now(timezone.utc).timestamp() * 1000)
    committed_ms = _parse_iso_ms(payload.get("committed_at"))
    if committed_ms is None:
        return fail("ATTEST_MALFORMED", "bad_timestamp", payload)
    if is_issued_in_future(committed_ms, now, opts.get("intended")):
        return fail("ATTEST_MALFORMED", "committed_at_in_future", payload)

    retired_historical = False
    if resolved.get("status") == "retired":
        if not is_issue_time_within_key_window(payload.get("committed_at"), resolved):
            return fail("ATTEST_UNKNOWN_KEY", "retired_key_outside_window", payload)
        retired_historical = True

    intended = opts.get("intended") if isinstance(opts.get("intended"), dict) else None
    wants_cross = bool(
        intended and (intended.get("grant") or intended.get("grant_fields") or intended.get("receipt_digest"))
    )
    if wants_cross:
        gf = grant_fields_from_intended(intended)
        if gf and gf.get("unparseable"):
            return fail("ATTEST_UNBOUND", "grant_unparseable", payload)
        if gf:
            if str(gf.get("jti") or "") != payload.get("grant_jti"):
                return fail("ATTEST_UNBOUND", "grant_jti_mismatch", payload)
            if str(gf.get("scope_hash") or "") != payload.get("scope_hash"):
                return fail("ATTEST_UNBOUND", "scope_hash_mismatch", payload)
            if nonce_of(gf) != nonce_of(payload):
                return fail("ATTEST_UNBOUND", "state_nonce_mismatch", payload)
            if gf.get("receipt_digest") and gf.get("receipt_digest") != payload.get("receipt_digest"):
                return fail("ATTEST_UNBOUND", "receipt_digest_mismatch", payload)
        if intended.get("receipt_digest") not in (None, "") and str(intended.get("receipt_digest")) != payload.get(
            "receipt_digest"
        ):
            return fail("ATTEST_UNBOUND", "receipt_digest_mismatch", payload)

    if retired_historical:
        return ok_status("ATTEST_RETIRED_KEY_VALID_AT_ISSUE", payload)
    return ok_status("ATTEST_VALID", payload)


def load_registry_document(source):
    if source.lower().startswith(("http://", "https://")):
        req = urllib.request.Request(source, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
            text = resp.read().decode("utf-8")
    else:
        with open(source, "r", encoding="utf-8") as fh:
            text = fh.read()
    doc = json.loads(text)
    if not doc or not isinstance(doc.get("keys"), list):
        raise ValueError("no keys[] in registry " + source)
    return doc


def fail_usage(msg):
    sys.stderr.write(msg + "\n" + USAGE)
    sys.exit(2)


def parse_args(argv):
    opts = {"token": None, "keys_source": None, "grant": None, "receipt_digest": None, "help": False}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--keys":
            i += 1
            opts["keys_source"] = argv[i] if i < len(argv) else None
        elif a == "--grant":
            i += 1
            opts["grant"] = argv[i] if i < len(argv) else None
        elif a == "--receipt-digest":
            i += 1
            opts["receipt_digest"] = argv[i] if i < len(argv) else None
        elif a in ("-h", "--help"):
            opts["help"] = True
        elif a.startswith("--"):
            raise ValueError("unknown flag: " + a)
        elif opts["token"] is None:
            opts["token"] = a
        else:
            raise ValueError("unexpected argument: " + a)
        i += 1
    return opts


def main():
    try:
        opts = parse_args(sys.argv[1:])
    except ValueError as e:
        fail_usage(str(e))
    if opts["help"]:
        sys.stdout.write(USAGE)
        sys.exit(2)
    if not opts["token"] or not str(opts["token"]).strip():
        fail_usage("no attestation token provided")
    if not opts["keys_source"]:
        fail_usage("--keys is required (customer-held executor registry; no default fetch)")
    try:
        registry = load_registry_document(opts["keys_source"])
    except Exception as e:
        fail_usage("could not load executor registry: " + str(e))
    intended = {}
    if opts["grant"] is not None:
        intended["grant"] = opts["grant"]
    if opts["receipt_digest"] is not None:
        intended["receipt_digest"] = opts["receipt_digest"]
    result = verify_execution_attestation(
        opts["token"],
        {"registry": registry, **({"intended": intended} if intended else {})},
    )
    sys.stdout.write(json.dumps(result, separators=(",", ":"), ensure_ascii=False) + "\n")
    sys.exit(0 if result["valid"] else 1)


if __name__ == "__main__":
    main()
