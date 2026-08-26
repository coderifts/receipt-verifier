#!/usr/bin/env python3
"""CodeRifts cr.toolset.attest.v1 tool-set declaration verifier ("Represented") --
Python 3.10+, depends only on `cryptography`. Sibling of verify.py / verify_attest.py /
verify_grant.py.

Usage:
  python3 verify_toolset.py <token> --keys <file|url> [--entries <file>] [--declarer <name>]

--keys is REQUIRED. Declaration keys are CUSTOMER-HELD; this verifier never fetches
CodeRifts. The registry is the same JSON shape as .well-known/coderifts-keys.json.

Output: JSON { valid, status, reason, payload } to stdout -- byte-identical to
verify-toolset.js. Exit codes: 0 valid (TOOLSET_ATTEST_VALID |
TOOLSET_ATTEST_RETIRED_KEY_VALID_AT_ISSUE), 1 otherwise, 2 usage error.

Retired-key rule is the ATTESTATION rule, not the grant rule: a declaration authorises
nothing, so a key valid at declared_at still proves the declarer made the statement
(TOOLSET_ATTEST_RETIRED_KEY_VALID_AT_ISSUE). Window is half-open [valid_from, retired_at).
Contrast cr.exec.v1 grants: retired -> UNKNOWN_KEY, because a grant is live permission.

Honesty: a valid declaration proves a holder of the declarer's key stated, at declared_at,
that the set with this digest is the complete set of tools that can mutate a governed
target. It does NOT prove the statement is true -- nothing here inspects a running process,
and a tool absent from the declaration is absent from this artifact too. Sampling
(@coderifts/bypass-probe) is the tested half; this is the accountable half.
"""

import hashlib
import json
import sys
import urllib.request
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

ATTEST_VERSION = "cr.toolset.attest.v1"
SIGNING_PREFIX = "crtoolsetattest.v1"
ENVELOPE_TAG = "cr.toolset.attest.v1"
CLOCK_SKEW_LEEWAY_MS = 30000
MAX_ENTRIES = 512

STATEMENTS = ("this is the complete set of tools that can mutate a governed target",)
MUTATION_CLASSES = ("mutating", "readonly")

REQUIRED_FIELDS = ("kid", "declarer", "statement", "set_digest", "declared_at")
OPTIONAL_STRINGS = (
    "session_id", "receipt_digest", "scope_note",
    "framework", "framework_version", "guard_version",
)
ALLOWED_KEYS = set(("v",) + REQUIRED_FIELDS + OPTIONAL_STRINGS
                   + ("tool_count", "mutating_count", "meta"))

TOOLSET_ATTEST_VALID = "TOOLSET_ATTEST_VALID"
TOOLSET_ATTEST_INVALID_SIGNATURE = "TOOLSET_ATTEST_INVALID_SIGNATURE"
TOOLSET_ATTEST_UNKNOWN_KEY = "TOOLSET_ATTEST_UNKNOWN_KEY"
TOOLSET_ATTEST_RETIRED_KEY_VALID_AT_ISSUE = "TOOLSET_ATTEST_RETIRED_KEY_VALID_AT_ISSUE"
TOOLSET_ATTEST_MALFORMED = "TOOLSET_ATTEST_MALFORMED"
TOOLSET_ATTEST_UNBOUND = "TOOLSET_ATTEST_UNBOUND"

USAGE = ("usage: python3 verify_toolset.py <token> --keys <file|url> "
         "[--entries <file>] [--declarer <name>]\n")


def _scalar(v):
    return "" if v is None else str(v)


def _optional(v):
    return str(v) if v is not None and len(str(v)) > 0 else ""


def _sha256hex(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _b64url_decode(s):
    pad = "=" * (-len(s) % 4)
    import base64
    return base64.urlsafe_b64decode(s + pad)


def _canonical_meta(meta):
    return json.dumps({k: meta[k] for k in sorted(meta)},
                      separators=(",", ":"), ensure_ascii=False)


def _meta_ok(meta):
    if meta is None:
        return True
    if not isinstance(meta, dict):
        return False
    if len(meta) > 8:
        return False
    for k, v in meta.items():
        if not isinstance(k, str) or len(k) == 0 or len(k) > 64 or "|" in k:
            return False
        if isinstance(v, bool) or isinstance(v, (int, float)):
            continue
        if isinstance(v, str):
            if len(v) > 256 or "|" in v:
                return False
            continue
        return False
    return True


def _signing_input(body):
    parts = [
        SIGNING_PREFIX,
        _scalar(body.get("kid")), _scalar(body.get("declarer")), _scalar(body.get("statement")),
        _scalar(body.get("set_digest")), _scalar(body.get("declared_at")),
        _optional(body.get("session_id")), _optional(body.get("receipt_digest")),
        _optional(body.get("framework")), _optional(body.get("framework_version")),
        _optional(body.get("guard_version")),
        "" if body.get("tool_count") is None else str(body["tool_count"]),
        "" if body.get("mutating_count") is None else str(body["mutating_count"]),
        _optional(body.get("scope_note")),
    ]
    meta = body.get("meta")
    if isinstance(meta, dict):
        parts.append(_canonical_meta(meta))
    return "|".join(parts)


def _field_has_delimiter(body):
    for k in REQUIRED_FIELDS + OPTIONAL_STRINGS:
        v = body.get(k)
        if isinstance(v, str) and "|" in v:
            return True
    return False


def compute_set_digest(entries):
    if not isinstance(entries, list):
        return {"ok": False, "reason": "entries_not_array"}
    if len(entries) == 0:
        return {"ok": False, "reason": "entries_empty"}
    if len(entries) > MAX_ENTRIES:
        return {"ok": False, "reason": "entries_too_many"}
    seen = set()
    rows = []
    for e in entries:
        if not isinstance(e, dict):
            return {"ok": False, "reason": "entry_not_object"}
        name = e.get("name")
        cls = e.get("mutation_class")
        sd = e.get("input_schema_digest")
        if not isinstance(name, str) or not name or len(name) > 128:
            return {"ok": False, "reason": "bad_entry_name"}
        if "|" in name:
            return {"ok": False, "reason": "delimiter_in_entry_name"}
        if cls not in MUTATION_CLASSES:
            return {"ok": False, "reason": "bad_mutation_class"}
        if sd is not None:
            if not isinstance(sd, str) or not sd.startswith("sha256:") or "|" in sd:
                return {"ok": False, "reason": "bad_input_schema_digest"}
        if name in seen:
            return {"ok": False, "reason": "duplicate_entry_name"}
        seen.add(name)
        rows.append([name, cls, "" if sd is None else sd])
    rows.sort(key=lambda r: r[0])
    canonical = "".join(" ".join(r) for r in rows)
    return {
        "ok": True,
        "digest": "sha256:" + _sha256hex(canonical),
        "tool_count": len(rows),
        "mutating_count": sum(1 for r in rows if r[1] == "mutating"),
    }


def _parse_ms(ts):
    if not isinstance(ts, str) or not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() * 1000.0
    except Exception:
        return None


def _is_issue_time_within_key_window(ts, key_meta):
    """Half-open [valid_from, retired_at): equal to retired_at is OUTSIDE."""
    if not key_meta or key_meta.get("status") == "active":
        return True
    if key_meta.get("status") != "retired":
        return False
    retired_at = key_meta.get("retired_at")
    if not isinstance(retired_at, str) or not retired_at:
        return False
    issue_ms = _parse_ms(ts)
    if issue_ms is None:
        return False
    vf = key_meta.get("valid_from")
    if vf:
        from_ms = _parse_ms(vf)
        if from_ms is not None and issue_ms < from_ms:
            return False
    retired_ms = _parse_ms(retired_at)
    if retired_ms is None:
        return False
    if issue_ms >= retired_ms:
        return False
    return True


def _resolve_declarer_key(registry, kid):
    if not isinstance(registry, dict) or not isinstance(registry.get("keys"), list):
        return None
    if not isinstance(kid, str) or not kid:
        return None
    matches = [k for k in registry["keys"]
               if isinstance(k, dict) and k.get("kid") == kid
               and isinstance(k.get("public_key_pem"), str)]
    if not matches:
        return None
    entry = next((k for k in matches if k.get("status") == "active"), matches[0])
    try:
        pub = load_pem_public_key(entry["public_key_pem"].encode("utf-8"))
    except Exception:
        return None
    if not isinstance(pub, Ed25519PublicKey):
        return None
    return {
        "publicKey": pub,
        # PASS THE REAL STATUS THROUGH -- normalising non-retired to "active" LAUNDERED a
        # revoked key into a healthy one before any gate could see it (mirrors verify-attest.js).
        "status": entry.get("status") or "active",
        "compromised_at": entry.get("compromised_at"),
        "valid_from": entry.get("valid_from") or None,
        "retired_at": entry.get("retired_at") or None,
    }


def _fail(status, reason, payload=None):
    return {"valid": False, "status": status, "reason": reason, "payload": payload}


def _ok(status, payload):
    return {"valid": True, "status": status, "reason": None, "payload": payload}


def _parse_attest_token(token):
    if not isinstance(token, str) or not token:
        return {"ok": False, "status": TOOLSET_ATTEST_MALFORMED, "reason": "malformed_structure"}
    segments = token.split("|")
    if len(segments) != 4 or any(not s for s in segments):
        return {"ok": False, "status": TOOLSET_ATTEST_MALFORMED, "reason": "malformed_structure"}
    if segments[0] != ENVELOPE_TAG:
        return {"ok": False, "status": TOOLSET_ATTEST_MALFORMED, "reason": "unsupported_version"}
    try:
        payload = json.loads(_b64url_decode(segments[2]).decode("utf-8"))
    except Exception:
        return {"ok": False, "status": TOOLSET_ATTEST_MALFORMED, "reason": "bad_json"}
    if not isinstance(payload, dict):
        return {"ok": False, "status": TOOLSET_ATTEST_MALFORMED, "reason": "bad_json"}
    if payload.get("v") != ATTEST_VERSION:
        return {"ok": False, "status": TOOLSET_ATTEST_MALFORMED,
                "reason": "unsupported_version", "payload": payload}
    for k in REQUIRED_FIELDS:
        v = payload.get(k)
        if not isinstance(v, str) or len(v) == 0:
            return {"ok": False, "status": TOOLSET_ATTEST_MALFORMED,
                    "reason": "missing_field", "payload": payload}
    if payload["statement"] not in STATEMENTS:
        return {"ok": False, "status": TOOLSET_ATTEST_MALFORMED,
                "reason": "bad_statement", "payload": payload}
    if not payload["set_digest"].startswith("sha256:"):
        return {"ok": False, "status": TOOLSET_ATTEST_MALFORMED,
                "reason": "bad_set_digest", "payload": payload}
    for k in OPTIONAL_STRINGS:
        v = payload.get(k)
        if v is not None and not isinstance(v, str):
            return {"ok": False, "status": TOOLSET_ATTEST_MALFORMED,
                    "reason": "bad_optional", "payload": payload}
    has_fw = payload.get("framework") not in (None, "")
    has_fwv = payload.get("framework_version") not in (None, "")
    if has_fw != has_fwv:
        return {"ok": False, "status": TOOLSET_ATTEST_MALFORMED,
                "reason": "framework_version_unpaired", "payload": payload}
    for k in ("tool_count", "mutating_count"):
        v = payload.get(k)
        if v is not None and (isinstance(v, bool) or not isinstance(v, int) or v < 0):
            return {"ok": False, "status": TOOLSET_ATTEST_MALFORMED,
                    "reason": "bad_" + k, "payload": payload}
    tc = payload.get("tool_count")
    mc = payload.get("mutating_count")
    if isinstance(tc, int) and not isinstance(tc, bool) \
            and isinstance(mc, int) and not isinstance(mc, bool) and mc > tc:
        return {"ok": False, "status": TOOLSET_ATTEST_MALFORMED,
                "reason": "mutating_exceeds_total", "payload": payload}
    rd = payload.get("receipt_digest")
    if rd is not None and rd != "" and not rd.startswith("sha256:"):
        return {"ok": False, "status": TOOLSET_ATTEST_MALFORMED,
                "reason": "bad_receipt_digest", "payload": payload}
    if payload["kid"] != segments[1]:
        return {"ok": False, "status": TOOLSET_ATTEST_MALFORMED,
                "reason": "kid_mismatch", "payload": payload}
    for k in payload:
        if k not in ALLOWED_KEYS:
            return {"ok": False, "status": TOOLSET_ATTEST_MALFORMED,
                    "reason": "unknown_field", "payload": payload}
    if not _meta_ok(payload.get("meta")):
        return {"ok": False, "status": TOOLSET_ATTEST_MALFORMED,
                "reason": "meta_bounds", "payload": payload}
    if _field_has_delimiter(payload):
        return {"ok": False, "status": TOOLSET_ATTEST_MALFORMED,
                "reason": "delimiter_in_field", "payload": payload}
    return {"ok": True, "payload": payload, "sig": segments[3]}


def verify_toolset_attestation(token, registry=None, entries=None, intended=None, now_ms=None):
    parsed = _parse_attest_token(token)
    if not parsed["ok"]:
        return _fail(parsed["status"], parsed["reason"], parsed.get("payload"))
    payload = parsed["payload"]

    resolved = _resolve_declarer_key(registry, payload["kid"])
    if not resolved:
        return _fail(TOOLSET_ATTEST_UNKNOWN_KEY, "kid_not_in_registry", payload)

    # KEY STATUS GATE -- RECEIPT_FORMAT 7.1 (normative); mirrors the JS sibling exactly.
    _st = (resolved or {}).get("status")
    if _st is not None and _st not in ("active", "retired", "revoked"):
        return _fail(TOOLSET_ATTEST_UNKNOWN_KEY, "unknown_key_status", payload)
    if _st == "revoked":
        _at = (resolved or {}).get("compromised_at")
        _b = _parse_ms(_at) if isinstance(_at, str) and _at else None
        _i = _parse_ms(payload.get("committed_at") or payload.get("declared_at") or payload.get("ts"))
        _decided = _b is not None and _i is not None and _i >= _b
        return _fail(TOOLSET_ATTEST_UNKNOWN_KEY, "revoked_key" if _decided else "revoked_key_undecidable", payload)


    try:
        resolved["publicKey"].verify(_b64url_decode(parsed["sig"]),
                                     _signing_input(payload).encode("utf-8"))
    except InvalidSignature:
        return _fail(TOOLSET_ATTEST_INVALID_SIGNATURE, "signature_mismatch", payload)
    except Exception:
        return _fail(TOOLSET_ATTEST_INVALID_SIGNATURE, "signature_error", payload)

    now = now_ms if now_ms is not None else datetime.now(timezone.utc).timestamp() * 1000.0
    decl = _parse_ms(payload["declared_at"])
    if decl is not None and decl > now + CLOCK_SKEW_LEEWAY_MS:
        return _fail(TOOLSET_ATTEST_MALFORMED, "declared_at_in_future", payload)

    if entries is not None:
        recomputed = compute_set_digest(entries)
        if not recomputed["ok"]:
            return _fail(TOOLSET_ATTEST_MALFORMED, "entries_" + recomputed["reason"], payload)
        if recomputed["digest"] != payload["set_digest"]:
            return _fail(TOOLSET_ATTEST_UNBOUND, "set_digest_mismatch", payload)
        tc = payload.get("tool_count")
        if isinstance(tc, int) and not isinstance(tc, bool) and tc != recomputed["tool_count"]:
            return _fail(TOOLSET_ATTEST_UNBOUND, "tool_count_mismatch", payload)
        mc = payload.get("mutating_count")
        if isinstance(mc, int) and not isinstance(mc, bool) and mc != recomputed["mutating_count"]:
            return _fail(TOOLSET_ATTEST_UNBOUND, "mutating_count_mismatch", payload)

    if intended:
        for k in ("session_id", "receipt_digest", "declarer"):
            want = intended.get(k)
            if want is not None:
                got = payload.get(k)
                if str(want) != str("" if got is None else got):
                    return _fail(TOOLSET_ATTEST_UNBOUND, k + "_mismatch", payload)

    if resolved["status"] == "retired":
        if not _is_issue_time_within_key_window(payload["declared_at"], resolved):
            return _fail(TOOLSET_ATTEST_UNKNOWN_KEY, "retired_key_outside_window", payload)
        return _ok(TOOLSET_ATTEST_RETIRED_KEY_VALID_AT_ISSUE, payload)
    return _ok(TOOLSET_ATTEST_VALID, payload)


def _load_keys(ref):
    if ref.startswith("http://") or ref.startswith("https://"):
        with urllib.request.urlopen(ref, timeout=10) as r:
            return json.loads(r.read().decode("utf-8"))
    with open(ref, "r", encoding="utf-8") as f:
        return json.load(f)


def main():
    args = sys.argv[1:]
    if not args or args[0].startswith("-"):
        sys.stderr.write(USAGE)
        sys.exit(2)
    token = args[0]
    keys_ref = None
    entries_ref = None
    declarer = None
    i = 1
    while i < len(args):
        if args[i] == "--keys":
            keys_ref = args[i + 1] if i + 1 < len(args) else None
            i += 2
            continue
        if args[i] == "--entries":
            entries_ref = args[i + 1] if i + 1 < len(args) else None
            i += 2
            continue
        if args[i] == "--declarer":
            declarer = args[i + 1] if i + 1 < len(args) else None
            i += 2
            continue
        sys.stderr.write(USAGE)
        sys.exit(2)
    if not keys_ref:
        sys.stderr.write(
            "--keys is required: this verifier NEVER fetches a default key registry.\n")
        sys.exit(2)
    try:
        registry = _load_keys(keys_ref)
        entries = None
        if entries_ref:
            with open(entries_ref, "r", encoding="utf-8") as f:
                entries = json.load(f)
    except Exception as err:
        sys.stderr.write(str(err) + "\n")
        sys.exit(2)
    intended = {"declarer": declarer} if declarer else None
    result = verify_toolset_attestation(token, registry=registry, entries=entries,
                                        intended=intended)
    sys.stdout.write(json.dumps(result, separators=(",", ":"), ensure_ascii=False) + "\n")
    sys.exit(0 if result["valid"] else 1)


if __name__ == "__main__":
    main()
