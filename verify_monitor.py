#!/usr/bin/env python3
"""CodeRifts cr.monitor.attest.v1 monitoring-attestation verifier.

Usage:
  python3 verify_monitor.py <token> --keys <file|url>
      [--decision-id <id>] [--receipt-digest sha256:...]

--keys is REQUIRED. Monitoring keys are CUSTOMER-HELD; this verifier never
fetches CodeRifts. Same registry shape as .well-known/coderifts-keys.json.

Byte-identical JSON output to verify-monitor.js. Exit codes: 0 valid
(MON_ATTEST_VALID | MON_ATTEST_RETIRED_KEY_VALID_AT_ISSUE), 1 otherwise,
2 usage error.

Retired-key rule is HISTORICAL (receipt class): retired kid + observed_at inside
[valid_from, retired_at) -> MON_ATTEST_RETIRED_KEY_VALID_AT_ISSUE. Contrast
grants: retired -> UNKNOWN_KEY, because a grant is live permission and this is a
statement about what was observed.

Honesty: a valid attestation proves a holder of the monitoring key asserts that a
decision's monitoring payload reached a sink with this delivery_status at this
time. It does NOT prove the sink acted on it, that a human read it, that the
decision is still current, or -- when delivery_status is `not_delivered` -- that
anything was delivered at all. MON-A-NOT-DELIVERED is VALID on purpose: a
signature over an honest "not delivered" is exactly as valid as over a delivery.
"""

import json
import sys

from cryptography.exceptions import InvalidSignature

from verify import b64url_decode
from verify_attest import (
    canonical_meta,
    is_issue_time_within_key_window,
    load_registry_document,
    resolve_executor_key,
    scalar,
)

ATTEST_VERSION = "cr.monitor.attest.v1"
SIGNING_PREFIX = "crmonattest.v1"
ENVELOPE_TAG = "cr.monitor.attest.v1"

DELIVERY_STATUSES = ("delivered_acked", "sent_unacked", "not_delivered")
SINK_KINDS = ("callback", "http")

REQUIRED_FIELDS = (
    "kid", "decision_id", "receipt_digest", "delivery_status", "sink_kind", "observed_at",
)
OPTIONAL_STRINGS = ("ack_digest",)
ALLOWED_KEYS = set(("v",) + REQUIRED_FIELDS + OPTIONAL_STRINGS + ("attempt_count", "meta"))

STATUSES = {
    "MON_ATTEST_VALID": "MON_ATTEST_VALID",
    "MON_ATTEST_INVALID_SIGNATURE": "MON_ATTEST_INVALID_SIGNATURE",
    "MON_ATTEST_UNKNOWN_KEY": "MON_ATTEST_UNKNOWN_KEY",
    "MON_ATTEST_RETIRED_KEY_VALID_AT_ISSUE": "MON_ATTEST_RETIRED_KEY_VALID_AT_ISSUE",
    "MON_ATTEST_MALFORMED": "MON_ATTEST_MALFORMED",
    "MON_ATTEST_UNBOUND": "MON_ATTEST_UNBOUND",
}

USAGE = (
    "usage: python3 verify_monitor.py <token> --keys <file|url> "
    "[--decision-id id] [--receipt-digest sha256:...]\n"
    "--keys is REQUIRED (customer-held monitoring registry). There is no default fetch.\n"
)

_MISSING = object()


def signing_input(body):
    """MIRRORED byte-for-byte from coderifts-app/src/verdict-core/monitoring-attestation.js:72."""
    ack = body.get("ack_digest")
    attempts = body.get("attempt_count")
    parts = [
        SIGNING_PREFIX,
        scalar(body.get("kid")),
        scalar(body.get("decision_id")),
        scalar(body.get("receipt_digest")),
        scalar(body.get("delivery_status")),
        str(ack) if ack is not None and len(str(ack)) > 0 else "",
        scalar(body.get("sink_kind")),
        scalar(body.get("observed_at")),
        str(attempts) if attempts is not None else "",
    ]
    meta = body.get("meta")
    if isinstance(meta, dict):
        parts.append(canonical_meta(meta))
    return "|".join(parts)


def fail(status, reason, payload=_MISSING):
    out = {"valid": False, "status": status}
    if reason:
        out["reason"] = reason
    if payload is not _MISSING:
        out["payload"] = payload
    return out


def field_has_delimiter(body):
    for k in REQUIRED_FIELDS + OPTIONAL_STRINGS:
        v = body.get(k)
        if isinstance(v, str) and "|" in v:
            return True
    return False


def parse_monitor_token(token):
    if not isinstance(token, str) or not token:
        return {"ok": False, "status": STATUSES["MON_ATTEST_MALFORMED"], "reason": "malformed_structure"}
    segments = token.split("|")
    if len(segments) != 4:
        return {"ok": False, "status": STATUSES["MON_ATTEST_MALFORMED"], "reason": "malformed_structure"}
    if segments[0] != ENVELOPE_TAG:
        return {"ok": False, "status": STATUSES["MON_ATTEST_MALFORMED"], "reason": "unsupported_version"}
    try:
        payload = json.loads(b64url_decode(segments[2]).decode("utf-8"))
    except Exception:
        return {"ok": False, "status": STATUSES["MON_ATTEST_MALFORMED"], "reason": "bad_json"}
    if not isinstance(payload, dict):
        return {"ok": False, "status": STATUSES["MON_ATTEST_MALFORMED"], "reason": "bad_json"}
    if payload.get("v") != ATTEST_VERSION:
        return {"ok": False, "status": STATUSES["MON_ATTEST_MALFORMED"], "reason": "unsupported_version", "payload": payload}
    for k in REQUIRED_FIELDS:
        v = payload.get(k)
        if not isinstance(v, str) or not v:
            return {"ok": False, "status": STATUSES["MON_ATTEST_MALFORMED"], "reason": "missing_field", "payload": payload}
    # An additive field is REFUSED, not ignored -- same rule as the other four envelopes.
    for k in payload:
        if k not in ALLOWED_KEYS:
            return {"ok": False, "status": STATUSES["MON_ATTEST_MALFORMED"], "reason": "unknown_field", "payload": payload}
    if payload.get("delivery_status") not in DELIVERY_STATUSES:
        return {"ok": False, "status": STATUSES["MON_ATTEST_MALFORMED"], "reason": "bad_delivery_status", "payload": payload}
    if payload.get("sink_kind") not in SINK_KINDS:
        return {"ok": False, "status": STATUSES["MON_ATTEST_MALFORMED"], "reason": "bad_sink_kind", "payload": payload}
    if segments[1] != payload.get("kid"):
        return {"ok": False, "status": STATUSES["MON_ATTEST_MALFORMED"], "reason": "kid_mismatch", "payload": payload}
    return {"ok": True, "payload": payload, "sig": segments[3]}


def verify_monitoring_attestation(token, opts=None):
    """(token, opts) -- two-ary, matching verify_execution_attestation.

    Python raises TypeError on an extra positional argument, so the 1128 guard the JS
    sibling needs is supplied by the language here.
    """
    o = opts or {}
    parsed = parse_monitor_token(token)
    if not parsed["ok"]:
        return fail(parsed["status"], parsed.get("reason"), parsed.get("payload", _MISSING))
    payload = parsed["payload"]

    if field_has_delimiter(payload):
        return fail(STATUSES["MON_ATTEST_INVALID_SIGNATURE"], "delimiter_in_field", payload)

    resolved = resolve_executor_key(o.get("registry"), payload.get("kid"))
    if not resolved:
        return fail(STATUSES["MON_ATTEST_UNKNOWN_KEY"], "unknown_kid", payload)

    try:
        resolved["public_key"].verify(
            b64url_decode(parsed["sig"]),
            signing_input(payload).encode("utf-8"),
        )
    except InvalidSignature:
        return fail(STATUSES["MON_ATTEST_INVALID_SIGNATURE"], "signature_mismatch", payload)
    except Exception:
        return fail(STATUSES["MON_ATTEST_INVALID_SIGNATURE"], "signature_error", payload)

    retired_historical = False
    if resolved.get("status") == "retired":
        if not is_issue_time_within_key_window(payload.get("observed_at"), resolved):
            return fail(STATUSES["MON_ATTEST_UNKNOWN_KEY"], "retired_key_outside_window", payload)
        retired_historical = True

    intended = o.get("intended")
    if isinstance(intended, dict):
        want_did = intended.get("decision_id")
        if want_did is not None and len(str(want_did)) > 0 and str(want_did) != payload.get("decision_id"):
            return fail(STATUSES["MON_ATTEST_UNBOUND"], "decision_id_mismatch", payload)
        want_rd = intended.get("receipt_digest")
        if want_rd is not None and len(str(want_rd)) > 0 and str(want_rd) != payload.get("receipt_digest"):
            return fail(STATUSES["MON_ATTEST_UNBOUND"], "receipt_digest_mismatch", payload)

    return {
        "valid": True,
        "status": STATUSES["MON_ATTEST_RETIRED_KEY_VALID_AT_ISSUE"] if retired_historical
        else STATUSES["MON_ATTEST_VALID"],
        "payload": payload,
    }


def fail_usage(msg):
    sys.stderr.write(msg + "\n" + USAGE)
    sys.exit(2)


def parse_args(argv):
    opts = {"token": None, "keys_source": None, "decision_id": None, "receipt_digest": None, "help": False}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--keys":
            i += 1
            opts["keys_source"] = argv[i] if i < len(argv) else None
        elif a == "--decision-id":
            i += 1
            opts["decision_id"] = argv[i] if i < len(argv) else None
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
        fail_usage("--keys is required (customer-held monitoring registry; no default fetch)")
    try:
        registry = load_registry_document(opts["keys_source"])
    except Exception as e:
        fail_usage("could not load monitoring registry: " + str(e))
    intended = {}
    if opts["decision_id"] is not None:
        intended["decision_id"] = opts["decision_id"]
    if opts["receipt_digest"] is not None:
        intended["receipt_digest"] = opts["receipt_digest"]
    result = verify_monitoring_attestation(
        opts["token"],
        {"registry": registry, **({"intended": intended} if intended else {})},
    )
    sys.stdout.write(json.dumps(result, separators=(",", ":"), ensure_ascii=False) + "\n")
    sys.exit(0 if result["valid"] else 1)


if __name__ == "__main__":
    main()
