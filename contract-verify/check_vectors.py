"""
check_vectors: run the published conformance vectors against verify_bundle.

Any implementation of the verify side can be checked against test-vectors.json.
This runner uses ours. Zero dependencies.

    python3 check_vectors.py
"""

import json
import os
import sys

from coderifts_verify import verify_bundle

VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test-vectors.json")


def run(path=VECTORS):
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    trusted_key = bytes.fromhex(doc["guard_public_key_hex"])
    expected_ref = doc["expected_ref"]

    failures = 0
    for c in doc["cases"]:
        res = verify_bundle(c["bundle"], c["contract"].encode("utf-8"),
                            trusted_key, expected_ref,
                            c["last_seen_version"], c["now"])
        exp = c["expect"]
        ok = (res.ok == exp["ok"])
        if exp["ok"]:
            if "verdict" in exp:
                ok = ok and res.verdict == exp["verdict"]
            if "action" in exp:
                ok = ok and res.action == exp["action"]
            if "new_last_seen" in exp:
                ok = ok and res.new_last_seen == exp["new_last_seen"]
        else:
            if "reason_contains" in exp:
                ok = ok and exp["reason_contains"] in res.reason
        status = "PASS" if ok else "FAIL"
        if not ok:
            failures += 1
        print("%-4s | %-20s | ok=%-5s verdict=%-16s action=%-5s %s"
              % (status, c["name"], res.ok,
                 res.verdict or "-", res.action or "-",
                 "" if res.ok else "(%s)" % res.reason))

    print("-" * 70)
    if failures:
        print("%d / %d vectors FAILED" % (failures, len(doc["cases"])))
        return 1
    print("all %d vectors pass" % len(doc["cases"]))
    return 0


if __name__ == "__main__":
    sys.exit(run())
