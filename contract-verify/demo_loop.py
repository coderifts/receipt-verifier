"""
Combined round-trip demo: fetch side + verify side, end to end, zero deps.

It serves a well-known endpoint from a local stdlib HTTP server, runs the
fetcher against it, hands the result to verify_bundle, and acts on the gate.
Then it shows a steady-state revalidation and a tampered-contract rejection.

Run:
    python3 demo_loop.py
"""

import json
import os
import tempfile
import threading
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

import _ed25519 as ed
from coderifts_verify import verify_bundle
from issuer import build_signed_bundle
from fetcher import fetch

REF = "refs/heads/main"
CONTRACT = '{"openapi":"3.0.0","paths":{"/orders":{"get":{"responses":{"200":{}}}}}}'
NOW = 1_000_000


def write_well_known(root, bundle, contract_text):
    d = os.path.join(root, ".well-known")
    if not os.path.isdir(d):
        os.makedirs(d)
    with open(os.path.join(d, "contract"), "w", encoding="utf-8") as f:
        json.dump({"bundle": bundle, "contract": contract_text}, f)


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def serve(root):
    handler = lambda *a, **k: QuietHandler(*a, directory=root, **k)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, "http://127.0.0.1:%d" % httpd.server_address[1]


def line(label, note):
    print("%-30s | %s" % (label, note))


def main():
    sk, pk = ed.keypair(b"\x07" * 32)  # guard key the agent trusts
    root = tempfile.mkdtemp(prefix="wellknown_")
    httpd, base = serve(root)
    print("Combined round trip: fetch side + verify side")
    print("serving %s%s" % (base, "/.well-known/contract"))
    print("-" * 78)

    try:
        # Cold start: publish a fresh PASS bundle, fetch it, verify, gate.
        bundle = build_signed_bundle(CONTRACT.encode(), "PASS", version=7,
                                     private_key=sk, public_key=pk,
                                     issued_at=NOW, ttl_seconds=300)
        write_well_known(root, bundle, CONTRACT)

        b, contract_bytes = fetch(base)
        line("GET /.well-known/contract", "bundle v%d, contract %d bytes" % (b["version"], len(contract_bytes)))
        res = verify_bundle(b, contract_bytes, pk, REF, last_seen_version=-1, now=NOW)
        line("verify_bundle", "ok=%s verdict=%s action=%s" % (res.ok, res.verdict, res.action))
        assert res.ok and res.action == "allow"
        last_seen = res.new_last_seen
        line("last_seen bump", "-1 -> %d" % last_seen)

        # Steady state: same endpoint, agent already at v7, revalidate.
        b, contract_bytes = fetch(base)
        res = verify_bundle(b, contract_bytes, pk, REF, last_seen_version=last_seen, now=NOW + 30)
        line("revalidate at v%d" % last_seen, "ok=%s action=%s" % (res.ok, res.action))
        assert res.ok and res.action == "allow"

        # Tamper: the served contract is altered, bundle still signs the old hash.
        write_well_known(root, bundle, CONTRACT + " tampered")
        b, contract_bytes = fetch(base)
        res = verify_bundle(b, contract_bytes, pk, REF, last_seen_version=last_seen, now=NOW)
        line("tampered contract served", "ok=%s reason=%s" % (res.ok, res.reason))
        assert not res.ok and "hash pin" in res.reason

        print("-" * 78)
        print("Round trip wired: one fetch, verify, gate. Zero deps, end to end.")
    finally:
        httpd.shutdown()


if __name__ == "__main__":
    main()
