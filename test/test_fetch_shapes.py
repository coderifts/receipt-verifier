#!/usr/bin/env python3
"""ID131 gap 5: default fetch accepts BOTH registry and legacy single-key bodies."""
import http.server
import json
import subprocess
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import verify  # noqa: E402

assert verify.DEFAULT_FETCH_URL == "https://app.coderifts.com/.well-known/coderifts-keys.json"

VECTORS = json.loads((Path(__file__).parent / "vectors.json").read_text())


class _Handler(http.server.BaseHTTPRequestHandler):
    body = b"{}"

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, fmt, *args):
        return


def serve(payload):
    _Handler.body = json.dumps(payload).encode("utf-8")
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    host, port = httpd.server_address
    return httpd, f"http://{host}:{port}/"


def main():
    # 1. Registry shape
    httpd, url = serve(VECTORS["retired"]["registry"])
    try:
        info = verify.fetch_key_document(url)
        assert "keyring" in info, "registry shape exposes keyring"
        assert info["kid"] == "test-k1"
        assert "test-retired-k0" in info["keyring"]
        assert info["keyring"]["test-retired-k0"]["status"] == "retired"
    finally:
        httpd.shutdown()

    # 2. Legacy single-key
    live = VECTORS["live"]
    httpd, url = serve({"kid": live["kid"], "alg": "Ed25519", "public_key_pem": live["public_key_pem"]})
    try:
        info = verify.fetch_key_document(url)
        assert "keyring" not in info, "legacy shape has no keyring"
        assert info["kid"] == live["kid"]
        token = live["vectors"][0]["token"]
        result = verify.verify_receipt(token, {"public_key": info["public_key"], "expected_kid": info["kid"]})
        assert result["valid"] is True
    finally:
        httpd.shutdown()

    # 3. Retired kid via default-fetch → RETIRED_KEY_VALID_AT_ISSUE
    httpd, url = serve(VECTORS["retired"]["registry"])
    try:
        info = verify.fetch_key_document(url)
        result = verify.verify_receipt(
            VECTORS["retired"]["token_valid_at_issue"],
            {"keyring": info["keyring"], "expected_kid": None},
        )
        assert result["status"] == "RETIRED_KEY_VALID_AT_ISSUE", result
        assert result["valid"] is True
        assert result.get("reason") != "unknown_kid"
        cli = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parent.parent / "verify.py"),
             VECTORS["retired"]["token_valid_at_issue"], "--fetch", url],
            capture_output=True, text=True, timeout=15,
        )
        assert cli.returncode == 0, cli.stderr
        parsed = json.loads(cli.stdout)
        assert parsed["status"] == "RETIRED_KEY_VALID_AT_ISSUE"
        assert parsed.get("reason") != "unknown_kid"
    finally:
        httpd.shutdown()

    print("test_fetch_shapes.py: OK (registry + legacy + retired-via-default-fetch)")


if __name__ == "__main__":
    main()
