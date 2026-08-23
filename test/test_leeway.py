"""ID104 clock-skew leeway — mirrors verify.js deriveStatus (stdlib unittest)."""
import os
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from verify import (  # noqa: E402
    CLOCK_SKEW_LEEWAY_MS,
    derive_status,
    expiry_leeway_ms,
    is_expired_at,
)


class TestClockSkewLeeway(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 8, 23, 12, 0, 0, tzinfo=timezone.utc).timestamp() * 1000
        self.entry = {"status": None, "retired_at": None}

    def _iso_ago(self, ms):
        return datetime.fromtimestamp((self.now - ms) / 1000, tz=timezone.utc).isoformat().replace("+00:00", "Z")

    def test_constant(self):
        self.assertEqual(CLOCK_SKEW_LEEWAY_MS, 30_000)
        self.assertEqual(expiry_leeway_ms(None), CLOCK_SKEW_LEEWAY_MS)

    def test_exp_10s_past_is_current(self):
        status = derive_status(
            {"v": 4, "expires_at": self._iso_ago(10_000)},
            self.entry,
            {"now": self.now},
        )
        self.assertEqual(status, "VERIFIED_CURRENT")
        self.assertFalse(is_expired_at(self.now - 10_000, self.now))

    def test_exp_40s_past_is_expired(self):
        status = derive_status(
            {"v": 4, "expires_at": self._iso_ago(40_000)},
            self.entry,
            {"now": self.now},
        )
        self.assertEqual(status, "VERIFIED_EXPIRED")
        self.assertTrue(is_expired_at(self.now - 40_000, self.now))

    def test_destructive_prod_not_guessed(self):
        status = derive_status(
            {"v": 4, "expires_at": self._iso_ago(1_000)},
            self.entry,
            {"now": self.now, "envelope": {"environment": "production", "operation": "deploy"}},
        )
        self.assertEqual(status, "VERIFIED_CURRENT")

    def test_non_destructive_1s_past_is_current(self):
        status = derive_status(
            {"v": 4, "expires_at": self._iso_ago(1_000)},
            self.entry,
            {"now": self.now, "envelope": {"environment": "staging", "operation": "merge"}},
        )
        self.assertEqual(status, "VERIFIED_CURRENT")


if __name__ == "__main__":
    unittest.main()
