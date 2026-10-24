import sys
import os
import unittest
import json
import tempfile
import shutil
from datetime import datetime, timezone, timedelta

src_dir = os.path.dirname(os.path.abspath(__file__))
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from whitelist_manager import (
    shielddns_manage_autoblock_whitelist,
    is_rfc1918,
    load_whitelist
)
from rate_limiter import (
    RateLimiterService,
    load_blocklist,
    parse_log_line
)

class TestShieldDNSRateLimiting(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.whitelist_path = os.path.join(self.test_dir, "whitelist.json")
        self.blocklist_path = os.path.join(self.test_dir, "blocklist.json")
        self.log_path = os.path.join(self.test_dir, "rate_limit.log")

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_parse_log_line_edge_cases(self):
        # Malformed / non-string timestamps
        self.assertIsNone(parse_log_line(json.dumps({"timestamp": 1728770000, "client_ip": "203.0.113.50"})))
        self.assertIsNone(parse_log_line(json.dumps({"timestamp": "invalid-ts", "client_ip": "203.0.113.50"})))
        # Invalid IP in JSON
        self.assertIsNone(parse_log_line(json.dumps({"timestamp": "2026-10-12T20:00:00Z", "client_ip": "999.999.999.999"})))
        self.assertIsNone(parse_log_line(json.dumps({"timestamp": "2026-10-12T20:00:00Z", "client_ip": 12345})))
        # Valid JSON line
        parsed = parse_log_line(json.dumps({"timestamp": "2026-10-12T20:00:00Z", "client_ip": "203.0.113.50"}))
        self.assertIsNotNone(parsed)
        dt, ip = parsed
        self.assertEqual(ip, "203.0.113.50")
        self.assertEqual(dt.year, 2026)

    def test_rate_limiting_and_blocking(self):
        service = RateLimiterService(
            hourly_threshold=5,
            whitelist_config_path=self.whitelist_path,
            blocklist_path=self.blocklist_path,
            rate_log_path=self.log_path
        )

        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()

        logs = []
        for _ in range(10):
            logs.append(json.dumps({"timestamp": now_iso, "client_ip": "203.0.113.50"}))

        for _ in range(10):
            logs.append(json.dumps({"timestamp": now_iso, "client_ip": "192.168.1.50"}))

        shielddns_manage_autoblock_whitelist("add", "203.0.113.99", self.whitelist_path)
        for _ in range(10):
            logs.append(json.dumps({"timestamp": now_iso, "client_ip": "203.0.113.99"}))

        for _ in range(3):
            logs.append(json.dumps({"timestamp": now_iso, "client_ip": "203.0.113.60"}))

        old_time = (now - timedelta(hours=2)).isoformat()
        for _ in range(10):
            logs.append(json.dumps({"timestamp": old_time, "client_ip": "203.0.113.70"}))

        result = service.process_logs(logs, window_hours=1.0, now=now)

        self.assertIn("203.0.113.50", result["newly_blocked"])
        self.assertIn("192.168.1.50", result["ignored_rfc1918"])
        self.assertIn("203.0.113.99", result["ignored_whitelisted"])
        self.assertNotIn("203.0.113.60", result["newly_blocked"])
        self.assertNotIn("203.0.113.70", result["newly_blocked"])

        blocked = load_blocklist(self.blocklist_path)
        self.assertIn("203.0.113.50", blocked)
        self.assertNotIn("192.168.1.50", blocked)

        self.assertTrue(os.path.exists(self.log_path))
        with open(self.log_path, "r", encoding="utf-8") as f:
            log_entries = [json.loads(line) for line in f if line.strip()]
        self.assertEqual(len(log_entries), 1)
        self.assertEqual(log_entries[0]["ip_address"], "203.0.113.50")
        self.assertEqual(log_entries[0]["action"], "blocked")
        self.assertIn("Exceeded hourly threshold", log_entries[0]["reason"])

if __name__ == "__main__":
    unittest.main()
