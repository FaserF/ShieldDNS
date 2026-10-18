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
    parse_log_line,
    is_whitelisted
)

class TestShieldDNSRateLimiting(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.whitelist_path = os.path.join(self.test_dir, "whitelist.json")
        self.blocklist_path = os.path.join(self.test_dir, "blocklist.json")
        self.log_path = os.path.join(self.test_dir, "rate_limit.log")

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_rfc1918_detection(self):
        self.assertTrue(is_rfc1918("10.0.0.1"))
        self.assertTrue(is_rfc1918("10.254.0.15"))
        self.assertTrue(is_rfc1918("172.16.0.1"))
        self.assertTrue(is_rfc1918("172.31.255.255"))
        self.assertTrue(is_rfc1918("192.168.1.100"))
        self.assertTrue(is_rfc1918("192.168.0.0/16"))

        self.assertFalse(is_rfc1918("127.0.0.1"))
        self.assertFalse(is_rfc1918("8.8.8.8"))
        self.assertFalse(is_rfc1918("1.1.1.1"))
        self.assertFalse(is_rfc1918("172.32.0.1"))
        self.assertFalse(is_rfc1918("203.0.113.5"))

    def test_is_whitelisted_invalid_ip(self):
        whitelist = ["1.1.1.1", "192.168.1.0/24"]
        self.assertFalse(is_whitelisted("not-an-ip", whitelist))
        self.assertFalse(is_whitelisted("999.999.999.999", whitelist))
        self.assertFalse(is_whitelisted("", whitelist))

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

    def test_whitelist_management(self):
        res = shielddns_manage_autoblock_whitelist("add", "203.0.113.10", self.whitelist_path)
        self.assertTrue(res)
        self.assertIn("203.0.113.10", load_whitelist(self.whitelist_path))

        res_cidr = shielddns_manage_autoblock_whitelist("add", "198.51.100.0/24", self.whitelist_path)
        self.assertTrue(res_cidr)
        self.assertIn("198.51.100.0/24", load_whitelist(self.whitelist_path))

        res_dup = shielddns_manage_autoblock_whitelist("add", "203.0.113.10", self.whitelist_path)
        self.assertTrue(res_dup)
        self.assertEqual(len(load_whitelist(self.whitelist_path)), 2)

        res_rm = shielddns_manage_autoblock_whitelist("remove", "203.0.113.10", self.whitelist_path)
        self.assertTrue(res_rm)
        self.assertNotIn("203.0.113.10", load_whitelist(self.whitelist_path))

        res_rm_none = shielddns_manage_autoblock_whitelist("remove", "1.2.3.4", self.whitelist_path)
        self.assertFalse(res_rm_none)

        with self.assertRaises(ValueError) as context:
            shielddns_manage_autoblock_whitelist("update", "203.0.113.10", self.whitelist_path)
        self.assertIn("Invalid operation", str(context.exception))

        with self.assertRaises(ValueError) as context:
            shielddns_manage_autoblock_whitelist("add", "invalid-ip", self.whitelist_path)
        self.assertIn("Invalid IP address", str(context.exception))

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

    def test_process_log_file(self):
        service = RateLimiterService(
            hourly_threshold=5,
            whitelist_config_path=self.whitelist_path,
            blocklist_path=self.blocklist_path,
            rate_log_path=self.log_path
        )

        now = datetime.now(timezone.utc)

        # Test with missing file
        missing_file_path = os.path.join(self.test_dir, "non_existent.log")
        result_missing = service.process_log_file(missing_file_path, window_hours=1.0, now=now)
        self.assertEqual(result_missing["processed_counts"], {})
        self.assertEqual(result_missing["newly_blocked"], [])
        self.assertEqual(result_missing["ignored_rfc1918"], [])
        self.assertEqual(result_missing["ignored_whitelisted"], [])

        # Test with existing file
        log_file_path = os.path.join(self.test_dir, "test_input.log")
        now_iso = now.isoformat()
        logs = []
        for _ in range(10):
            logs.append(json.dumps({"timestamp": now_iso, "client_ip": "203.0.113.50"}))

        with open(log_file_path, "w", encoding="utf-8") as f:
            for log in logs:
                f.write(log + "\n")

        result_existing = service.process_log_file(log_file_path, window_hours=1.0, now=now)
        self.assertIn("203.0.113.50", result_existing["newly_blocked"])
        self.assertEqual(result_existing["processed_counts"]["203.0.113.50"], 10)

if __name__ == "__main__":
    unittest.main()
