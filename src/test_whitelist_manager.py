import sys
import os
import unittest
import json
import tempfile
import shutil
from unittest.mock import patch

src_dir = os.path.dirname(os.path.abspath(__file__))
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from whitelist_manager import (
    is_rfc1918,
    load_whitelist,
    save_whitelist,
    shielddns_manage_autoblock_whitelist
)

class TestWhitelistManager(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.whitelist_path = os.path.join(self.test_dir, "whitelist.json")

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_is_rfc1918(self):
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

        # Invalid inputs
        self.assertFalse(is_rfc1918("invalid_ip"))
        self.assertFalse(is_rfc1918(None))
        self.assertFalse(is_rfc1918(12345))

    def test_load_whitelist(self):
        # File doesn't exist
        self.assertEqual(load_whitelist(self.whitelist_path), [])

        # Valid list format
        with open(self.whitelist_path, "w", encoding="utf-8") as f:
            json.dump(["192.168.1.1", "10.0.0.1"], f)
        self.assertEqual(load_whitelist(self.whitelist_path), ["192.168.1.1", "10.0.0.1"])

        # Valid dict format
        with open(self.whitelist_path, "w", encoding="utf-8") as f:
            json.dump({"whitelist": ["172.16.0.1"]}, f)
        self.assertEqual(load_whitelist(self.whitelist_path), ["172.16.0.1"])

        # Invalid JSON
        with open(self.whitelist_path, "w", encoding="utf-8") as f:
            f.write("invalid json")
        self.assertEqual(load_whitelist(self.whitelist_path), [])

        # Unexpected structure
        with open(self.whitelist_path, "w", encoding="utf-8") as f:
            json.dump({"other_key": ["1.1.1.1"]}, f)
        self.assertEqual(load_whitelist(self.whitelist_path), [])

        # Mixed types
        with open(self.whitelist_path, "w", encoding="utf-8") as f:
            json.dump([123, "8.8.8.8", None], f)
        self.assertEqual(load_whitelist(self.whitelist_path), ["8.8.8.8"])

    def test_save_whitelist(self):
        # Save new list
        entries = ["192.168.1.1", "10.0.0.1"]
        save_whitelist(entries, self.whitelist_path)

        self.assertTrue(os.path.exists(self.whitelist_path))
        with open(self.whitelist_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data, {"whitelist": entries})

        # Exception during save should raise and not corrupt file (simulated by mocking)
        with patch('os.replace') as mock_replace:
            mock_replace.side_effect = Exception("Mock replace error")
            with self.assertRaises(Exception):
                save_whitelist(["8.8.8.8"], self.whitelist_path)

            # The original file should still contain the old data, because replace failed
            with open(self.whitelist_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data, {"whitelist": entries})

    def test_shielddns_manage_autoblock_whitelist(self):
        # Invalid operation
        with self.assertRaises(ValueError):
            shielddns_manage_autoblock_whitelist("update", "10.0.0.1", self.whitelist_path)

        # Invalid IP
        with self.assertRaises(ValueError):
            shielddns_manage_autoblock_whitelist("add", "invalid_ip", self.whitelist_path)

        # Add single IP
        res = shielddns_manage_autoblock_whitelist("add", "203.0.113.10", self.whitelist_path)
        self.assertTrue(res)
        self.assertIn("203.0.113.10", load_whitelist(self.whitelist_path))

        # Add CIDR range
        res_cidr = shielddns_manage_autoblock_whitelist("add", "198.51.100.0/24", self.whitelist_path)
        self.assertTrue(res_cidr)
        self.assertIn("198.51.100.0/24", load_whitelist(self.whitelist_path))

        # Add duplicate
        res_dup = shielddns_manage_autoblock_whitelist("add", "203.0.113.10", self.whitelist_path)
        self.assertTrue(res_dup)
        self.assertEqual(len(load_whitelist(self.whitelist_path)), 2)

        # Remove existing IP
        res_rm = shielddns_manage_autoblock_whitelist("remove", "203.0.113.10", self.whitelist_path)
        self.assertTrue(res_rm)
        self.assertNotIn("203.0.113.10", load_whitelist(self.whitelist_path))

        # Remove non-existent IP
        res_rm_none = shielddns_manage_autoblock_whitelist("remove", "1.2.3.4", self.whitelist_path)
        self.assertFalse(res_rm_none)

if __name__ == "__main__":
    unittest.main()
