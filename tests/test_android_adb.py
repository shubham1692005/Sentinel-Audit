import unittest
import sqlite3
from unittest.mock import patch

from security_audit import android_adb, db


class AndroidWirelessAdbTests(unittest.TestCase):
    def test_target_is_one_private_ipv4_endpoint(self):
        self.assertEqual(android_adb.validate_target("192.168.43.1:37099"), "192.168.43.1:37099")
        self.assertEqual(android_adb.validate_target("10.143.22.165:55671"), "10.143.22.165:55671")
        self.assertEqual(android_adb.validate_target("172.20.4.9:37099"), "172.20.4.9:37099")
        for value in ("8.8.8.8:5555", "192.168.1.1", "192.168.1.1:0", "192.168.1.1:65536", "192.168.1.1:+55", "10.0.0.1/24:5555"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                android_adb.validate_target(value)

    def test_only_exact_authorized_wireless_adb_device_is_accepted(self):
        with patch.object(android_adb, "_run", return_value="List of devices attached\n192.168.43.1:37099 device product:test model:Phone transport_id:1") as run:
            android_adb._verify_paired_wireless_device("adb.exe", "192.168.43.1:37099")
            run.assert_called_once_with("adb.exe", "devices", "-l", timeout=10)
        with patch.object(android_adb, "_run", return_value="List of devices attached\n192.168.43.1:37099 unauthorized"):
            with self.assertRaisesRegex(android_adb.AndroidAdbError, "not an authorized wireless phone"):
                android_adb._verify_paired_wireless_device("adb.exe", "192.168.43.1:37099")
        with patch.object(android_adb, "_run", return_value="List of devices attached\n192.168.43.2:5555 device"):
            with self.assertRaisesRegex(android_adb.AndroidAdbError, "not connected"):
                android_adb._verify_paired_wireless_device("adb.exe", "192.168.43.1:37099")

    def test_parser_returns_only_requested_third_party_package_versions(self):
        listing = "package:com.example.first\npackage:com.example.second\n"
        dump = "Package [com.example.first] (abc):\n  versionCode=17 minSdk=23 targetSdk=34\n  versionName=1.2.3\nPackage [com.android.system] (def):\n  versionCode=1\n  versionName=system\n"
        apps, truncated = android_adb._parse_apps(listing, dump)
        self.assertFalse(truncated)
        self.assertEqual([app["package_name"] for app in apps], ["com.example.first", "com.example.second"])
        self.assertEqual(apps[0]["version_name"], "1.2.3")
        self.assertNotIn("com.android.system", repr(apps))

    def test_database_migration_adds_adb_job_kind_and_keeps_payload_foreign_key(self):
        conn = sqlite3.connect(":memory:")
        conn.execute("PRAGMA foreign_keys=ON")
        for number, script in db.MIGRATIONS[:6]:
            if number in (2, 6):
                conn.execute("PRAGMA foreign_keys=OFF")
            conn.executescript(f"BEGIN IMMEDIATE;\n{script}\nPRAGMA user_version={number};\nCOMMIT;")
            if number in (2, 6):
                conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.executescript(f"BEGIN IMMEDIATE;\n{db.MIGRATION_7}\nPRAGMA user_version=7;\nCOMMIT;")
        conn.execute("PRAGMA foreign_keys=ON")
        job_schema = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='scan_jobs'").fetchone()[0]
        payload_refs = conn.execute("PRAGMA foreign_key_list(scan_job_inputs)").fetchall()
        self.assertIn("android_adb", job_schema)
        self.assertTrue(any(row[2] == "scan_jobs" for row in payload_refs))
        self.assertEqual(conn.execute("PRAGMA foreign_key_check").fetchall(), [])
        conn.close()


if __name__ == "__main__":
    unittest.main()
