import http.client
import json
import os
import shutil
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from security_audit import android_device, reports
from security_audit.api import Handler, create_admin
from security_audit.db import connect


def sample_payload(**changes):
    payload = {
        "schema_version": 1,
        "consent_confirmed": True,
        "collected_at": "2026-10-08T12:00:00.000Z",
        "device": {"manufacturer": "Example", "model": "Phone 1", "android_version": "16", "sdk_int": 36, "security_patch": "2026-09-01"},
        "checks": {
            "device_info": {"status": "checked", "detail": "Read by Android public APIs."},
            "security_patch": {"status": "checked", "value": "2026-09-01"},
            "secure_screen_lock": {"status": "checked", "value": True},
            "adb_debugging": {"status": "checked", "value": False},
            "developer_options": {"status": "checked", "value": False},
            "visible_app_inventory": {"status": "checked", "value": 1, "detail": "Launcher-visible apps only."},
            "play_protect": {"status": "unavailable", "detail": "Android does not expose a public verdict API."},
            "storage_encryption": {"status": "unavailable", "detail": "Not collected."},
        },
        "apps": [{"name": "Example App", "package_name": "com.example.app", "version_name": "1.0", "version_code": 1}],
    }
    payload.update(changes)
    return payload


class AndroidDeviceAuditUnitTests(unittest.TestCase):
    def test_consent_and_payload_validation(self):
        payload = sample_payload()
        payload["consent_confirmed"] = False
        with self.assertRaisesRegex(ValueError, "consent"):
            android_device.validate_payload(payload)
        with self.assertRaisesRegex(ValueError, "package name"):
            android_device.validate_payload(sample_payload(apps=[{"package_name": "bad package"}]))
        with self.assertRaisesRegex(ValueError, "visible apps"):
            android_device.validate_payload(sample_payload(apps=[{"package_name": "com.example.app"}] * 501))

    def test_unavailable_checks_are_reported_and_version_alone_is_not_a_cve(self):
        payload = sample_payload(apps=[{"package_name": "com.example.legacy", "version_name": "1.0", "version_code": 1}], checks={
            "secure_screen_lock": {"status": "unavailable", "detail": "Permission was not available."},
            "play_protect": {"status": "unavailable", "detail": "No public verdict API."},
            "visible_app_inventory": {"status": "not_checked", "detail": "User skipped inventory."},
        })
        result = android_device.build_assessment(payload)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["facts"]["collection_coverage"]["secure_screen_lock"]["status"], "unavailable")
        self.assertTrue(any("play protect" in warning.lower() for warning in result["warnings"]))
        self.assertTrue(any("not checked" in warning.lower() for warning in result["warnings"]))
        self.assertFalse(any(item.get("cve") for item in result["findings"]))

    def test_lock_and_old_patch_findings_remain_conservative(self):
        payload = sample_payload()
        payload["device"]["security_patch"] = "2024-01-01"
        payload["checks"]["secure_screen_lock"] = {"status": "checked", "value": False}
        result = android_device.build_assessment(payload)
        self.assertEqual({item["severity"] for item in result["findings"]}, {"low", "info"})
        self.assertFalse(any(item.get("cve") for item in result["findings"]))
        self.assertIn("does not confirm an unpatched vulnerability", next(item["description"] for item in result["findings"] if "patch date" in item["title"]))

    def test_app_inventory_is_encrypted_at_rest_and_restored_for_reports(self):
        secret = "android-audit-test-secret-with-enough-length"
        result = android_device.build_assessment(sample_payload())
        protected = android_device.protect_inventory(result, secret)
        encoded = json.dumps(protected)
        self.assertNotIn("com.example.app", encoded)
        self.assertIn("apps_encrypted", protected["facts"])
        restored = android_device.restore_inventory(protected, secret)
        self.assertEqual(restored["facts"]["apps"][0]["package_name"], "com.example.app")


class AndroidDeviceAuditApiTests(unittest.TestCase):
    def test_authenticated_consent_job_persistence_and_reports(self):
        work = Path(__file__).resolve().parent.parent / "work" / "android-device-test"
        shutil.rmtree(work, ignore_errors=True)
        work.mkdir(parents=True, exist_ok=True)
        db_path = work / "android.db"
        secret = "android-audit-api-test-secret-2026-long-enough"
        old_db = os.environ.get("AUDIT_DB")
        old_proxy = os.environ.get("TRUST_PROXY_HEADERS")
        with patch.dict(os.environ, {"AUDIT_DB": str(db_path), "AUDIT_SECRET": secret, "TRUST_PROXY_HEADERS": "1"}), \
             patch("security_audit.api.SECRET_CONFIGURED", True), patch("security_audit.api.SECRET", secret):
            db = connect()
            create_admin(db, "android-audit@example.test", "long-android-audit-password-123")
            db.close()
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                def request(path, method="GET", data=None, cookies="", csrf="", secure=True):
                    conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=15)
                    headers = {}
                    if cookies:
                        headers["Cookie"] = cookies
                    if method != "GET":
                        headers.update({"Content-Type": "application/json", "X-CSRF-Token": csrf})
                    if secure:
                        headers["X-Forwarded-Proto"] = "https"
                    conn.request(method, path, json.dumps(data) if data is not None else None, headers)
                    response = conn.getresponse()
                    result = (response.status, response.getheaders(), response.read())
                    conn.close()
                    return result

                status, headers, _ = request("/api/auth/login", "POST", {"email": "android-audit@example.test", "password": "long-android-audit-password-123"}, secure=False)
                self.assertEqual(status, 200)
                cookies = "; ".join(value.split(";", 1)[0] for key, value in headers if key.lower() == "set-cookie")
                csrf = next(value.split(";", 1)[0].split("=", 1)[1] for key, value in headers if key.lower() == "set-cookie" and value.startswith("audit_csrf="))
                status, _, projects = request("/api/projects", cookies=cookies)
                self.assertEqual(status, 200)
                project_id = json.loads(projects)["projects"][0]["id"]

                missing_consent = {"project_id": project_id, "kind": "android_device", "device_audit": sample_payload()}
                status, _, _ = request("/api/scan-jobs", "POST", missing_consent, cookies, csrf)
                self.assertEqual(status, 400)
                no_tls = {**missing_consent, "consent_confirmed": True}
                status, _, _ = request("/api/scan-jobs", "POST", no_tls, cookies, csrf, secure=False)
                self.assertEqual(status, 400)

                adb_without_consent = {"project_id": project_id, "kind": "android_adb", "target": "192.168.43.1:37099"}
                status, _, _ = request("/api/scan-jobs", "POST", adb_without_consent, cookies, csrf)
                self.assertEqual(status, 400)
                adb_public_target = {**adb_without_consent, "consent_confirmed": True, "target": "8.8.8.8:5555"}
                status, _, _ = request("/api/scan-jobs", "POST", adb_public_target, cookies, csrf)
                self.assertEqual(status, 400)
                adb_private_target = {**adb_without_consent, "consent_confirmed": True}
                adb_evidence = android_device.build_assessment(sample_payload())
                adb_evidence["scope_details"]["engine"] = "adb_wireless"
                adb_evidence["facts"]["inventory_scope"] = "adb_third_party_packages"
                adb_evidence["facts"]["collection_method"] = "authorized_wireless_adb"
                with patch("security_audit.api.android_adb.collect", return_value=adb_evidence):
                    status, _, response = request("/api/scan-jobs", "POST", adb_private_target, cookies, csrf)
                    self.assertEqual(status, 202)
                    adb_job_id = json.loads(response)["job_id"]
                    deadline = time.monotonic() + 15
                    while time.monotonic() < deadline:
                        status, _, response = request("/api/scan-jobs/" + adb_job_id, cookies=cookies)
                        self.assertEqual(status, 200)
                        adb_job = json.loads(response)["job"]
                        if adb_job["status"] in ("completed", "failed", "cancelled"):
                            break
                        time.sleep(0.03)
                self.assertEqual(adb_job["status"], "completed", adb_job.get("error"))
                self.assertEqual(adb_job["kind"], "android_adb")
                self.assertEqual(adb_job["target"], "192.168.43.1:37099")
                adb_assessment_id = adb_job["result"]["assessment_id"]
                db = connect()
                adb_stored = db.execute("SELECT kind,summary FROM assessments WHERE id=?", (adb_assessment_id,)).fetchone()
                self.assertEqual(adb_stored["kind"], "android_device")
                self.assertNotIn("com.example.app", adb_stored["summary"])
                self.assertIn("apps_encrypted", adb_stored["summary"])
                db.close()
                status, _, response = request(f"/api/reports/json?project_id={project_id}&type=technical&assessment_id={adb_assessment_id}", cookies=cookies)
                self.assertEqual(status, 200)
                adb_report = json.loads(response)
                self.assertEqual(adb_report["scope_authorization"][0]["method"], "adb_wireless")
                self.assertEqual(adb_report["scope_authorization"][0]["android_device"]["inventory_scope"], "adb_third_party_packages")
                status, _, response = request(f"/api/reports/html?project_id={project_id}&type=technical&assessment_id={adb_assessment_id}", cookies=cookies)
                self.assertEqual(status, 200)
                self.assertIn(b"Checks (source: authorized Android Debug Bridge)", response)
                self.assertIn(b"Third-party app inventory collected by ADB", response)
                status, _, response = request(f"/api/reports/pdf?project_id={project_id}&type=technical&assessment_id={adb_assessment_id}", cookies=cookies)
                self.assertEqual(status, 200)
                self.assertTrue(response.startswith(b"%PDF-1.4"))
                self.assertIn(b"authorized Android Debug Bridge", response)

                body = {**no_tls, "device_audit": sample_payload()}
                status, _, response = request("/api/scan-jobs", "POST", body, cookies, csrf)
                self.assertEqual(status, 202)
                job_id = json.loads(response)["job_id"]
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    status, _, response = request("/api/scan-jobs/" + job_id, cookies=cookies)
                    self.assertEqual(status, 200)
                    job = json.loads(response)["job"]
                    if job["status"] in ("completed", "failed", "cancelled"):
                        break
                    time.sleep(0.03)
                self.assertEqual(job["status"], "completed", job.get("error"))
                self.assertEqual(job["kind"], "android_device")
                self.assertNotIn("com.example.app", json.dumps(job["result"]))

                db = connect()
                saved_input = db.execute("SELECT count(*) FROM scan_job_inputs WHERE job_id=?", (job_id,)).fetchone()[0]
                stored = db.execute("SELECT id,kind,summary FROM assessments ORDER BY id DESC LIMIT 1").fetchone()
                self.assertEqual(saved_input, 0)
                self.assertEqual(stored["kind"], "android_device")
                self.assertNotIn("com.example.app", stored["summary"])
                self.assertIn("apps_encrypted", stored["summary"])
                android_assessment_id = stored["id"]
                other_summary = {"scope": "OTHER_ASSESSMENT_PRIVATE_MARKER", "facts": {"platform": "test desktop"}}
                other_assessment_id = db.execute("INSERT INTO assessments(project_id,kind,summary) VALUES(?,'local',?)", (project_id, json.dumps(other_summary))).lastrowid
                db.execute("INSERT INTO findings(project_id,assessment_id,title,category,severity,likelihood,impact,risk_score,description,evidence) VALUES(?,?,?,'configuration','low',2,2,0.8,?,'{}')", (project_id, other_assessment_id, "OTHER_ASSESSMENT_FINDING_MARKER", "Must not appear in the Android assessment report"))
                db.commit()
                db.close()

                status, _, response = request(f"/api/assessments?project_id={project_id}", cookies=cookies)
                self.assertEqual(status, 200)
                history = next(item["summary"] for item in json.loads(response)["assessments"] if item["id"] == android_assessment_id)
                self.assertEqual(history["facts"]["apps"][0]["package_name"], "com.example.app")

                status, _, response = request(f"/api/reports/json?project_id={project_id}&type=technical", cookies=cookies)
                self.assertEqual(status, 200)
                report = json.loads(response)
                mobile = next(item["android_device"] for item in report["scope_authorization"] if item["kind"] == "android_device")
                self.assertEqual(mobile["apps"][0]["package_name"], "com.example.app")
                self.assertTrue(any("launcher-visible apps" in warning for warning in report["assessment_limitations"]))
                status, headers, response = request(f"/api/reports/json?project_id={project_id}&type=technical&assessment_id={android_assessment_id}", cookies=cookies)
                self.assertEqual(status, 200)
                android_report = json.loads(response)
                self.assertEqual(android_report["assessment_id"], android_assessment_id)
                self.assertEqual([item["id"] for item in android_report["assessments"]], [android_assessment_id])
                self.assertEqual(len(android_report["scope_authorization"]), 1)
                self.assertEqual(android_report["scope_authorization"][0]["kind"], "android_device")
                self.assertIn("com.example.app", json.dumps(android_report))
                self.assertIsNone(android_report["compliance"]["assessment"]["percentage"])
                self.assertEqual(android_report["compliance"]["assessment"]["determination"], "Not assessed")
                self.assertTrue(any(control["control_key"] == "ID.AM-02" for control in android_report["compliance"]["assessment"]["controls"]))
                self.assertTrue(any(evidence.get("check") == "security_patch" for control in android_report["compliance"]["assessment"]["controls"] for evidence in control["evidence"]))
                self.assertNotIn("OTHER_ASSESSMENT_PRIVATE_MARKER", json.dumps(android_report))
                self.assertNotIn("OTHER_ASSESSMENT_FINDING_MARKER", json.dumps(android_report))
                status, pdf_headers, pdf_report = request(f"/api/reports/pdf?project_id={project_id}&type=technical&assessment_id={android_assessment_id}", cookies=cookies)
                self.assertEqual(status, 200)
                self.assertTrue(pdf_report.startswith(b"%PDF-1.4"))
                self.assertIn(f"security-technical-assessment-{android_assessment_id}.pdf", dict(pdf_headers)["Content-Disposition"])
                self.assertIn(b"com.example.app", pdf_report)
                self.assertIn(b"ANDROID DEVICE AUDIT", pdf_report)
                self.assertIn(b"ASSESSMENT-LINKED COMPLIANCE EVIDENCE", pdf_report)
                self.assertIn(b"NIST CSF 2.0 ID.AM-02", pdf_report)
                self.assertNotIn(b"OTHER_ASSESSMENT_PRIVATE_MARKER", pdf_report)
                self.assertNotIn(b"OTHER_ASSESSMENT_FINDING_MARKER", pdf_report)
                status, _, response = request(f"/api/reports/json?project_id={project_id}&type=technical&assessment_id={other_assessment_id}", cookies=cookies)
                self.assertEqual(status, 200)
                other_report = json.loads(response)
                self.assertEqual([item["id"] for item in other_report["assessments"]], [other_assessment_id])
                self.assertIn("OTHER_ASSESSMENT_FINDING_MARKER", json.dumps(other_report))
                self.assertNotIn("com.example.app", json.dumps(other_report))
                status, _, response = request(f"/api/reports/json?project_id={project_id}&type=executive", cookies=cookies)
                self.assertEqual(status, 200)
                executive = json.loads(response)
                self.assertNotIn("com.example.app", json.dumps(executive))
                html_report = reports.html_bytes(report).decode("utf-8")
                self.assertIn("Android device audit", html_report)
                self.assertIn("Checks (source: Android public APIs)", html_report)
                self.assertIn("Secure Screen Lock", html_report)
                self.assertIn("com.example.app", html_report)
                pdf_report = reports.pdf_bytes(report)
                self.assertIn(b"ANDROID DEVICE AUDIT", pdf_report)
                self.assertIn(b"Android public APIs", pdf_report)
                self.assertIn(b"com.example.app", pdf_report)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
        if old_db is None:
            os.environ.pop("AUDIT_DB", None)
        else:
            os.environ["AUDIT_DB"] = old_db
        if old_proxy is None:
            os.environ.pop("TRUST_PROXY_HEADERS", None)
        else:
            os.environ["TRUST_PROXY_HEADERS"] = old_proxy
        shutil.rmtree(work, ignore_errors=True)
