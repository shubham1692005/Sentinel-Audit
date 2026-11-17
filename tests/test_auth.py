"""End-to-end coverage for the authentication and account-security API."""
import http.client
import base64
import hashlib
import importlib.util
import json
import os
import re
import sqlite3
import shutil
import threading
import time
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch

from http.server import ThreadingHTTPServer

from security_audit import auth as authlib
from security_audit import api
from security_audit.api import Handler, create_admin
from security_audit.db import MIGRATIONS, connect


class AuthenticationPrimitiveTests(unittest.TestCase):
    def test_totp_matches_rfc_6238_and_signing_secret_rejects_placeholders(self):
        secret = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
        self.assertEqual(authlib.totp(secret, 59), "287082")
        self.assertTrue(api.valid_signing_secret("a" * 32))
        self.assertFalse(api.valid_signing_secret("short"))
        self.assertFalse(api.valid_signing_secret("replace-with-a-long-random-secret"))
        legacy = api.pw_hash("legacy-password-123", b"legacy-salt-1234")
        self.assertTrue(authlib.password_verify("legacy-password-123", legacy))
        self.assertTrue(authlib.password_needs_upgrade(legacy))

    @unittest.skipUnless(importlib.util.find_spec("cryptography"), "cryptography is an installed application dependency")
    def test_mfa_secret_is_encrypted_and_bound_to_signing_secret(self):
        encrypted = authlib.encrypt_secret("private-totp-seed", "stable-secret-for-tests")
        self.assertNotIn("private-totp-seed", encrypted)
        self.assertEqual(authlib.decrypt_secret(encrypted, "stable-secret-for-tests"), "private-totp-seed")
        with self.assertRaises(Exception):
            authlib.decrypt_secret(encrypted, "different-signing-secret")

    def test_schema_upgrade_preserves_existing_accounts_and_projects(self):
        path = Path(__file__).resolve().parent.parent / "work" / "auth-migration-test.db"
        path.parent.mkdir(parents=True, exist_ok=True)
        for suffix in ("", "-wal", "-shm"):
            Path(str(path) + suffix).unlink(missing_ok=True)
        legacy = sqlite3.connect(path)
        for version, script in MIGRATIONS[:3]:
            if version == 2:
                legacy.execute("PRAGMA foreign_keys=OFF")
            legacy.executescript(script)
            legacy.execute(f"PRAGMA user_version={version}")
            if version == 2:
                legacy.execute("PRAGMA foreign_keys=ON")
            legacy.commit()
        legacy.execute("INSERT INTO users(email,password_hash,role) VALUES('legacy@example.test','old-password-hash','admin')")
        legacy.execute("INSERT INTO organizations(name) VALUES('Legacy Org')")
        legacy.execute("INSERT INTO projects(organization_id,name) VALUES(1,'Legacy Project')")
        legacy.commit()
        legacy.close()
        upgraded = connect(str(path))
        account = upgraded.execute("SELECT email,password_hash,role,is_email_verified,email_verification_skipped,mfa_enabled FROM users").fetchone()
        self.assertEqual((account["email"], account["password_hash"], account["role"]), ("legacy@example.test", "old-password-hash", "admin"))
        self.assertEqual((account["is_email_verified"], account["email_verification_skipped"], account["mfa_enabled"]), (1, 0, 0))
        self.assertEqual(upgraded.execute("SELECT name FROM projects").fetchone()["name"], "Legacy Project")
        self.assertEqual(upgraded.execute("PRAGMA user_version").fetchone()[0], 9)
        upgraded.close()
        for suffix in ("", "-wal", "-shm"):
            Path(str(path) + suffix).unlink(missing_ok=True)


class AuthenticationWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = Path(__file__).resolve().parent.parent / "work" / "auth-test"
        shutil.rmtree(cls.temp, ignore_errors=True)
        cls.temp.mkdir(parents=True, exist_ok=True)
        cls.old_db = os.environ.get("AUDIT_DB")
        cls.old_secret = os.environ.get("AUDIT_SECRET")
        os.environ["AUDIT_DB"] = str(cls.temp / "auth.db")
        os.environ["AUDIT_SECRET"] = "test-only-stable-auth-signing-secret"
        cls.old_secret_value, cls.old_secret_configured = api.SECRET, api.SECRET_CONFIGURED
        api.SECRET = os.environ["AUDIT_SECRET"]
        api.SECRET_CONFIGURED = True
        db = connect()
        create_admin(db, "admin@example.test", "long-admin-password-123", "Audit Admin", "audit-admin")
        db.close()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        api.SECRET, api.SECRET_CONFIGURED = cls.old_secret_value, cls.old_secret_configured
        if cls.old_db is None:
            os.environ.pop("AUDIT_DB", None)
        else:
            os.environ["AUDIT_DB"] = cls.old_db
        if cls.old_secret is None:
            os.environ.pop("AUDIT_SECRET", None)
        else:
            os.environ["AUDIT_SECRET"] = cls.old_secret
        shutil.rmtree(cls.temp, ignore_errors=True)

    def request(self, path, method="GET", data=None, cookies="", csrf=""):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {}
        if cookies:
            headers["Cookie"] = cookies
        if method != "GET":
            headers.update({"Content-Type": "application/json", "X-CSRF-Token": csrf})
        conn.request(method, path, json.dumps(data) if data is not None else None, headers)
        response = conn.getresponse()
        result = (response.status, response.getheaders(), response.read())
        conn.close()
        return result

    def clear_registration_throttle(self):
        db = connect()
        key = hashlib.sha256(b"127.0.0.1|register").hexdigest()
        db.execute("DELETE FROM auth_rate_limits WHERE key_hash=?", (key,))
        db.commit()
        db.close()

    def registration_org_id(self):
        status, _, body = self.request("/api/auth/registration-organizations")
        self.assertEqual(status, 200)
        return json.loads(body)["organizations"][0]["id"]

    def approve_registration(self, email, organization_id):
        status, headers, _ = self.request("/api/auth/login", "POST", {"email":"admin@example.test","password":"long-admin-password-123"})
        self.assertEqual(status, 200)
        cookies, csrf = self.cookie_and_csrf(headers)
        status, _, body = self.request(f"/api/membership-requests?organization_id={organization_id}", cookies=cookies)
        self.assertEqual(status, 200)
        item = next(request for request in json.loads(body)["requests"] if request["email"] == email)
        status, _, body = self.request(f"/api/membership-requests/{item['id']}/decision", "POST", {"decision":"approve"}, cookies, csrf)
        self.assertEqual(status, 200, body.decode())

    @staticmethod
    def cookie_and_csrf(headers):
        cookies = "; ".join(value.split(";", 1)[0] for key, value in headers if key.lower() == "set-cookie")
        csrf = next(value.split(";", 1)[0].split("=", 1)[1] for key, value in headers if key.lower() == "set-cookie" and value.startswith("audit_csrf="))
        return cookies, csrf

    def test_email_password_registration_login_and_password_reset(self):
        self.clear_registration_throttle()
        sent = []
        org_id = self.registration_org_id()
        status, _, body = self.request("/api/auth/register", "POST", {
            "email": "audit-user@example.test", "password": "initial-audit-password-123", "confirm_password": "initial-audit-password-123", "organization_id": org_id,
        })
        self.assertEqual(status, 201)
        self.assertIn("approve", json.loads(body)["message"].lower())
        db = connect()
        account = db.execute("SELECT id FROM users WHERE email=?", ("audit-user@example.test",)).fetchone()
        self.assertIsNone(account, "signup must remain pending until an organization administrator approves it")
        db.close()
        status, _, _ = self.request("/api/auth/login", "POST", {"email": "audit-user@example.test", "password": "initial-audit-password-123"})
        self.assertEqual(status, 401)
        self.approve_registration("audit-user@example.test", org_id)
        status, headers, _ = self.request("/api/auth/login", "POST", {"email": "audit-user@example.test", "password": "initial-audit-password-123"})
        self.assertEqual(status, 200)
        cookies, csrf = self.cookie_and_csrf(headers)
        status, _, body = self.request("/api/auth/me", cookies=cookies)
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["user"]["is_email_verified"])
        self.assertTrue(json.loads(body)["user"]["email_verification_skipped"])
        status, _, _ = self.request("/api/auth/change-password", "POST", {
            "current_password": "initial-audit-password-123", "new_password": "mismatched-password-123", "confirm_password": "different-password-456",
        }, cookies, csrf)
        self.assertEqual(status, 400)
        status, _, _ = self.request("/api/auth/change-password", "POST", {
            "current_password": "initial-audit-password-123", "new_password": "12345", "confirm_password": "12345",
        }, cookies, csrf)
        self.assertEqual(status, 400)
        status, _, _ = self.request("/api/auth/change-password", "POST", {
            "current_password": "incorrect-current-password", "new_password": "updated-audit-password-456",
            "confirm_password": "updated-audit-password-456",
        }, cookies, csrf)
        self.assertEqual(status, 401)
        status, _, _ = self.request("/api/auth/change-password", "POST", {
            "current_password": "initial-audit-password-123", "new_password": "updated-audit-password-456",
            "confirm_password": "updated-audit-password-456",
        }, cookies, csrf)
        self.assertEqual(status, 200)
        status, _, _ = self.request("/api/auth/login", "POST", {"email": "audit-user@example.test", "password": "initial-audit-password-123"})
        self.assertEqual(status, 401)
        status, _, _ = self.request("/api/auth/login", "POST", {"email": "audit-user@example.test", "password": "updated-audit-password-456"})
        self.assertEqual(status, 200)
        with patch.object(authlib, "smtp_configured", return_value=True), \
             patch.object(authlib, "send_email", side_effect=lambda *args: sent.append(args)):
            status, _, _ = self.request("/api/auth/forgot-password", "POST", {"email": "audit-user@example.test"})
        self.assertEqual(status, 200)
        # The reset email has a distinct label and is never exposed by the API response.
        reset_token = re.search(r"password reset code is: ([A-Za-z0-9_-]+)", sent[-1][2]).group(1)
        db = connect()
        db.execute("UPDATE auth_tokens SET expires_at=? WHERE token_hash=?", (int(time.time()) - 1, authlib.token_hash(reset_token)))
        db.commit()
        db.close()
        status, _, _ = self.request("/api/auth/reset-password", "POST", {"token": reset_token, "password": "reset-audit-password-789", "confirm_password": "reset-audit-password-789"})
        self.assertEqual(status, 400)
        with patch.object(authlib, "smtp_configured", return_value=True), \
             patch.object(authlib, "send_email", side_effect=lambda *args: sent.append(args)):
            status, _, _ = self.request("/api/auth/forgot-password", "POST", {"email": "audit-user@example.test"})
        self.assertEqual(status, 200)
        reset_token = re.search(r"password reset code is: ([A-Za-z0-9_-]+)", sent[-1][2]).group(1)
        status, _, _ = self.request("/api/auth/reset-password", "POST", {"token": reset_token, "password": "reset-audit-password-789", "confirm_password": "reset-audit-password-789"})
        self.assertEqual(status, 200)
        status, _, _ = self.request("/api/auth/reset-password", "POST", {"token": reset_token, "password": "reset-audit-password-789", "confirm_password": "reset-audit-password-789"})
        self.assertEqual(status, 400)
        status, _, _ = self.request("/api/auth/me", cookies=cookies)
        self.assertEqual(status, 401)
        status, _, _ = self.request("/api/auth/login", "POST", {"email": "audit-user@example.test", "password": "reset-audit-password-789"})
        self.assertEqual(status, 200)

    def test_registration_works_without_captcha_or_smtp_and_recovery_explains_smtp_requirement(self):
        self.clear_registration_throttle()
        with patch.object(authlib, "captcha_configured", return_value=False), patch.object(authlib, "smtp_configured", return_value=False):
            status, _, body = self.request("/api/auth/register", "POST", {"email": "setup@example.test", "password": "initial-audit-password-123", "confirm_password": "initial-audit-password-123", "organization_id": self.registration_org_id()})
            self.assertEqual(status, 201)
            self.assertIn("approve", json.loads(body)["message"].lower())
            status, _, body = self.request("/api/auth/forgot-password", "POST", {"email": "setup@example.test"})
            self.assertEqual(status, 503)
            self.assertIn("SMTP_HOST", json.loads(body)["error"])
        self.clear_registration_throttle()
        db = connect()
        key = hashlib.sha256(b"127.0.0.1|resend-verification").hexdigest()
        db.execute("DELETE FROM auth_rate_limits WHERE key_hash=?", (key,))
        db.commit()
        db.close()

    def test_registration_password_and_email_validation(self):
        self.clear_registration_throttle()
        valid = {"email": "validation@example.test", "password": "initial-audit-password-123", "confirm_password": "initial-audit-password-123", "organization_id": self.registration_org_id()}
        variants = [
            ({**valid, "email": "not-an-email"}, 400),
            ({**valid, "password": "abcde", "confirm_password": "abcde"}, 400),
            ({**valid, "confirm_password": "different"}, 400),
            ({**valid, "email": "admin@example.test"}, 409),
        ]
        for data, expected in variants:
            status, _, _ = self.request("/api/auth/register", "POST", data)
            self.assertEqual(status, expected)
        status, _, body = self.request("/api/auth/register", "POST", valid)
        self.assertEqual(status, 201)
        self.assertIn("approve", json.loads(body)["message"].lower())
        status, _, _ = self.request("/api/auth/login", "POST", {"email": valid["email"], "password": valid["password"]})
        self.assertEqual(status, 401)
        self.approve_registration(valid["email"], valid["organization_id"])
        status, _, _ = self.request("/api/auth/login", "POST", {"email": valid["email"], "password": valid["password"]})
        self.assertEqual(status, 200)
        self.clear_registration_throttle()

    def test_resend_verification_and_expired_tokens(self):
        db = connect()
        user_id = db.execute("INSERT INTO users(email,password_hash,role,is_email_verified) VALUES('resend@example.test',?,'user',0)", (api.pw_hash("long-resend-password-123"),)).lastrowid
        expired_token = authlib.token()
        db.execute("INSERT INTO auth_tokens(user_id,kind,token_hash,expires_at) VALUES(?,'email_verify',?,?)", (user_id, authlib.token_hash(expired_token), int(time.time()) - 10))
        db.commit()
        db.close()
        status, _, _ = self.request("/api/auth/verify-email", "POST", {"token": expired_token})
        self.assertEqual(status, 400)
        sent = []
        with patch.object(authlib, "captcha_configured", return_value=True), \
             patch.object(authlib, "verify_captcha", return_value=True), \
             patch.object(authlib, "smtp_configured", return_value=True), \
             patch.object(authlib, "send_email", side_effect=lambda *args: sent.append(args)):
            status, _, body = self.request("/api/auth/resend-verification", "POST", {"email": "resend@example.test", "captcha_token": "test-token"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["message"], "If the address needs verification, a message will be sent.")
        self.assertEqual(len(sent), 1)
        token = re.search(r"verification code is: ([A-Za-z0-9_-]+)", sent[0][2]).group(1)
        status, _, _ = self.request("/api/auth/verify-email", "POST", {"token": token})
        self.assertEqual(status, 200)
        status, _, _ = self.request("/api/auth/verify-email", "POST", {"token": token})
        self.assertEqual(status, 400)
        db = connect()
        db.execute("INSERT INTO users(email,password_hash,role,is_email_verified) VALUES('smtp-fails@example.test',?,'user',0)", (api.pw_hash("long-smtp-failure-password-123"),))
        db.commit()
        db.close()
        with patch.object(authlib, "captcha_configured", return_value=True), \
             patch.object(authlib, "verify_captcha", return_value=True), \
             patch.object(authlib, "smtp_configured", return_value=True), \
             patch.object(authlib, "send_email", side_effect=RuntimeError("private SMTP detail")):
            status, _, body = self.request("/api/auth/resend-verification", "POST", {"email": "smtp-fails@example.test", "captcha_token": "test-token"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["message"], "If the address needs verification, a message will be sent.")

    def test_session_revoke_expiration_and_logout(self):
        credentials = {"email": "audit-user@example.test", "password": "reset-audit-password-789"}
        status, headers, _ = self.request("/api/auth/login", "POST", credentials)
        self.assertEqual(status, 200)
        old_cookies, _ = self.cookie_and_csrf(headers)
        status, headers, _ = self.request("/api/auth/login", "POST", credentials)
        self.assertEqual(status, 200)
        current_cookies, current_csrf = self.cookie_and_csrf(headers)
        status, _, body = self.request("/api/auth/sessions/revoke-others", "POST", {}, current_cookies, current_csrf)
        self.assertEqual(status, 200)
        self.assertGreaterEqual(json.loads(body)["revoked"], 1)
        status, _, _ = self.request("/api/auth/me", cookies=old_cookies)
        self.assertEqual(status, 401)
        status, _, body = self.request("/api/auth/sessions", cookies=current_cookies)
        self.assertEqual(status, 200)
        session_id = next(session["id"] for session in json.loads(body)["sessions"] if session["current"])
        db = connect()
        db.execute("UPDATE auth_sessions SET expires_at=? WHERE id=?", (int(time.time()) - 1, session_id))
        db.commit()
        db.close()
        status, _, _ = self.request("/api/auth/me", cookies=current_cookies)
        self.assertEqual(status, 401)
        status, headers, _ = self.request("/api/auth/login", "POST", credentials)
        self.assertEqual(status, 200)
        logout_cookies, logout_csrf = self.cookie_and_csrf(headers)
        status, _, _ = self.request("/api/auth/logout", "POST", {}, logout_cookies, logout_csrf)
        self.assertEqual(status, 200)
        status, _, _ = self.request("/api/auth/me", cookies=logout_cookies)
        self.assertEqual(status, 401)

    def test_login_attempts_are_rate_limited_without_account_enumeration(self):
        db = connect()
        db.execute("INSERT INTO users(email,password_hash,role,is_email_verified) VALUES('rate-limited@example.test',?,'user',1)", (api.pw_hash("long-rate-limit-password-123"),))
        db.commit()
        db.close()
        statuses = []
        for _ in range(6):
            status, _, body = self.request("/api/auth/login", "POST", {"email": "rate-limited@example.test", "password": "incorrect-password"})
            statuses.append(status)
            if status == 401:
                self.assertEqual(json.loads(body)["error"], "Email or password is incorrect")
        self.assertEqual(statuses, [401, 401, 401, 401, 401, 429])
        status, _, body = self.request("/api/auth/login", "POST", {"email": "does-not-exist@example.test", "password": "incorrect-password"})
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)["error"], "Email or password is incorrect")
        db = connect()
        db.execute("INSERT INTO users(email,password_hash,role,is_email_verified) VALUES('captcha-login@example.test',?,'user',1)", (api.pw_hash("long-captcha-login-password-123"),))
        db.commit()
        db.close()
        credentials = {"email": "captcha-login@example.test", "password": "incorrect-password"}
        for _ in range(3):
            status, _, _ = self.request("/api/auth/login", "POST", credentials)
            self.assertEqual(status, 401)
        with patch.object(authlib, "captcha_configured", return_value=True), patch.object(authlib, "verify_captcha", return_value=False):
            status, _, _ = self.request("/api/auth/login", "POST", {**credentials, "captcha_token": "bad-token"})
        self.assertEqual(status, 400)
        with patch.object(authlib, "captcha_configured", return_value=True), patch.object(authlib, "verify_captcha", return_value=True):
            status, _, _ = self.request("/api/auth/login", "POST", {"email": "captcha-login@example.test", "password": "long-captcha-login-password-123", "captcha_token": "good-token"})
        self.assertEqual(status, 200)

    def test_same_origin_mobile_frontend_assets_and_private_api_access(self):
        status, _, body = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn(b"auth-enhancements.js", body)
        status, _, body = self.request("/auth-enhancements.js")
        self.assertEqual(status, 200)
        self.assertIn(b"securitySettingsView", body)
        self.assertIn(b"Minimum 6 characters.", body)
        self.assertIn(b'minlength="6"', body)
        self.assertIn(b'values.password !== values.confirm_password', body)
        status, _, body = self.request("/config.js")
        self.assertEqual(status, 200)
        self.assertNotIn(b"test-only-stable-auth-signing-secret", body)
        self.assertIn(b"AUDIT_ACCOUNT_CAPTCHA_READY", body)
        self.assertIn(b"AUDIT_ACCOUNT_EMAIL_READY", body)
        status, _, _ = self.request("/api/admin/users")
        self.assertEqual(status, 401)

    def test_mfa_enrollment_challenge_and_one_time_recovery_code(self):
        db = connect()
        user_id = db.execute("SELECT id FROM users WHERE email='admin@example.test'").fetchone()[0]
        db.execute("UPDATE users SET mfa_enabled=0,mfa_secret='' WHERE id=?", (user_id,))
        db.commit()
        db.close()
        status, headers, _ = self.request("/api/auth/login", "POST", {"email": "admin@example.test", "password": "long-admin-password-123"})
        self.assertEqual(status, 200)
        cookies, csrf = self.cookie_and_csrf(headers)
        mock_encrypt = lambda value, secret: "encrypted:" + value
        mock_decrypt = lambda value, secret: value.removeprefix("encrypted:")
        encrypt_patch = nullcontext() if importlib.util.find_spec("cryptography") else patch.object(authlib, "encrypt_secret", side_effect=mock_encrypt)
        decrypt_patch = nullcontext() if importlib.util.find_spec("cryptography") else patch.object(authlib, "decrypt_secret", side_effect=mock_decrypt)
        with encrypt_patch, decrypt_patch, patch.object(authlib, "qr_data_uri", return_value="data:image/png;base64,dGVzdA=="):
            status, _, body = self.request("/api/auth/mfa/setup", "POST", {}, cookies, csrf)
            self.assertEqual(status, 200)
            secret = json.loads(body)["secret"]
            status, _, body = self.request("/api/auth/mfa/enable", "POST", {"code": authlib.totp(secret)}, cookies, csrf)
            self.assertEqual(status, 200)
            recovery = json.loads(body)["recovery_codes"]
            self.assertEqual(len(recovery), 10)
            status, _, body = self.request("/api/auth/login", "POST", {"email": "admin@example.test", "password": "long-admin-password-123"})
            self.assertEqual(status, 200)
            challenge = json.loads(body)["challenge"]
            status, _, _ = self.request("/api/auth/mfa/verify", "POST", {"challenge": challenge, "code": authlib.totp(secret)})
            self.assertEqual(status, 200)
            status, _, body = self.request("/api/auth/login", "POST", {"email": "admin@example.test", "password": "long-admin-password-123"})
            self.assertEqual(status, 200)
            recovery_challenge = json.loads(body)["challenge"]
            status, headers, _ = self.request("/api/auth/mfa/verify", "POST", {"challenge": recovery_challenge, "code": recovery[0]})
            self.assertEqual(status, 200)
            cookies, csrf = self.cookie_and_csrf(headers)
            status, _, body = self.request("/api/auth/login", "POST", {"email": "admin@example.test", "password": "long-admin-password-123"})
            self.assertEqual(status, 200)
            spent_code_challenge = json.loads(body)["challenge"]
            status, _, _ = self.request("/api/auth/mfa/verify", "POST", {"challenge": spent_code_challenge, "code": recovery[0]})
            self.assertEqual(status, 401)
            status, _, body = self.request("/api/auth/sessions", cookies=cookies)
            self.assertEqual(status, 200)
            self.assertTrue(any(item["current"] for item in json.loads(body)["sessions"]))
            status, _, body = self.request("/api/auth/login", "POST", {"email": "admin@example.test", "password": "long-admin-password-123"})
            self.assertEqual(status, 200)
            clear_challenge = json.loads(body)["challenge"]
            status, _, _ = self.request("/api/auth/mfa/verify", "POST", {"challenge": clear_challenge, "code": authlib.totp(secret)})
            self.assertEqual(status, 200)
            for _ in range(5):
                status, _, body = self.request("/api/auth/login", "POST", {"email": "admin@example.test", "password": "long-admin-password-123"})
                self.assertEqual(status, 200)
                distinct_challenge = json.loads(body)["challenge"]
                status, _, _ = self.request("/api/auth/mfa/verify", "POST", {"challenge": distinct_challenge, "code": "invalid"})
                self.assertEqual(status, 401)
            status, _, body = self.request("/api/auth/login", "POST", {"email": "admin@example.test", "password": "long-admin-password-123"})
            self.assertEqual(status, 200)
            rate_limited_challenge = json.loads(body)["challenge"]
            status, _, _ = self.request("/api/auth/mfa/verify", "POST", {"challenge": rate_limited_challenge, "code": "invalid"})
            self.assertEqual(status, 429)
            status, _, _ = self.request("/api/auth/mfa/disable", "POST", {"password": "wrong-password", "code": authlib.totp(secret)}, cookies, csrf)
            self.assertEqual(status, 401)
            status, _, _ = self.request("/api/auth/mfa/disable", "POST", {"password": "long-admin-password-123", "code": "invalid"}, cookies, csrf)
            self.assertEqual(status, 401)
            status, _, _ = self.request("/api/auth/mfa/disable", "POST", {"password": "long-admin-password-123", "code": authlib.totp(secret)}, cookies, csrf)
            self.assertEqual(status, 200)

    def test_admin_user_management_and_role_restrictions(self):
        status, headers, _ = self.request("/api/auth/login", "POST", {"email": "admin@example.test", "password": "long-admin-password-123"})
        self.assertEqual(status, 200)
        cookies, csrf = self.cookie_and_csrf(headers)
        user_data = {
            "full_name": "Review User", "username": "review-user", "email": "review-user@example.test",
            "password": "long-review-password-123", "role": "user", "is_active": True,
            "is_email_verified": True, "organization_id": 1,
        }
        invalid_data = {**user_data, "is_active": "false"}
        status, _, _ = self.request("/api/admin/users", "POST", invalid_data, cookies, csrf)
        self.assertEqual(status, 400)
        status, _, body = self.request("/api/admin/users", "POST", user_data, cookies, csrf)
        self.assertEqual(status, 201)
        user_id = json.loads(body)["id"]
        status, user_headers, _ = self.request("/api/auth/login", "POST", {"email": "review-user@example.test", "password": "long-review-password-123"})
        self.assertEqual(status, 200)
        user_cookies, _ = self.cookie_and_csrf(user_headers)
        status, _, _ = self.request(f"/api/admin/users/{user_id}", "PATCH", {"email": "renamed-user@example.test"}, cookies, csrf)
        self.assertEqual(status, 200)
        status, _, body = self.request("/api/admin/users?q=renamed-user", cookies=cookies)
        self.assertFalse(json.loads(body)["users"][0]["is_email_verified"])
        status, _, _ = self.request("/api/auth/me", cookies=user_cookies)
        self.assertEqual(status, 403)
        status, _, _ = self.request(f"/api/admin/users/{user_id}", "PATCH", {"role": "auditor", "is_active": False}, cookies, csrf)
        self.assertEqual(status, 200)
        status, _, body = self.request("/api/admin/users?q=review-user&active=0", cookies=cookies)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["users"][0]["role"], "auditor")
        status, _, body = self.request("/api/admin/security-events", cookies=cookies)
        self.assertEqual(status, 200)
        events = {event["event"] for event in json.loads(body)["events"]}
        self.assertTrue({"user_email_changed", "user_deactivated", "user_role_changed"}.issubset(events))
        status, _, _ = self.request("/api/admin/users", cookies="", csrf="")
        self.assertEqual(status, 401)
        status, _, _ = self.request(f"/api/admin/users/{user_id}/reset-password", "POST", {"password": "long-admin-reset-password-123"}, cookies, csrf)
        self.assertEqual(status, 200)
        status, _, _ = self.request("/api/auth/login", "POST", {"email": "renamed-user@example.test", "password": "long-admin-reset-password-123"})
        self.assertEqual(status, 401)  # Email remains unverified after an address change.
        status, _, _ = self.request(f"/api/admin/users/{user_id}", "PATCH", {"is_email_verified": True, "is_active": True}, cookies, csrf)
        self.assertEqual(status, 200)
        sent = []
        with patch.object(authlib, "smtp_configured", return_value=True), patch.object(authlib, "send_email", side_effect=lambda *args: sent.append(args)):
            status, _, _ = self.request("/api/admin/users/invite", "POST", {"full_name": "Invited User", "username": "invited-user", "email": "invited@example.test", "role": "user", "organization_id": 1}, cookies, csrf)
        self.assertEqual(status, 201)
        invite = re.search(r"one-time invitation code to set your password: ([A-Za-z0-9_-]+)", sent[0][2]).group(1)
        invite_password = "long-invited-password-123"
        status, _, _ = self.request("/api/auth/accept-invite", "POST", {"token": invite, "password": invite_password, "confirm_password": invite_password})
        self.assertEqual(status, 200)
        status, _, _ = self.request("/api/auth/accept-invite", "POST", {"token": invite, "password": invite_password, "confirm_password": invite_password})
        self.assertEqual(status, 400)
        db = connect()
        invited_id = db.execute("SELECT id FROM users WHERE email='invited@example.test'").fetchone()[0]
        db.execute("UPDATE users SET mfa_enabled=1,mfa_secret='encrypted:test' WHERE id=?", (invited_id,))
        db.execute("INSERT INTO mfa_recovery_codes(user_id,code_hash) VALUES(?,?)", (invited_id, authlib.token_hash("UNUSED-CODE")))
        db.commit()
        db.close()
        status, _, _ = self.request(f"/api/admin/users/{invited_id}/reset-mfa", "POST", {}, cookies, csrf)
        self.assertEqual(status, 200)
        db = connect()
        self.assertEqual(db.execute("SELECT mfa_enabled FROM users WHERE id=?", (invited_id,)).fetchone()[0], 0)
        self.assertEqual(db.execute("SELECT count(*) FROM mfa_recovery_codes WHERE user_id=?", (invited_id,)).fetchone()[0], 0)
        db.close()
        status, _, _ = self.request(f"/api/admin/users/{invited_id}", "DELETE", {}, cookies, csrf)
        self.assertEqual(status, 200)
        status, _, _ = self.request("/api/auth/login", "POST", {"email": "invited@example.test", "password": invite_password})
        self.assertEqual(status, 401)
        status, _, _ = self.request("/api/admin/users/1", "PATCH", {"role": "user"}, cookies, csrf)
        self.assertEqual(status, 409)  # The last active administrator cannot be demoted.


if __name__ == "__main__":
    unittest.main()
