"""Authentication primitives and outbound email providers for Sentinel Audit."""
import base64
import hashlib
import hmac
import json
import os
import secrets
import smtplib
import struct
import time
import urllib.parse
import urllib.request
from email.message import EmailMessage

try:
    from argon2 import PasswordHasher, Type
    from argon2.exceptions import VerifyMismatchError, VerificationError
    _password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, type=Type.ID)
except ImportError:  # Legacy databases stay readable; new passwords require requirements.txt.
    _password_hasher = None
_dummy_password_hash = _password_hasher.hash("Sentinel invalid account password") if _password_hasher else ""


def password_hash(password):
    if _password_hasher is None:
        raise RuntimeError("Install the required authentication dependencies with: pip install -r requirements.txt")
    return _password_hasher.hash(password)


def password_verify(password, stored):
    if stored.startswith("$argon2"):
        if _password_hasher is None:
            raise RuntimeError("Install argon2-cffi to verify this account")
        try:
            return _password_hasher.verify(stored, password)
        except Exception:
            return False
    # Backward-compatible PBKDF2 verification for users created by older versions.
    try:
        raw = base64.b64decode(stored)
        if len(raw) != 48:
            return False
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), raw[:16], 310000)
        return hmac.compare_digest(raw[16:], candidate)
    except Exception:
        return False


def password_needs_upgrade(stored):
    return not stored.startswith("$argon2")


def dummy_password_check(password):
    if _password_hasher:
        try:
            _password_hasher.verify(_dummy_password_hash, password)
        except Exception:
            pass
    else:
        hashlib.pbkdf2_hmac("sha256", password.encode(), b"sentinel-dummy-salt", 310000)


def valid_password(password):
    return isinstance(password, str) and 6 <= len(password) <= 256


def token():
    return secrets.token_urlsafe(32)


def token_hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def new_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp(secret, for_time=None):
    key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8), casefold=True)
    counter = int((for_time if for_time is not None else time.time()) // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return str((struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000).zfill(6)


def verify_totp(secret, code, now=None):
    if not isinstance(code, str) or not code.isdigit() or len(code) != 6:
        return False
    now = time.time() if now is None else now
    return any(hmac.compare_digest(totp(secret, now + drift * 30), code) for drift in (-1, 0, 1))


def encrypt_secret(value, signing_secret):
    from cryptography.fernet import Fernet
    key = base64.urlsafe_b64encode(hashlib.sha256(signing_secret.encode() + b"sentinel-mfa").digest())
    return Fernet(key).encrypt(value.encode()).decode()


def decrypt_secret(value, signing_secret):
    from cryptography.fernet import Fernet
    key = base64.urlsafe_b64encode(hashlib.sha256(signing_secret.encode() + b"sentinel-mfa").digest())
    return Fernet(key).decrypt(value.encode()).decode()


def recovery_codes(count=10):
    return [secrets.token_hex(6).upper() for _ in range(count)]


def qr_data_uri(otpauth_uri):
    import io
    import qrcode
    image = qrcode.make(otpauth_uri)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode()


def captcha_configured():
    return bool(os.environ.get("CAPTCHA_SECRET_KEY") and os.environ.get("CAPTCHA_SITE_KEY"))


def verify_captcha(response, remote_ip=""):
    if not captcha_configured() or not isinstance(response, str) or not response:
        return False
    data = {"secret": os.environ["CAPTCHA_SECRET_KEY"], "response": response}
    if remote_ip:
        data["remoteip"] = remote_ip
    request = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=urllib.parse.urlencode(data).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as result:
            payload = json.loads(result.read(8192))
        return payload.get("success") is True
    except Exception:
        return False


def smtp_configured():
    return bool(os.environ.get("SMTP_HOST") and os.environ.get("SMTP_FROM"))


def send_email(recipient, subject, text, html=None):
    if not smtp_configured():
        raise RuntimeError("Email delivery is not configured. Set SMTP_HOST and SMTP_FROM.")
    message = EmailMessage()
    message["From"] = os.environ["SMTP_FROM"]
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(text)
    if html:
        message.add_alternative(html, subtype="html")
    host = os.environ["SMTP_HOST"]
    port = int(os.environ.get("SMTP_PORT", "587"))
    timeout = 10
    if os.environ.get("SMTP_SSL", "").lower() in ("1", "true", "yes"):
        client = smtplib.SMTP_SSL(host, port, timeout=timeout)
    else:
        client = smtplib.SMTP(host, port, timeout=timeout)
        if os.environ.get("SMTP_STARTTLS", "true").lower() in ("1", "true", "yes"):
            client.starttls()
    try:
        username = os.environ.get("SMTP_USERNAME", "")
        if username:
            client.login(username, os.environ.get("SMTP_PASSWORD", ""))
        client.send_message(message)
    finally:
        try:
            client.quit()
        except Exception:
            pass
