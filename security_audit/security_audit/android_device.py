"""Validation and conservative analysis for consent-based Android audits."""

from __future__ import annotations

import datetime as dt
import json
import re
from typing import Any

from . import auth


MAX_APPS = 500
MAX_PAYLOAD_APPS = 500
PACKAGE_RE = re.compile(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$")
CHECK_KEYS = {
    "device_info",
    "security_patch",
    "secure_screen_lock",
    "adb_debugging",
    "developer_options",
    "visible_app_inventory",
    "play_protect",
    "storage_encryption",
}


def _text(value: Any, field: str, limit: int, *, required: bool = False) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text")
    value = value.strip()
    if required and not value:
        raise ValueError(f"{field} is required")
    if len(value) > limit or any(ord(ch) < 32 and ch not in "\t\n\r" for ch in value):
        raise ValueError(f"{field} is invalid or too long")
    return value


def validate_payload(value: Any) -> dict[str, Any]:
    """Return a bounded allow-listed payload; reject unconsented or oversized data."""
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("Unsupported Android audit payload")
    if value.get("consent_confirmed") is not True:
        raise ValueError("Explicit on-device consent is required")
    collected_at = _text(value.get("collected_at"), "collected_at", 40, required=True)
    try:
        dt.datetime.fromisoformat(collected_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("collected_at must be an ISO timestamp") from exc

    device = value.get("device")
    if not isinstance(device, dict):
        raise ValueError("Android device details are required")
    normalized_device = {
        "manufacturer": _text(device.get("manufacturer"), "manufacturer", 100, required=True),
        "model": _text(device.get("model"), "model", 120, required=True),
        "android_version": _text(device.get("android_version"), "android_version", 40, required=True),
        "sdk_int": device.get("sdk_int"),
        "security_patch": _text(device.get("security_patch"), "security_patch", 20),
    }
    if isinstance(normalized_device["sdk_int"], bool) or not isinstance(normalized_device["sdk_int"], int) or not 1 <= normalized_device["sdk_int"] <= 100:
        raise ValueError("sdk_int must be an Android API level")
    if normalized_device["security_patch"] and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", normalized_device["security_patch"]):
        raise ValueError("security_patch must use YYYY-MM-DD format")

    checks = value.get("checks")
    if not isinstance(checks, dict) or set(checks) - CHECK_KEYS:
        raise ValueError("Android audit checks are invalid")
    normalized_checks: dict[str, dict[str, Any]] = {}
    for key, check in checks.items():
        if not isinstance(check, dict) or check.get("status") not in ("checked", "unavailable", "not_checked"):
            raise ValueError(f"Invalid status for {key}")
        item: dict[str, Any] = {"status": check["status"]}
        if "value" in check:
            observed = check["value"]
            if isinstance(observed, bool) or isinstance(observed, int):
                item["value"] = observed
            elif isinstance(observed, str):
                item["value"] = _text(observed, f"{key}.value", 120)
            else:
                raise ValueError(f"Invalid value for {key}")
        detail = _text(check.get("detail"), f"{key}.detail", 300)
        if detail:
            item["detail"] = detail
        normalized_checks[key] = item

    apps = value.get("apps", [])
    if not isinstance(apps, list) or len(apps) > MAX_PAYLOAD_APPS:
        raise ValueError(f"App inventory is limited to {MAX_PAYLOAD_APPS} visible apps")
    normalized_apps = []
    seen: set[str] = set()
    for app in apps:
        if not isinstance(app, dict):
            raise ValueError("Invalid app inventory entry")
        package_name = _text(app.get("package_name"), "package_name", 255, required=True)
        if not PACKAGE_RE.fullmatch(package_name):
            raise ValueError("Invalid Android package name")
        if package_name in seen:
            continue
        seen.add(package_name)
        version_code = app.get("version_code", 0)
        if isinstance(version_code, bool) or not isinstance(version_code, int) or not 0 <= version_code <= 2**63 - 1:
            raise ValueError("version_code must be a non-negative integer")
        normalized_apps.append({
            "package_name": package_name,
            "name": _text(app.get("name"), "app name", 120),
            "version_name": _text(app.get("version_name"), "version_name", 100),
            "version_code": version_code,
        })

    return {
        "schema_version": 1,
        "consent_confirmed": True,
        "collected_at": collected_at,
        "device": normalized_device,
        "checks": normalized_checks,
        "apps": normalized_apps,
    }


def build_assessment(raw_payload: Any) -> dict[str, Any]:
    """Build conservative, report-ready assessment facts and findings."""
    payload = validate_payload(raw_payload)
    device = payload["device"]
    checks = payload["checks"]
    apps = payload["apps"]
    findings: list[dict[str, Any]] = []

    lock = checks.get("secure_screen_lock", {})
    if lock.get("status") == "checked" and lock.get("value") is False:
        findings.append({
            "title": "Android device reports no secure screen lock",
            "category": "configuration",
            "severity": "low",
            "likelihood": 2,
            "impact": 3,
            "description": "The Android system reported that no secure keyguard lock is configured. This is a device configuration observation; it does not prove that data has been accessed.",
            "remediation": "Configure a strong screen lock in Android Settings and review the device's lock-screen privacy options.",
            "evidence": {"source": "Android on-device audit", "check": "secure_screen_lock", "value": False, "collected_at": payload["collected_at"]},
            "verified": True,
        })

    for check_key, title, wording in (
        ("adb_debugging", "Android USB debugging is enabled", "USB debugging was reported enabled. This can increase exposure when the device is connected to a trusted computer; it does not by itself prove unauthorized access."),
        ("developer_options", "Android developer options are enabled", "Developer options were reported enabled. This is an observation only and is not automatically a vulnerability."),
    ):
        check = checks.get(check_key, {})
        if check.get("status") == "checked" and check.get("value") is True:
            findings.append({
                "title": title,
                "category": "configuration",
                "severity": "info",
                "likelihood": 1,
                "impact": 0,
                "description": wording,
                "remediation": "If this setting is not needed, turn it off in Android Developer options. Keep it enabled only for a specific trusted development task.",
                "evidence": {"source": "Android on-device audit", "check": check_key, "value": True, "collected_at": payload["collected_at"]},
                "verified": True,
            })

    patch = device["security_patch"]
    if patch:
        try:
            patch_date = dt.date.fromisoformat(patch)
            age_days = (dt.date.today() - patch_date).days
        except ValueError:
            age_days = -1
        if age_days > 365:
            findings.append({
                "title": "Android security patch date is over one year old",
                "category": "configuration",
                "severity": "info",
                "likelihood": 1,
                "impact": 0,
                "description": f"The device reported security patch level {patch} ({age_days} days old). Patch age alone does not confirm an unpatched vulnerability; verify current vendor support and update availability for this exact model.",
                "remediation": "Check the device manufacturer's supported update channel for this exact model and install any available Android security update.",
                "evidence": {"source": "Android on-device audit", "check": "security_patch", "security_patch": patch, "patch_age_days": age_days, "collected_at": payload["collected_at"]},
                "verified": True,
            })

    coverage = {
        key: {"status": check["status"], **({"detail": check["detail"]} if check.get("detail") else {})}
        for key, check in checks.items()
    }
    warnings = [
        "Only launcher-visible apps returned by Android package visibility are included; this is not a complete installed-package inventory.",
        "App versions are recorded as inventory evidence only. No CVE is asserted without a reliable vendor/product/version advisory match.",
        "This on-device audit does not inspect app data, files, messages, credentials, or exploitability.",
    ]
    for key, check in checks.items():
        if check["status"] != "checked":
            status_label = check["status"].replace("_", " ")
            warnings.append(f"{key.replace('_', ' ').title()} was {status_label}: {check.get('detail') or 'not available on this device.'}")

    return {
        "assessment": {
            "type": "android_device",
            "authorized": True,
            "consent_confirmed": True,
            "read_only": True,
            "engine": "Sentinel Audit Android companion",
            "collected_at": payload["collected_at"],
            "data_categories": ["device model and Android version", "security patch date", "supported security settings", "launcher-visible app names, package names, and versions"],
        },
        "scope": f"Android device: {device['manufacturer']} {device['model']}",
        "scope_details": {
            "engine": "android_companion",
            "checks_completed": sum(check["status"] == "checked" for check in checks.values()),
            "checks_unavailable": sum(check["status"] == "unavailable" for check in checks.values()),
            "checks_not_checked": sum(check["status"] == "not_checked" for check in checks.values()),
            "visible_apps": len(apps),
            "warnings": warnings,
        },
        "facts": {
            "device": device,
            "collection_coverage": coverage,
            "check_results": checks,
            "visible_app_count": len(apps),
            "apps": apps,
        },
        "findings": findings,
        "warnings": warnings,
    }


def protect_inventory(assessment: dict[str, Any], secret: str) -> dict[str, Any]:
    """Encrypt app package/version inventory before persisting the assessment."""
    facts = assessment.get("facts")
    if not isinstance(facts, dict):
        return assessment
    apps = facts.pop("apps", [])
    facts["apps_encrypted"] = auth.encrypt_secret(json.dumps(apps, separators=(",", ":")), secret)
    return assessment


def restore_inventory(assessment: dict[str, Any], secret: str) -> dict[str, Any]:
    """Decrypt inventory only for an authorized report/history response."""
    facts = assessment.get("facts")
    if not isinstance(facts, dict) or "apps_encrypted" not in facts:
        return assessment
    ciphertext = facts.pop("apps_encrypted")
    try:
        apps = json.loads(auth.decrypt_secret(ciphertext, secret))
        if not isinstance(apps, list):
            raise ValueError("invalid encrypted app inventory")
        facts["apps"] = apps
    except Exception:
        facts.setdefault("collection_coverage", {})["visible_app_inventory"] = {
            "status": "unavailable",
            "detail": "Encrypted inventory could not be opened with the configured AUDIT_SECRET.",
        }
    return assessment
