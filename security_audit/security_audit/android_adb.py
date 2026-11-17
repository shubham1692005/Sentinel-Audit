"""Read-only Android evidence collection from an explicitly paired wireless ADB device."""

from __future__ import annotations

import datetime as dt
import ipaddress
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from . import android_device

MAX_DUMP_CHARS = 8_000_000
SERIAL_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}$")
PACKAGE_LINE_RE = re.compile(r"^package:([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+)\s*$")
PACKAGE_HEADER_RE = re.compile(r"^\s*Package \[([^\]]+)\]")
VERSION_CODE_RE = re.compile(r"\bversionCode=(\d+)")
VERSION_NAME_RE = re.compile(r"\bversionName=([^\s]+)")


class AndroidAdbError(RuntimeError):
    """A bounded, user-actionable failure from the paired ADB connection."""


def validate_target(value: str) -> str:
    """Accept exactly one RFC1918 IPv4 endpoint and a valid ADB connection port."""
    if not isinstance(value, str) or len(value) > 32:
        raise ValueError("Enter the paired phone's private IPv4 address and Wireless debugging connection port")
    try:
        host, raw_port = value.rsplit(":", 1)
        if not re.fullmatch(r"[0-9]{1,5}", raw_port):
            raise ValueError("invalid port")
        address = ipaddress.IPv4Address(host)
        port = int(raw_port)
    except (ValueError, TypeError) as exc:
        raise ValueError("Enter the paired phone's private IPv4 address and Wireless debugging connection port") from exc
    private_networks = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"), ipaddress.ip_network("192.168.0.0/16"))
    if not any(address in network for network in private_networks) or not 1 <= port <= 65535:
        raise ValueError("Wireless ADB is limited to one RFC1918 private IPv4 address and a valid port")
    return f"{address}:{port}"


def find_adb() -> str:
    configured = os.environ.get("ADB_PATH", "").strip().strip('"')
    candidates = [configured] if configured else []
    found = shutil.which("adb")
    if found:
        candidates.append(found)
    roots = [os.environ.get("ANDROID_SDK_ROOT", ""), os.environ.get("ANDROID_HOME", "")]
    local = os.environ.get("LOCALAPPDATA", "")
    if local:
        roots.append(str(Path(local) / "Android" / "Sdk"))
    for root in roots:
        if root:
            candidates.extend(str(Path(root) / "platform-tools" / name) for name in ("adb.exe", "adb"))
    for candidate in candidates:
        path = Path(candidate).expanduser()
        if path.is_file() and path.name.lower() in ("adb", "adb.exe"):
            return str(path.resolve())
    raise AndroidAdbError("ADB was not found on the Sentinel server computer. Install Android SDK Platform Tools or set ADB_PATH to adb.exe.")


def _run(adb: str, *args: str, timeout: int = 15) -> str:
    try:
        done = subprocess.run([adb, *args], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False, shell=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired as exc:
        raise AndroidAdbError("ADB timed out. Check that Wireless debugging is enabled and the paired phone is reachable.") from exc
    except OSError as exc:
        raise AndroidAdbError("Could not start ADB. Check Android SDK Platform Tools on the server computer.") from exc
    output = (done.stdout or "").strip()
    if len(output) > MAX_DUMP_CHARS:
        raise AndroidAdbError("The phone returned more package data than this audit accepts.")
    if done.returncode:
        detail = (done.stderr or output or "ADB command failed").replace("\r", " ").replace("\n", " ")[:240]
        raise AndroidAdbError(f"ADB could not read the authorized phone: {detail}")
    return output


def _verify_paired_wireless_device(adb: str, serial: str) -> None:
    serial = validate_target(serial)
    if not SERIAL_RE.fullmatch(serial):
        raise AndroidAdbError("Enter the phone's private IPv4 address and Wireless debugging connection port.")
    listing = _run(adb, "devices", "-l", timeout=10)
    match = next((line for line in listing.splitlines() if line.split() and line.split()[0] == serial), None)
    if match is None:
        raise AndroidAdbError("This private IP:port is not connected in ADB. Pair the phone from Wireless debugging, then run adb connect with its connection port.")
    parts = match.split()
    if len(parts) < 2 or parts[1] != "device" or "usb:" in match:
        raise AndroidAdbError("The selected ADB device is not an authorized wireless phone. Approve the pairing on the phone and retry.")


def _shell(adb: str, serial: str, *args: str, timeout: int = 15) -> str:
    return _run(adb, "-s", serial, "shell", *args, timeout=timeout)


def _prop(adb: str, serial: str, name: str) -> str:
    return _shell(adb, serial, "getprop", name, timeout=10).strip()[:120]


def _parse_apps(package_listing: str, package_dump: str) -> tuple[list[dict[str, Any]], bool]:
    names = list(dict.fromkeys(m.group(1) for line in package_listing.splitlines() if (m := PACKAGE_LINE_RE.fullmatch(line.strip()))))
    limit = android_device.MAX_APPS
    truncated = len(names) > limit
    allowed = set(names[:limit])
    versions: dict[str, dict[str, Any]] = {}
    current = None
    for line in package_dump.splitlines():
        header = PACKAGE_HEADER_RE.match(line)
        if header:
            candidate = header.group(1)
            current = candidate if candidate in allowed else None
            if current:
                versions.setdefault(current, {"version_name": "", "version_code": 0})
        elif current:
            if not versions[current]["version_name"] and (m := VERSION_NAME_RE.search(line)):
                versions[current]["version_name"] = m.group(1)[:100]
            if not versions[current]["version_code"] and (m := VERSION_CODE_RE.search(line)):
                versions[current]["version_code"] = min(int(m.group(1)), 2**63 - 1)
    return ([{"name": p, "package_name": p, **versions.get(p, {"version_name": "", "version_code": 0})} for p in sorted(allowed)], truncated)


def collect(serial: str) -> dict[str, Any]:
    """Collect allow-listed system properties and third-party package versions from one paired device."""
    serial = validate_target(serial)
    adb = find_adb()
    _verify_paired_wireless_device(adb, serial)
    manufacturer = _prop(adb, serial, "ro.product.manufacturer") or "Unknown manufacturer"
    model = _prop(adb, serial, "ro.product.model") or "Unknown model"
    android_version = _prop(adb, serial, "ro.build.version.release") or "Unavailable"
    try:
        sdk_int = int(_prop(adb, serial, "ro.build.version.sdk"))
    except ValueError as exc:
        raise AndroidAdbError("Could not read the phone's Android API level through ADB.") from exc
    if not 1 <= sdk_int <= 100:
        raise AndroidAdbError("The phone reported an invalid Android API level.")
    patch = _prop(adb, serial, "ro.build.version.security_patch")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", patch):
        patch = ""
    adb_enabled = _shell(adb, serial, "settings", "get", "global", "adb_enabled", timeout=10)
    dev_enabled = _shell(adb, serial, "settings", "get", "global", "development_settings_enabled", timeout=10)
    crypto = _prop(adb, serial, "ro.crypto.state").lower()
    crypto_type = _prop(adb, serial, "ro.crypto.type").lower()
    encryption = {"status": "checked", "value": crypto == "encrypted", "detail": f"Android system property ro.crypto.state={crypto}; encryption type={crypto_type or 'not reported'}."} if crypto in ("encrypted", "unencrypted") else {"status": "unavailable", "detail": "This Android build did not report a recognized encryption state."}
    packages = _shell(adb, serial, "pm", "list", "packages", "-3", timeout=20)
    dump = _shell(adb, serial, "dumpsys", "package", timeout=30)
    apps, truncated = _parse_apps(packages, dump)
    inventory_detail = "Third-party package names and version metadata read through the authorized Android Debug Bridge; app data was not accessed."
    if truncated:
        inventory_detail += f" Inventory was limited to the first {android_device.MAX_APPS} packages."
    checks = {
        "device_info": {"status": "checked", "detail": "Read-only Android system properties collected over paired Wireless debugging."},
        "security_patch": {"status": "checked" if patch else "unavailable", **({"value": patch} if patch else {}), "detail": "Android security patch system property."},
        "secure_screen_lock": {"status": "not_checked", "detail": "ADB does not query a stable screen-lock state across Android vendors."},
        "adb_debugging": {"status": "checked", "value": adb_enabled == "1", "detail": "Android Settings.Global adb_enabled; Wireless debugging was required for this connection."},
        "developer_options": {"status": "checked" if dev_enabled in ("0", "1") else "unavailable", **({"value": dev_enabled == "1"} if dev_enabled in ("0", "1") else {}), "detail": "Android Settings.Global development_settings_enabled."},
        "visible_app_inventory": {"status": "checked", "value": len(apps), "detail": inventory_detail},
        "play_protect": {"status": "unavailable", "detail": "Android does not expose a generally available Play Protect verdict to this audit."},
        "storage_encryption": encryption,
    }
    payload = {"schema_version": 1, "consent_confirmed": True, "collected_at": dt.datetime.now(dt.timezone.utc).isoformat(), "device": {"manufacturer": manufacturer, "model": model, "android_version": android_version, "sdk_int": sdk_int, "security_patch": patch}, "checks": checks, "apps": apps}
    result = android_device.build_assessment(payload)
    result["scope"] = f"Android device via authorized Wireless ADB: {manufacturer} {model} ({serial})"
    result["assessment"]["engine"] = "Sentinel Audit read-only Wireless ADB collector"
    result["assessment"]["data_categories"] = ["device model and Android version", "security patch date", "ADB/developer setting status", "storage encryption system property", "third-party app package names and versions"]
    result["scope_details"]["engine"] = "adb_wireless"
    result["scope_details"]["warnings"] = [w for w in result["scope_details"]["warnings"] if not w.startswith("Only launcher-visible apps")]
    result["scope_details"]["warnings"].insert(0, "Wireless ADB inventory includes third-party package entries only; system packages, private app data, files, messages and credentials are not inspected.")
    result["facts"]["inventory_scope"] = "adb_third_party_packages"
    result["facts"]["collection_method"] = "authorized_wireless_adb"
    result["facts"]["inventory_truncated"] = truncated
    result["warnings"] = list(result["scope_details"]["warnings"])
    return result
