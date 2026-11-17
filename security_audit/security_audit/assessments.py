"""
Security Audit Assessment Engine
================================

Production-style, read-only assessment engine for the Sentinel Audit
platform.

Capabilities
------------
1. Local endpoint security assessment
2. Windows security checks
3. Linux security checks
4. Software inventory
5. Advisory/CVE candidate correlation
6. Authorized private IPv4 network discovery
7. TCP service discovery
8. Conservative UDP discovery
9. Reverse DNS
10. Evidence-based findings
11. Assessment summaries
12. Unified assessment orchestration

Safety
------
- Explicit authorization is required for network assessments.
- Only private/loopback IPv4 targets are accepted.
- Network scope is limited to /24.
- No exploitation.
- No brute forcing.
- No credential attacks.
- No destructive actions.
- Network checks are read-only connectivity/discovery checks.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import uuid
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED, as_completed
from datetime import datetime, timezone
from typing import Any

from .vulnerability import match, enrich_service
from . import nmap_scanner
from . import risk as risk_engine
from .correlation import correlate_findings


# ============================================================================
# CONSTANTS
# ============================================================================

COMMON_TCP_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP Submission",
    636: "LDAPS",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    9200: "Elasticsearch",
}

# Mobile hotspot paths can add latency; keep probes bounded while allowing
# enough time for a normal TCP handshake on a congested local Wi-Fi link.
TCP_CONNECT_TIMEOUT_SECONDS = 0.9

COMMON_UDP_PORTS: dict[int, str] = {
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    123: "NTP",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    161: "SNMP",
    162: "SNMP-Trap",
    500: "IKE",
    514: "Syslog",
    1194: "OpenVPN",
    1900: "SSDP",
    4500: "IPsec NAT-T",
}

CLEAR_TEXT_SERVICES = {
    21: "FTP",
    23: "Telnet",
    110: "POP3",
    143: "IMAP",
}

SENSITIVE_SERVICES = {
    135: "MS-RPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    9200: "Elasticsearch",
}

SERVICE_EXPOSURE_NOTES = {
    21: ("FTP is commonly used for file transfer and may transmit data without encryption, depending on configuration.", "Disable it if unused or replace it with an encrypted transfer service."),
    22: ("SSH provides remote administration; its exposure increases the reachable management surface.", "Restrict access to approved management networks and review authentication and patching."),
    23: ("Telnet is commonly unencrypted, which can expose session data if that protocol is in use.", "Disable Telnet or replace it with an encrypted management protocol."),
    53: ("DNS may disclose naming information or provide a query surface, depending on server role and configuration.", "Confirm the service role and restrict recursive or administrative functions as appropriate."),
    80: ("HTTP may expose websites, APIs, or administrative pages without transport encryption.", "Use HTTPS for sensitive traffic and restrict administrative interfaces."),
    443: ("HTTPS exposes a web application or service to network clients; application-level weaknesses remain possible.", "Keep the application and TLS configuration supported and limit sensitive endpoints."),
    445: ("SMB may expose file shares and Windows networking functions, depending on access controls.", "Restrict SMB to trusted networks and verify share permissions and patching."),
    1433: ("A database listener may expose data or authentication interfaces to network clients.", "Restrict database access to application and administration hosts."),
    3306: ("A database listener may expose data or authentication interfaces to network clients.", "Restrict database access to application and administration hosts."),
    3389: ("Remote Desktop exposes an interactive administration interface to network clients.", "Restrict access to approved management systems and use strong authentication."),
    5432: ("A database listener may expose data or authentication interfaces to network clients.", "Restrict database access to application and administration hosts."),
}

SEVERITIES = (
    "critical",
    "high",
    "medium",
    "low",
    "info",
)


# ============================================================================
# TIME / ID HELPERS
# ============================================================================

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _assessment_id(prefix: str = "ASSESS") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:16].upper()}"


def _finding_id(
    title: str,
    category: str,
    evidence: Any,
) -> str:
    raw = json.dumps(
        {
            "title": title,
            "category": category,
            "evidence": evidence,
        },
        sort_keys=True,
        default=str,
    ).encode("utf-8")

    digest = hashlib.sha256(raw).hexdigest()[:16].upper()

    return f"F-{digest}"


def _safe_text(
    value: Any,
    limit: int = 5000,
) -> str:
    if value is None:
        return ""

    return str(value)[:limit]


# ============================================================================
# FINDING MODEL
# ============================================================================

def _finding(
    title: str,
    severity: str,
    category: str,
    description: str,
    evidence: Any,
    verified: bool = True,
    remediation: str = (
        "Review the finding and apply vendor-supported "
        "security guidance."
    ),
    cve: str = "",
    cvss: float | None = None,
    confidence: str = "high",
    references: list[str] | None = None,
    status: str = "open",
    verification_status: str | None = None,
    likelihood: int = 3,
    impact: int | None = None,
) -> dict[str, Any]:
    """
    Create a normalized finding.

    This schema intentionally matches the database/API layer.
    """

    severity = str(
        severity or "info"
    ).lower()

    if severity not in SEVERITIES:
        severity = "info"

    confidence = str(
        confidence or "high"
    ).lower()

    if confidence not in {
        "high",
        "medium",
        "low",
        "candidate",
    }:
        confidence = "low"

    return {
        "id": _finding_id(
            title,
            category,
            evidence,
        ),
        "title": _safe_text(
            title,
            240,
        ),
        "severity": severity,
        "category": _safe_text(
            category,
            100,
        ),
        "description": _safe_text(
            description,
            5000,
        ),
        "evidence": (
            evidence
            if isinstance(evidence, dict)
            else {
                "details": _safe_text(
                    evidence,
                    5000,
                )
            }
        ),
        "verified": bool(verified),
        "verification_status": verification_status or ("confirmed observation" if verified else "candidate / unverified"),
        "likelihood": likelihood,
        "impact": impact if impact is not None else risk_engine.SEVERITY_SCORE.get(severity, 0),
        "confidence": confidence,
        "remediation": _safe_text(
            remediation,
            5000,
        ),
        "cve": _safe_text(
            cve,
            100,
        ),
        "cvss": cvss,
        "references": references or [],
        "timestamp": _utc_now(),
        "status": status,
    }


# ============================================================================
# POWERSELL HELPERS
# ============================================================================

def _powershell(
    script: str,
) -> str:
    """
    Execute a predefined read-only PowerShell command.
    """

    if os.name != "nt":
        raise RuntimeError(
            "PowerShell is only available on Windows."
        )

    process = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    if process.returncode != 0:
        raise RuntimeError(
            _safe_text(
                process.stderr
                or "PowerShell check failed",
                1000,
            )
        )

    return process.stdout.strip()


def _optional_powershell(
    script: str,
) -> Any:
    try:
        raw = _powershell(script)

        if not raw:
            return None

        return json.loads(raw)

    except Exception as exc:
        return {
            "collection_error": _safe_text(
                exc,
                500,
            )
        }


def _collect_windows_check(
    facts: dict[str, Any],
    coverage: dict[str, Any],
    key: str,
    script: str,
    source: str,
    limitation: str = "",
) -> Any:
    """Run one fixed, read-only PowerShell query and record its coverage state."""
    value = _optional_powershell(script)
    error = value.get("collection_error") if isinstance(value, dict) else None
    if error:
        text = str(error).lower()
        status = "permission_required" if any(word in text for word in ("access denied", "unauthorized", "elevation", "administrator")) else "unavailable"
        coverage[key] = {"status": status, "source": source, "detail": _safe_text(str(error), 300), "limitation": limitation}
    elif value is None:
        coverage[key] = {"status": "unavailable", "source": source, "detail": "No data returned", "limitation": limitation}
    else:
        coverage[key] = {"status": "collected", "source": source, "limitation": limitation}
    facts[key] = value
    return value


# ============================================================================
# NORMALIZATION
# ============================================================================

def _as_list(
    value: Any,
) -> list[Any]:

    if value is None:
        return []

    if isinstance(value, list):
        return value

    return [value]


# ============================================================================
# WINDOWS ASSESSMENT
# ============================================================================

def _windows_assessment() -> tuple[
    dict[str, Any],
    list[dict[str, Any]],
]:
    facts: dict[str, Any] = {}
    findings: list[dict[str, Any]] = []
    coverage: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Operating system
    # ------------------------------------------------------------------

    _collect_windows_check(
        facts, coverage, "computer_system",
        """
        Get-CimInstance Win32_OperatingSystem |
        Select-Object Caption,Version,BuildNumber,OSArchitecture,LastBootUpTime,InstallDate |
        ConvertTo-Json -Compress
        """,
        "Get-CimInstance Win32_OperatingSystem",
    )

    # ------------------------------------------------------------------
    # Firewall
    # ------------------------------------------------------------------

    _collect_windows_check(
        facts, coverage, "firewall_profiles",
        """
        Get-NetFirewallProfile |
        Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction |
        ConvertTo-Json -Compress
        """,
        "Get-NetFirewallProfile",
    )

    firewall = facts["firewall_profiles"]

    if isinstance(
        firewall,
        dict,
    ) and "collection_error" not in firewall:
        firewall = [firewall]

    if not isinstance(
        firewall,
        list,
    ):
        firewall = []

    facts["firewall_profiles"] = firewall

    # ------------------------------------------------------------------
    # Defender
    # ------------------------------------------------------------------

    _collect_windows_check(
        facts, coverage, "defender",
        """
        Get-MpComputerStatus |
        Select-Object AMServiceEnabled,AntivirusEnabled,AntispywareEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,AntivirusSignatureLastUpdated,AntispywareSignatureLastUpdated,AntivirusSignatureAge,AntispywareSignatureAge |
        ConvertTo-Json -Compress
        """,
        "Get-MpComputerStatus",
    )

    # ------------------------------------------------------------------
    # Hotfixes
    # ------------------------------------------------------------------

    _collect_windows_check(
        facts, coverage, "hotfixes",
        """
        Get-HotFix |
        Sort-Object InstalledOn -Descending |
        Select-Object -First 30 HotFixID,Description,InstalledOn,InstalledBy |
        ConvertTo-Json -Compress
        """,
        "Get-HotFix",
    )

    if isinstance(
        facts["hotfixes"],
        dict,
    ):
        if "collection_error" in facts["hotfixes"]:
            facts["hotfixes"] = []

    if not isinstance(
        facts["hotfixes"],
        list,
    ):
        facts["hotfixes"] = _as_list(
            facts["hotfixes"]
        )

    # ------------------------------------------------------------------
    # Installed software
    # ------------------------------------------------------------------

    _collect_windows_check(
        facts, coverage, "installed_software",
        """
        Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' -ErrorAction SilentlyContinue |
        Where-Object DisplayName |
        Select-Object -First 2000 @{n='name';e={$_.DisplayName}},@{n='version';e={$_.DisplayVersion}},Publisher,InstallDate |
        ConvertTo-Json -Compress
        """,
        "Windows uninstall registry inventory",
    )

    software = facts["installed_software"]

    if isinstance(
        software,
        dict,
    ):

        if "collection_error" in software:
            facts["installed_software"] = []

        else:
            facts["installed_software"] = [
                software
            ]

    elif not isinstance(
        software,
        list,
    ):
        facts["installed_software"] = []

    # ------------------------------------------------------------------
    # Windows services
    # ------------------------------------------------------------------

    _collect_windows_check(
        facts, coverage, "services",
        """
        Get-Service |
        Where-Object Status -eq Running |
        Select-Object Name,DisplayName,Status,StartType |
        Select-Object -First 500 |
        ConvertTo-Json -Compress
        """,
        "Get-Service",
    )

    # ------------------------------------------------------------------
    # Additional read-only endpoint posture checks
    # ------------------------------------------------------------------

    _collect_windows_check(
        facts, coverage, "appx_packages",
        r"""
        Get-AppxPackage -ErrorAction Stop |
        Select-Object -First 1000 Name,Version,Publisher |
        ConvertTo-Json -Compress
        """,
        "Get-AppxPackage (current signed-in user)",
        "Packaged-app inventory is limited to the account running Sentinel; package paths and app data are not collected.",
    )
    _collect_windows_check(
        facts, coverage, "pending_windows_updates",
        r"""
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $result = $searcher.Search('IsInstalled=0 and IsHidden=0')
        $items = @($result.Updates | Select-Object -First 100 | ForEach-Object {
            [PSCustomObject]@{ Title=$_.Title; MsrcSeverity=$_.MsrcSeverity; IsDownloaded=$_.IsDownloaded }
        })
        [PSCustomObject]@{ ResultCode=$result.ResultCode; PendingCount=$result.Updates.Count; Updates=$items } |
        ConvertTo-Json -Compress -Depth 4
        """,
        "Windows Update Agent search (query only)",
        "May contact the configured Windows Update or WSUS source; failure means update state is unknown, not up to date.",
    )
    _collect_windows_check(
        facts, coverage, "bitlocker_volumes",
        r"""
        Get-BitLockerVolume -ErrorAction Stop |
        Select-Object MountPoint,VolumeType,VolumeStatus,ProtectionStatus,EncryptionMethod |
        ConvertTo-Json -Compress
        """,
        "Get-BitLockerVolume",
        "Recovery keys and key protectors are deliberately not collected; this query may require administrator rights.",
    )
    _collect_windows_check(
        facts, coverage, "secure_boot",
        r"""
        $result = try { [PSCustomObject]@{ Supported=$true; Enabled=[bool](Confirm-SecureBootUEFI -ErrorAction Stop) } }
        catch { [PSCustomObject]@{ Supported=$false; Error=$_.Exception.Message } }
        $result | ConvertTo-Json -Compress
        """,
        "Confirm-SecureBootUEFI",
        "Legacy BIOS and some virtual machines do not expose this UEFI check; unsupported is not treated as disabled.",
    )
    _collect_windows_check(
        facts, coverage, "tpm",
        r"""
        Get-Tpm -ErrorAction Stop |
        Select-Object TpmPresent,TpmReady,TpmEnabled,TpmActivated,LockedOut |
        ConvertTo-Json -Compress
        """,
        "Get-Tpm",
        "No TPM secrets, keys, or attestation material are collected.",
    )
    _collect_windows_check(
        facts, coverage, "uac",
        r"""
        $p = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop
        [PSCustomObject]@{ EnableLUA=$p.EnableLUA; ConsentPromptBehaviorAdmin=$p.ConsentPromptBehaviorAdmin; PromptOnSecureDesktop=$p.PromptOnSecureDesktop } |
        ConvertTo-Json -Compress
        """,
        "UAC policy registry values (read only)",
    )
    _collect_windows_check(
        facts, coverage, "listening_ports",
        r"""
        Get-NetTCPConnection -State Listen -ErrorAction Stop |
        Select-Object -First 500 LocalAddress,LocalPort,OwningProcess |
        ConvertTo-Json -Compress
        """,
        "Get-NetTCPConnection",
        "Only listening TCP endpoints and process IDs are collected; no command lines or active remote connections.",
    )
    _collect_windows_check(
        facts, coverage, "udp_endpoints",
        r"""
        Get-NetUDPEndpoint -ErrorAction Stop |
        Select-Object -First 500 LocalAddress,LocalPort,OwningProcess |
        ConvertTo-Json -Compress
        """,
        "Get-NetUDPEndpoint",
        "Only local UDP endpoints and process IDs are collected.",
    )
    _collect_windows_check(
        facts, coverage, "local_account_posture",
        r"""
        $users = @(Get-LocalUser -ErrorAction Stop)
        $guest = $users | Where-Object { $_.SID.Value -match '-501$' } | Select-Object -First 1
        $guestEnabled = $null
        if ($guest) { $guestEnabled = [bool]$guest.Enabled }
        [PSCustomObject]@{ EnabledLocalAccountCount=@($users | Where-Object Enabled).Count; GuestAccountEnabled=$guestEnabled } |
        ConvertTo-Json -Compress
        """,
        "Get-LocalUser aggregate only",
        "Account names, group memberships, passwords, and password hashes are not collected; this query may require a supported Windows edition/module.",
    )
    # Windows does not provide a stable, complete built-in API for per-app
    # permissions across packaged and desktop applications. Report this gap.
    coverage["windows_app_permissions"] = {
        "status": "not_available",
        "source": "Windows platform capability",
        "detail": "Per-app permission coverage is not reliably available through this read-only collector.",
        "limitation": "Review app privacy permissions in Windows Settings.",
    }
    facts["collection_coverage"] = coverage

    updates = facts.get("pending_windows_updates")
    if isinstance(updates, dict) and not updates.get("collection_error"):
        for update in _as_list(updates.get("Updates", [])):
            if isinstance(update, dict) and str(update.get("MsrcSeverity", "")).lower() in ("critical", "important"):
                level = str(update.get("MsrcSeverity", "")).lower()
                findings.append(_finding(
                    title="Important Windows security update is pending",
                    severity="high" if level == "critical" else "medium",
                    category="patch management",
                    description="The configured Windows Update source lists this update as not installed. This is evidence of a pending update, not proof that a specific vulnerability is exploitable on this computer.",
                    evidence={"source": "Windows Update Agent search", "update": update, "verified": True},
                    verified=True,
                    remediation="Review the update in Windows Settings and install it through your normal change process, then rerun the assessment.",
                ))

    bitlocker = facts.get("bitlocker_volumes")
    if not (isinstance(bitlocker, dict) and bitlocker.get("collection_error")):
        for volume in _as_list(bitlocker):
            if isinstance(volume, dict) and str(volume.get("VolumeType", "")).lower() in ("operatingsystem", "fixeddata") and str(volume.get("ProtectionStatus", "")).lower() in ("off", "0", "false"):
                findings.append(_finding(
                    title=f"BitLocker protection is off for {volume.get('MountPoint', 'a fixed volume')}",
                    severity="medium",
                    category="data protection",
                    description="Windows reports that BitLocker protection is off for this fixed volume. This does not reveal whether another approved encryption product is in use.",
                    evidence={"source": "Get-BitLockerVolume", "volume": volume},
                    verified=True,
                    remediation="Confirm the organization's encryption policy, enable approved full-disk encryption if required, and verify protection status without exporting recovery keys.",
                ))

    secure_boot = facts.get("secure_boot")
    if isinstance(secure_boot, dict) and secure_boot.get("Supported") is True and secure_boot.get("Enabled") is False:
        findings.append(_finding(
            title="Secure Boot is disabled",
            severity="medium",
            category="platform security",
            description="The UEFI Secure Boot check reports that Secure Boot is supported but disabled. Unsupported systems are reported as unavailable and do not create this finding.",
            evidence={"source": "Confirm-SecureBootUEFI", "result": secure_boot},
            verified=True,
            remediation="Review device and operating-system requirements, enable Secure Boot in UEFI firmware if supported, and rerun the check.",
        ))

    uac = facts.get("uac")
    if isinstance(uac, dict) and str(uac.get("EnableLUA", "1")) == "0":
        findings.append(_finding(
            title="User Account Control is disabled",
            severity="high",
            category="platform security",
            description="Windows reports that User Account Control (UAC) is disabled. This reduces prompts that help limit unintended administrator-level changes.",
            evidence={"source": "UAC policy registry values", "result": uac},
            verified=True,
            remediation="Review the organization's policy and re-enable UAC, then restart Windows if required and rerun the check.",
        ))

    # ------------------------------------------------------------------
    # Firewall findings
    # ------------------------------------------------------------------

    for profile in facts[
        "firewall_profiles"
    ]:

        if not profile.get(
            "Enabled",
            False,
        ):

            findings.append(
                _finding(
                    title=(
                        "Windows firewall profile disabled: "
                        f"{profile.get('Name', 'Unknown')}"
                    ),
                    severity="high",
                    category="configuration",
                    description=(
                        "A Windows Firewall profile is disabled."
                    ),
                    evidence={
                        "source": "Get-NetFirewallProfile",
                        "profile": profile,
                    },
                    verified=True,
                    remediation=(
                        "Enable the firewall profile and review "
                        "inbound and outbound firewall rules."
                    ),
                )
            )

    # ------------------------------------------------------------------
    # Defender findings
    # ------------------------------------------------------------------

    defender = facts.get(
        "defender"
    )

    if (
        isinstance(defender, dict)
        and "collection_error" not in defender
    ):

        if not defender.get(
            "AntivirusEnabled",
            False,
        ):

            findings.append(
                _finding(
                    title=(
                        "Microsoft Defender antivirus "
                        "protection is disabled"
                    ),
                    severity="high",
                    category="endpoint protection",
                    description=(
                        "Windows reports that antivirus "
                        "protection is not enabled."
                    ),
                    evidence={
                        "source": "Get-MpComputerStatus",
                        "result": defender,
                    },
                    verified=True,
                    remediation=(
                        "Enable an approved endpoint protection "
                        "solution and verify that it is active."
                    ),
                )
            )

        if not defender.get(
            "RealTimeProtectionEnabled",
            False,
        ):

            findings.append(
                _finding(
                    title=(
                        "Microsoft Defender real-time "
                        "protection is disabled"
                    ),
                    severity="high",
                    category="endpoint protection",
                    description=(
                        "Real-time malware protection is "
                        "not enabled."
                    ),
                    evidence={
                        "source": "Get-MpComputerStatus",
                        "result": defender,
                    },
                    verified=True,
                    remediation=(
                        "Enable real-time protection or verify "
                        "that an approved equivalent endpoint "
                        "security product is active."
                    ),
                )
            )

    return (
        facts,
        findings,
    )


# ============================================================================
# LINUX ASSESSMENT
# ============================================================================

def _linux_software_inventory() -> list[
    dict[str, str]
]:
    """
    Collect installed packages using dpkg or rpm.
    """

    if platform.system() != "Linux":
        return []

    # Debian / Ubuntu
    if shutil.which(
        "dpkg-query"
    ):

        try:

            process = subprocess.run(
                [
                    "dpkg-query",
                    "-W",
                    "-f=${binary:Package}\t${Version}\n",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            inventory = []

            for line in process.stdout.splitlines():

                if "\t" not in line:
                    continue

                name, version = line.split(
                    "\t",
                    1,
                )

                inventory.append(
                    {
                        "name": name.strip(),
                        "version": version.strip(),
                        "source": "dpkg",
                    }
                )

            return inventory[:5000]

        except Exception:
            pass

    # RHEL / Fedora / Rocky / Alma / CentOS
    if shutil.which("rpm"):

        try:

            process = subprocess.run(
                [
                    "rpm",
                    "-qa",
                    "--qf",
                    "%{NAME}\t%{VERSION}-%{RELEASE}\n",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            inventory = []

            for line in process.stdout.splitlines():

                if "\t" not in line:
                    continue

                name, version = line.split(
                    "\t",
                    1,
                )

                inventory.append(
                    {
                        "name": name.strip(),
                        "version": version.strip(),
                        "source": "rpm",
                    }
                )

            return inventory[:5000]

        except Exception:
            pass

    return []


def _linux_assessment() -> tuple[
    dict[str, Any],
    list[dict[str, Any]],
]:

    facts: dict[str, Any] = {}
    findings: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # OS
    # ------------------------------------------------------------------

    if os.path.exists(
        "/etc/os-release"
    ):

        try:

            with open(
                "/etc/os-release",
                encoding="utf-8",
                errors="replace",
            ) as handle:

                facts["os_release"] = (
                    handle.read()[:10000]
                )

        except Exception:
            facts["os_release"] = ""

    else:
        facts["os_release"] = (
            platform.platform()
        )

    facts["kernel"] = platform.release()

    # ------------------------------------------------------------------
    # Listening sockets
    # ------------------------------------------------------------------

    if shutil.which(
        "ss"
    ):

        try:

            facts["listening_sockets"] = (
                subprocess.run(
                    [
                        "ss",
                        "-lntup",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=15,
                ).stdout[:30000]
            )

        except Exception:
            facts["listening_sockets"] = ""

    # ------------------------------------------------------------------
    # Software
    # ------------------------------------------------------------------

    facts["software_inventory"] = (
        _linux_software_inventory()
    )

    # ------------------------------------------------------------------
    # IP forwarding
    # ------------------------------------------------------------------

    forwarding_file = (
        "/proc/sys/net/ipv4/ip_forward"
    )

    if os.path.exists(
        forwarding_file
    ):

        try:

            with open(
                forwarding_file,
                encoding="utf-8",
            ) as handle:

                value = handle.read().strip()

            facts["ipv4_forwarding"] = value

            if value == "1":

                findings.append(
                    _finding(
                        title=(
                            "IPv4 forwarding is enabled"
                        ),
                        severity="medium",
                        category="configuration",
                        description=(
                            "The system is configured to "
                            "forward IPv4 traffic."
                        ),
                        evidence={
                            "source": forwarding_file,
                            "value": value,
                        },
                        verified=True,
                        remediation=(
                            "Disable IPv4 forwarding when "
                            "the system is not intended to "
                            "operate as a router, gateway, "
                            "firewall, or network appliance."
                        ),
                    )
                )

        except Exception:
            pass

    # ------------------------------------------------------------------
    # SSH configuration
    # ------------------------------------------------------------------

    ssh_config = "/etc/ssh/sshd_config"

    if os.path.exists(
        ssh_config
    ):

        try:

            with open(
                ssh_config,
                encoding="utf-8",
                errors="replace",
            ) as handle:

                content = handle.read()

            facts["ssh_configuration"] = {
                "path": ssh_config,
                "size": len(content),
            }

            # PermitRootLogin
            root_match = re.search(
                r"(?im)^\s*PermitRootLogin\s+(\S+)",
                content,
            )

            if root_match:

                value = root_match.group(
                    1
                ).lower()

                if value in {
                    "yes",
                    "without-password",
                    "prohibit-password",
                }:

                    findings.append(
                        _finding(
                            title=(
                                "SSH root login is permitted"
                            ),
                            severity="high",
                            category="authentication",
                            description=(
                                "The SSH configuration "
                                "allows direct root login."
                            ),
                            evidence={
                                "source": ssh_config,
                                "setting": (
                                    "PermitRootLogin"
                                ),
                                "value": value,
                            },
                            verified=True,
                            remediation=(
                                "Disable direct root SSH "
                                "login and use controlled "
                                "privilege escalation."
                            ),
                        )
                    )

        except Exception:
            pass

    return (
        facts,
        findings,
    )


# ============================================================================
# SOFTWARE ADVISORY CORRELATION
# ============================================================================

def _software_findings(
    inventory: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    findings = []

    for package in inventory:

        name = str(
            package.get("name")
            or package.get("Name")
            or ""
        ).strip()

        version = str(
            package.get("version")
            or package.get("Version")
            or ""
        ).strip()

        if not name or not version:
            continue

        try:
            advisories = match(
                name,
                version,
            )

        except Exception:
            advisories = []

        for advisory in advisories:

            cve = advisory.get(
                "cve",
                "",
            )

            findings.append(
                _finding(
                    title=(
                        f"Potentially affected software: "
                        f"{name} {version}"
                    ),
                    severity=advisory.get(
                        "severity",
                        "medium",
                    ),
                    category="vulnerability",
                    description=(
                        f"The installed version matched "
                        f"advisory {cve}. This is a candidate "
                        "correlation and does not independently "
                        "prove exploitability. Vendor backports, "
                        "package provenance, runtime configuration "
                        "and compensating controls require review."
                    ),
                    evidence={
                        "source": advisory.get(
                            "source"
                        ),
                        "product": name,
                        "version": version,
                        "reference": advisory.get(
                            "url"
                        ),
                        "confidence": (
                            advisory.get(
                                "confidence",
                                "candidate",
                            )
                        ),
                        "status": "candidate",
                    },
                    verified=False,
                    confidence="candidate",
                    remediation=advisory.get(
                        "remediation",
                        (
                            "Update the affected package "
                            "to a vendor-supported release "
                            "and verify package provenance."
                        ),
                    ),
                    cve=cve,
                    cvss=advisory.get(
                        "cvss"
                    ),
                    references=[
                        advisory.get("url")
                    ]
                    if advisory.get("url")
                    else [],
                )
            )

    return findings


# ============================================================================
# LOCAL ASSESSMENT
# ============================================================================

def local_assessment() -> dict[str, Any]:
    """
    Perform a read-only assessment of the current host.

    This function is called directly by api.py.
    """

    started = _utc_now()

    facts: dict[str, Any] = {
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "hostname": platform.node(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "assessment_type": "local",
        "started_at": started,
    }

    findings: list[
        dict[str, Any]
    ] = []

    # ------------------------------------------------------------------
    # Platform-specific collection
    # ------------------------------------------------------------------

    if os.name == "nt":

        platform_facts, platform_findings = (
            _windows_assessment()
        )

        facts.update(
            platform_facts
        )

        findings.extend(
            platform_findings
        )

        inventory = _as_list(
            facts.get(
                "installed_software",
                [],
            )
        )

    else:

        platform_facts, platform_findings = (
            _linux_assessment()
        )

        facts.update(
            platform_facts
        )

        findings.extend(
            platform_findings
        )

        inventory = _as_list(
            facts.get(
                "software_inventory",
                [],
            )
        )

    # ------------------------------------------------------------------
    # Vulnerability correlation
    # ------------------------------------------------------------------

    findings.extend(
        _software_findings(
            inventory
        )
    )

    # ------------------------------------------------------------------
    # Finding correlation / deduplication
    # ------------------------------------------------------------------

    raw_findings = list(findings)
    findings = correlate_findings(raw_findings)

    # ------------------------------------------------------------------
    # Severity summary
    # ------------------------------------------------------------------

    severity_counts = {
        severity: 0
        for severity in SEVERITIES
    }

    category_counts: dict[str, int] = {}

    for finding in findings:

        severity = finding.get(
            "severity",
            "info",
        )

        if severity in severity_counts:
            severity_counts[
                severity
            ] += 1

        category = finding.get(
            "category",
            "other",
        )

        category_counts[
            category
        ] = (
            category_counts.get(
                category,
                0,
            )
            + 1
        )

    coverage = facts.get("collection_coverage", {})
    unavailable_checks = [
        name
        for name, result in coverage.items()
        if isinstance(result, dict)
        and result.get("status") in ("unavailable", "permission_required")
    ]
    warnings = []
    if unavailable_checks:
        warnings.append(
            "Some host checks could not collect data ("
            + ", ".join(unavailable_checks)
            + "); assessment results may be incomplete."
        )

    return {
        "assessment": {
            "id": _assessment_id(
                "LOCAL"
            ),
            "type": "local",
            "started_at": started,
            "completed_at": _utc_now(),
            "authorized": True,
            "read_only": True,
        },
        "facts": facts,
        "inventory": inventory,
        "raw_findings": raw_findings,
        "raw_observations": raw_findings,
        "findings": findings,
        "warnings": warnings,
        "summary": {
            "raw_finding_count": len(
                raw_findings
            ),
            "finding_count": len(
                findings
            ),
            "verified_findings": sum(
                1
                for finding in findings
                if finding.get(
                    "verified"
                )
            ),
            "candidate_findings": sum(
                1
                for finding in findings
                if not finding.get(
                    "verified"
                )
            ),
            "software_count": len(
                inventory
            ),
            "severity_counts": severity_counts,
            "category_counts": category_counts,
        },
        "checks": len(facts),
    }


# ============================================================================
# TARGET / SCOPE VALIDATION
# ============================================================================

def validate_scope(
    target: str,
    authorized: bool,
    public_authorized: bool = False,
) -> ipaddress.IPv4Network:
    """
    Validate an explicitly authorized network target.

    Allowed:
        10.0.0.0/8
        172.16.0.0/12
        192.168.0.0/16
        127.0.0.0/8

    Maximum:
        /24
    """

    if authorized is not True:
        raise ValueError(
            "Explicit authorization is required."
        )

    if not isinstance(
        target,
        str,
    ) or not target.strip():

        raise ValueError(
            "Target cannot be empty."
        )

    target = target.strip()

    # Public authorization is scoped to one literal IPv4 host. A domain is
    # accepted only when it resolves to exactly one public IPv4 address; the
    # API pins that address into the job before the worker starts.
    if public_authorized is True:
        try:
            if "/" in target:
                public_network = ipaddress.ip_network(target, strict=True)
                if public_network.version != 4 or public_network.prefixlen != 32:
                    raise ValueError
                public_ip = public_network.network_address
            else:
                try:
                    public_ip = ipaddress.ip_address(target)
                    if public_ip.version != 4: raise ValueError
                except ValueError:
                    if len(target)>253 or not re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}",target): raise ValueError
                    answers={ipaddress.IPv4Address(item[4][0]) for item in socket.getaddrinfo(target,None,socket.AF_INET,socket.SOCK_STREAM)}
                    if len(answers)!=1: raise ValueError("domain must resolve to exactly one IPv4 address")
                    public_ip=next(iter(answers))
                public_network = ipaddress.ip_network(f"{public_ip}/32")
        except (ValueError,socket.gaierror) as exc:
            raise ValueError("Public assessment requires one globally routable IPv4 address or a domain resolving to exactly one public IPv4 address; public ranges and multi-address domains are not allowed.") from exc
        if (not public_ip.is_global or public_ip.is_multicast or public_ip.is_unspecified
                or public_ip.is_loopback or public_ip.is_link_local or public_ip.is_private
                or public_ip.is_reserved):
            raise ValueError("Public assessment requires a globally routable unicast IPv4 address; private, reserved, multicast, and documentation ranges are blocked.")
        return public_network

    # ---------------------------------------------------------------
    # CIDR / direct IP
    # ---------------------------------------------------------------

    try:

        # A bare address is one host (/32). An explicit CIDR must be a
        # canonical network; rejecting host bits avoids silently widening a
        # user's selected scope (for example 10.0.0.7/24).
        network = ipaddress.ip_network(
            target,
            strict=("/" in target),
        )

    except ValueError:

        # -----------------------------------------------------------
        # Hostname
        # -----------------------------------------------------------

        try:

            resolved_ip = socket.gethostbyname(
                target
            )

        except socket.gaierror as exc:

            raise ValueError(
                f"Unable to resolve target: {target}"
            ) from exc

        ip = ipaddress.ip_address(
            resolved_ip
        )

        network = ipaddress.ip_network(
            f"{ip}/{ip.max_prefixlen}",
            strict=False,
        )

    if network.version != 4:

        raise ValueError(
            "Only IPv4 targets are supported."
        )

    private_ranges=(ipaddress.ip_network("10.0.0.0/8"),ipaddress.ip_network("172.16.0.0/12"),ipaddress.ip_network("192.168.0.0/16"),ipaddress.ip_network("127.0.0.0/8"))
    if not any(network.subnet_of(item) for item in private_ranges):
        raise ValueError("A separate explicit public-target authorization is required for public IP addresses.")

    if network.num_addresses > 256:

        raise ValueError(
            "Network scope is limited to "
            "/24 (maximum 256 addresses)."
        )

    return network


# ============================================================================
# DNS
# ============================================================================

def _reverse_dns(
    address: str,
) -> str:

    try:

        hostname, _, _ = socket.gethostbyaddr(
            address
        )

        if hostname and hostname != address:
            return hostname

    except Exception:
        pass

    return ""


# ============================================================================
# TCP CONNECTIVITY
# ============================================================================

def _tcp_open(
    address: str,
    port: int,
    timeout: float = TCP_CONNECT_TIMEOUT_SECONDS,
) -> bool:

    try:

        with socket.create_connection(
            (
                address,
                port,
            ),
            timeout=timeout,
        ):
            return True

    except (
        OSError,
        TimeoutError,
    ):
        return False


def _discover_tcp_host(address: str, cancelled=None) -> dict[str, Any]:
    """Cheap fallback discovery for a network scope when Nmap is unavailable."""
    record = {"address": str(address), "hostname": _reverse_dns(str(address)), "alive": False, "reachability": "no_response"}
    for port in (22, 53, 80, 443, 445, 3389):
        if cancelled and cancelled():
            break
        if _tcp_open(str(address), port):
            record.update(alive=True, reachability="reachable")
            break
    return record


def _identify_tcp_service(address: str, port: int) -> dict[str, str]:
    """Read a bounded service greeting or HTTP Server header; never authenticate."""
    result={"banner":"","product":"","version":""}
    try:
        with socket.create_connection((address,port),timeout=.7) as sock:
            sock.settimeout(.7)
            if port in (80,8080): sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {address}\r\nConnection: close\r\n\r\n".encode("ascii"))
            raw=sock.recv(2048)
        banner="".join(ch for ch in raw.decode("utf-8","replace") if ch in "\r\n\t" or 32<=ord(ch)<127)[:512].strip(); result["banner"]=banner
        found=re.search(r"(?im)^server:\s*([^\r\n]+)",banner); service=found.group(1).strip() if found else banner.splitlines()[0] if banner else ""
        patterns=((r"OpenSSL[/ _-]?([0-9][\w.\-]*)","OpenSSL"),(r"OpenSSH[_ /-]?([0-9][\w.\-]*)","OpenSSH"),(r"nginx[/ ]([0-9][\w.\-]*)","nginx"),(r"Apache[/ ]([0-9][\w.\-]*)","Apache HTTP Server"),(r"vsFTPd\s*([0-9][\w.\-]*)","vsftpd"),(r"ProFTPD\s*([0-9][\w.\-]*)","ProFTPD"))
        for pattern,product in patterns:
            match=re.search(pattern,service,re.I)
            if match: result.update(product=product,version=match.group(1)); break
    except (OSError,TimeoutError): pass
    return result


def _scan_tcp_host(
    address: str,
    ports: tuple[int, ...],
    cancelled=None,
    discovery: dict[str, Any] | None = None,
) -> dict[str, Any]:

    address = str(
        address
    )

    record: dict[str, Any] = dict(discovery) if discovery else {
        "address": address,
        "hostname": _reverse_dns(
            address
        ),
        "alive": False,
        "reachability": "no_response",
        "open_ports": [],
    }
    record.setdefault("open_ports", [])
    record.setdefault("reachability", "no_response")

    # ---------------------------------------------------------------
    # Host reachability
    # ---------------------------------------------------------------

    probe_ports = (
        22,
        80,
        443,
        445,
        3389,
    )

    for port in (() if discovery else probe_ports):

        if cancelled and cancelled(): return record

        if _tcp_open(
            address,
            port,
        TCP_CONNECT_TIMEOUT_SECONDS,
        ):

            record["alive"] = True
            record["reachability"] = "reachable"
            break

    # ---------------------------------------------------------------
    # Port discovery
    # ---------------------------------------------------------------

    for port in ports:

        if cancelled and cancelled(): return record

        if _tcp_open(
            address,
            port,
            TCP_CONNECT_TIMEOUT_SECONDS,
        ):

            record[
                "open_ports"
            ].append(
                {
                    "port": port,
                    "protocol": "tcp",
                    "service": COMMON_TCP_PORTS.get(
                        port,
                        "unknown",
                    ),
                    "state": "open",
                    "evidence_source": "bounded TCP connect check",
                    "verification_status": "confirmed observation",
                    "service_verification_status": "candidate / unverified",
                    "detection_method": "bounded TCP connect and safe banner read",
                    "scan_timestamp": _utc_now(),
                    **_identify_tcp_service(address,port),
                }
            )

    if record["open_ports"]:
        record["alive"] = True
        record["reachability"] = "reachable"

    return record


# ============================================================================
# UDP
# ============================================================================

def _udp_probe(
    address: str,
    port: int,
    timeout: float = 0.5,
) -> str:
    """
    Conservative UDP probe.

    UDP does not provide a TCP-like handshake.

    Result:
        open|responding
        open|filtered
        closed
        unknown
    """

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
    )

    try:

        sock.settimeout(
            timeout
        )

        # Empty datagram.
        # No protocol-specific exploit/payload.
        sock.sendto(
            b"",
            (
                address,
                port,
            ),
        )

        try:

            sock.recvfrom(
                1024
            )

            return "open|responding"

        except socket.timeout:

            return "open|filtered"

    except ConnectionRefusedError:

        return "closed"

    except OSError:

        return "unknown"

    finally:
        sock.close()


def _scan_udp_host(
    address: str,
    ports: tuple[int, ...],
    cancelled=None,
) -> list[dict[str, Any]]:

    results = []

    for port in ports:

        if cancelled and cancelled(): break

        state = _udp_probe(
            address,
            port,
        )

        if state in {
            "open|responding",
            "open|filtered",
        }:

            results.append(
                {
                    "port": port,
                    "protocol": "udp",
                    "service": COMMON_UDP_PORTS.get(
                        port,
                        "unknown",
                    ),
                    "state": state,
                    "evidence_source": "conservative UDP datagram probe",
                    "verification_status": "confirmed observation" if state == "open|responding" else "candidate / unverified",
                    "service_verification_status": "candidate / unverified",
                    "detection_method": "empty UDP datagram; no protocol-specific query",
                    "scan_timestamp": _utc_now(),
                }
            )

    return results


# ============================================================================
# NETWORK FINDINGS
# ============================================================================

def _network_findings(
    hosts: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    findings = []

    for host in hosts:

        address = host.get(
            "address",
            "",
        )

        hostname = host.get(
            "hostname",
            "",
        )

        display = (
            f"{address} ({hostname})"
            if hostname
            else address
        )

        # -----------------------------------------------------------
        # TCP services
        # -----------------------------------------------------------

        for service in host.get(
            "open_ports",
            [],
        ):

            # Nmap-discovered services may carry product/version/CPE data.
            # Enrich them before generating findings so CVE/CVSS evidence is
            # attached to the same normalized service record.
            try:
                service = enrich_service(service, use_nvd=True)
            except Exception:
                service = dict(service)
                service.setdefault("cves", [])

            port = service.get(
                "port"
            )

            service_name = service.get(
                "service",
                "unknown",
            )

            exposure_note, exposure_fix = SERVICE_EXPOSURE_NOTES.get(
                int(port or 0),
                ("A reachable TCP service adds to the host's network attack surface. Its security impact depends on the actual service, configuration, and access controls.", "Confirm the service is required, restrict access to expected clients, and keep it supported and patched."),
            )
            identified_label = service_name if service_name and service_name.lower() != "unknown" else f"unidentified service on TCP/{port}"
            findings.append(_finding(
                title=f"Reachable network service: {identified_label} on {display}",
                severity="info",
                category="network exposure",
                description=(f"TCP/{port} is confirmed reachable. {exposure_note} This observation describes potential exposure; it does not establish a vulnerability or successful attack."),
                evidence={"source": service.get("detection_method", "TCP service discovery"), "address": address, "hostname": hostname, "port": port, "protocol": "tcp", "service": service_name, "product": service.get("product", ""), "version": service.get("version", ""), "state": service.get("state", "open"), "service_verification_status": service.get("service_verification_status", "candidate / unverified"), "cpe": service.get("cpe", []), "scan_timestamp": service.get("scan_timestamp"), "scan_method": service.get("scan_method")},
                verified=True,
                verification_status="confirmed observation",
                remediation=exposure_fix,
            ))

            for advisory in service.get("cves", []):
                severity = str(advisory.get("severity") or "medium").lower()
                if severity not in SEVERITIES:
                    severity = "medium"
                advisory_verified = bool(advisory.get("verified", False))
                confidence = advisory.get("confidence", "candidate")
                findings.append(_finding(
                    title=f"CVE candidate for {service.get('product') or service_name} {service.get('version') or ''}: {advisory.get('cve', 'unknown')}",
                    severity=severity,
                    category="vulnerability candidate",
                    description=(
                        "A read-only service/version/CPE correlation identified a potential advisory. "
                        "This does not prove exploitability; confirm exact affected configuration, vendor backports, "
                        "and deployment context before treating it as verified."
                    ),
                    evidence={
                        "source": service.get("detection_method", "network/service discovery"),
                        "address": address, "hostname": hostname, "port": port,
                        "protocol": service.get("protocol", "tcp"),
                        "product": service.get("product", ""), "version": service.get("version", ""),
                        "cpe": service.get("cpe", []), "cpe_source": service.get("cpe_source", "none"), "cpe_confidence": service.get("cpe_confidence", "none"), "scan_timestamp": service.get("scan_timestamp"), "scan_method": service.get("scan_method"), "banner": service.get("banner", ""),
                        "cvss_version": advisory.get("cvss_version"), "cvss_vector": advisory.get("cvss_vector"), "cvss_metrics": advisory.get("cvss_metrics", []),
                        "match_type": advisory.get("match_type"),
                        "advisory_severity": severity,
                        "applicability_status": "verified" if advisory_verified else "candidate / unverified",
                        "verification_basis": advisory.get("verification_basis", ""),
                        "advisory_source": advisory.get("source"),
                        "reference": advisory.get("url"),
                    },
                    verified=advisory_verified,
                    verification_status="confirmed vulnerability evidence" if advisory_verified else "candidate / unverified",
                    likelihood=3 if advisory_verified else 1,
                    confidence=confidence,
                    cve=advisory.get("cve", ""),
                    cvss=advisory.get("cvss"),
                    remediation=advisory.get("remediation", "Review the vendor advisory and patch or upgrade if applicable."),
                    references=[advisory.get("url", "")] if advisory.get("url") else [],
                ))

            # Cleartext
            if port in CLEAR_TEXT_SERVICES:

                findings.append(
                    _finding(
                        title=(
                            f"Potential cleartext transport exposure: "
                            f"{service_name} on {display}"
                        ),
                        severity="medium",
                        category="network service",
                    description=(
                        f"TCP/{port} is reachable and commonly associated with {service_name}. "
                        "If the detected service uses cleartext transport, credentials or data may be exposed to observers on the path. "
                        "This is potential exposure, not evidence of an attack or a confirmed insecure configuration."
                    ),
                        evidence={
                            "source": (
                                "bounded TCP "
                                "connect check"
                            ),
                            "address": address,
                            "hostname": hostname,
                            "port": port,
                            "protocol": "tcp",
                            "service": service_name,
                            "state": "open",
                        },
                        verified=True,
                        remediation=(
                            "Disable the service if it is "
                            "not required or replace it "
                            "with an encrypted alternative."
                        ),
                    )
                )

            # SMB
            if port == 445:

                findings.append(
                    _finding(
                        title=(
                            f"SMB service reachable on "
                            f"{display}"
                        ),
                        severity="medium",
                        category="network service",
                        description=(
                            "TCP/445 is reachable within "
                            "the authorized assessment scope. "
                            "Reachability does not establish "
                            "a vulnerability."
                        ),
                        evidence={
                            "source": (
                                "bounded TCP "
                                "connect check"
                            ),
                            "address": address,
                            "hostname": hostname,
                            "port": 445,
                            "protocol": "tcp",
                            "service": "SMB",
                            "state": "open",
                        },
                        verified=True,
                        remediation=(
                            "Restrict SMB access to required "
                            "trusted networks and verify "
                            "patching and SMB configuration."
                        ),
                    )
                )

            # Sensitive service exposure
            if port in SENSITIVE_SERVICES:

                findings.append(
                    _finding(
                        title=(
                            f"Sensitive service reachable: "
                            f"{service_name} on {display}"
                        ),
                        severity="low",
                        category="network exposure",
                        description=(
                            f"TCP/{port} ({service_name}) is reachable within the authorized scope. "
                            "Depending on its configuration and access controls, it may expose administrative functions, data, or authentication interfaces. "
                            "Reachability alone does not establish unauthorized access or a vulnerability."
                        ),
                        evidence={
                            "source": (
                                "bounded TCP "
                                "connect check"
                            ),
                            "address": address,
                            "hostname": hostname,
                            "port": port,
                            "protocol": "tcp",
                            "service": service_name,
                            "state": "open",
                        },
                        verified=True,
                        remediation=(
                            "Restrict access to trusted "
                            "management hosts or networks. "
                            "Verify authentication, encryption, "
                            "patching, and service configuration."
                        ),
                    )
                )

        # -----------------------------------------------------------
        # UDP services
        # -----------------------------------------------------------

        for service in host.get(
            "udp_services",
            [],
        ):
            udp_state = service.get("state", "open|filtered")
            udp_status = "Open" if udp_state in ("open", "open|responding") else "Open or Filtered (UDP)"
            protocol_verified = udp_state in ("open", "open|responding")
            udp_port = service.get("port")
            udp_name = str(service.get("service") or "unknown")
            udp_exposure = {
                53: "If this is DNS, its query surface or naming information may be exposed, depending on server configuration.",
                69: "If this is TFTP, file transfer may lack authentication and encryption.",
                123: "If this is NTP, the service may expose information or consume resources if misconfigured.",
                161: "If this is SNMP, device information may be exposed depending on version and access controls.",
                1900: "If this is SSDP, device discovery information may be exposed to network peers.",
            }.get(udp_port, "If a UDP service is present, it may expand the reachable network attack surface; its role and access controls are not confirmed by this probe.")

            findings.append(
                _finding(
                    title=(
                        f"UDP port observation: {udp_name} candidate "
                        f"on {address}:{udp_port}"
                    ),
                    severity="info",
                    category="network discovery",
                    description=(
                        f"The UDP probe reports {udp_status} for UDP/{udp_port}. "
                        f"The service label {udp_name} is a candidate unless protocol-specific evidence confirms it. {udp_exposure} "
                        "This is potential exposure only; the probe does not establish a vulnerability or successful attack."
                    ),
                    evidence={
                        "source": (
                            "conservative UDP probe"
                        ),
                        "address": address,
                        "hostname": hostname,
                        "port": udp_port,
                        "protocol": "udp",
                        "service": service.get(
                            "service"
                        ),
                        "state": udp_state,
                        "status": udp_status,
                    },
                    verified=protocol_verified,
                    confidence="low",
                    verification_status="confirmed observation" if protocol_verified else "candidate / unverified",
                    remediation=(
                        "Confirm whether the UDP service is required and restrict access where appropriate."
                    ),
                    status=udp_status,
                )
            )

    return findings


def _network_risk_summary(hosts: list[dict[str, Any]], services: list[dict[str, Any]], findings: list[dict[str, Any]], requested: int, discovery_status: str = "completed") -> dict[str, Any]:
    """Keep per-asset risk visible while offering a deterministic scope rollup."""
    per_asset: dict[str, dict[str, Any]] = {}
    for finding in findings:
        address = str(finding.get("target_ip") or (finding.get("evidence") or {}).get("address") or "")
        if not address:
            continue
        asset = per_asset.setdefault(address, {"address": address, "hostname": finding.get("hostname") or (finding.get("evidence") or {}).get("hostname", ""), "risk_score": 0.0, "finding_count": 0})
        calculated = risk_engine.calculate_finding_risk(finding)
        asset["risk_score"] += float(calculated.get("risk_score", 0) or 0)
        asset["finding_count"] += 1
    assets = sorted(({**item, "risk_score": round(item["risk_score"], 1)} for item in per_asset.values()), key=lambda item: (-item["risk_score"], item["address"]))
    service_counts: dict[str, int] = {}
    for service in services:
        name = str(service.get("service") or "unknown").strip().lower()
        if name and name != "unknown":
            service_counts[name] = service_counts.get(name, 0) + 1
    most_exposed = sorted(({"service": name, "count": count} for name, count in service_counts.items()), key=lambda item: (-item["count"], item["service"]))[:10]
    counts = {name: sum(1 for finding in findings if str(finding.get("severity", "info")).lower() == name) for name in SEVERITIES}
    if any("reachability" in host for host in hosts):
        reachable = sum(1 for host in hosts if host.get("reachability") == "reachable")
    else:
        reachable = sum(1 for host in hosts if host.get("alive"))
    confirmed_ports = [service for service in services if str(service.get("protocol", "tcp")).lower() != "udp" or str(service.get("state", "")).lower() in ("open", "open|responding")]
    uncertain_udp = sum(1 for service in services if str(service.get("protocol", "")).lower() == "udp" and str(service.get("state", "")).lower() not in ("open", "open|responding"))
    return {
        "hosts_requested": requested,
        "hosts_discovered": reachable,
        "hosts_reachable": reachable,
        "hosts_uncertain": max(0, requested - reachable),
        "exposed_ports": len(confirmed_ports),
        "udp_candidates_unverified": uncertain_udp,
        "services_identified": sum(1 for service in services if str(service.get("service") or "unknown").lower() != "unknown" and service.get("service_verification_status") == "confirmed"),
        "severity_counts": counts,
        "total_sentinel_risk": round(sum(item["risk_score"] for item in assets), 1),
        "highest_risk_assets": assets[:5],
        "asset_risks": assets,
        "most_exposed_services": most_exposed,
        "discovery_status": discovery_status,
    }


# ============================================================================
# NETWORK ASSESSMENT
# ============================================================================

def network_assessment(
    target: str,
    authorized: bool,
    public_authorized: bool = False,
    progress_callback=None,
    cancelled=None,
) -> dict[str, Any]:
    """
    Perform an explicitly authorized and bounded IPv4 network assessment.
    """

    started = _utc_now()

    network = validate_scope(
        target,
        authorized,
        public_authorized,
    )

    # For a single authorized IPv4 target, prefer Nmap for full TCP/service/CPE
    # detection. Keep the existing bounded socket engine as a fallback and for
    # private network scopes where a full 65,535-port scan per host would be
    # unnecessarily expensive.
    if network.num_addresses == 1 and nmap_scanner.find_nmap():
        if progress_callback:
            progress_callback(5, "Nmap reachability discovery starting")
        discovery_warning = ""
        discovered_single = False
        try:
            discovery_result = nmap_scanner.discover(str(network))
            discovered_single = any(h.get("address") == str(network.network_address) for h in discovery_result.get("hosts", []))
            discovery_status = "completed"
        except RuntimeError as exc:
            discovery_status = "partial"
            discovery_warning = f"Host reachability discovery was incomplete: {exc}"
        if progress_callback:
            progress_callback(15, "Nmap detailed single-host assessment starting")
        try:
            nmap_result = nmap_scanner.scan(str(network.network_address), full_tcp=None, udp_top=100)
        except RuntimeError as exc:
            # A phase failure should produce a partial assessment record, not
            # turn missing evidence into a clean result or discard scope.
            nmap_result = {"hosts": [], "warnings": [f"Nmap assessment was incomplete: {exc}"], "tcp_scope": "incomplete", "udp_scope": "not completed", "phase_status": {"tcp": "partial", "udp": "not_started"}}
        hosts = nmap_result.get("hosts", [])
        for host in hosts:
            tcp_open = bool(host.get("open_ports"))
            udp_responded = any(service.get("state") in ("open", "open|responding") for service in host.get("udp_services", []))
            host["reachability"] = "reachable" if discovered_single or tcp_open or udp_responded else "discovery_uncertain"
            host.setdefault("device_type", "Unknown / Unverified")
            host.setdefault("scan_coverage", dict(nmap_result.get("phase_status", {})))
        raw_findings = _network_findings(hosts)
        findings = correlate_findings(raw_findings)
        services = []
        udp_services = []
        for host in hosts:
            for service in host.get("open_ports", []):
                item = dict(service); item["address"] = host["address"]; item["hostname"] = host.get("hostname", ""); services.append(item)
            for service in host.get("udp_services", []):
                item = dict(service); item["address"] = host["address"]; item["hostname"] = host.get("hostname", ""); udp_services.append(item)
        severity_counts = {severity: 0 for severity in SEVERITIES}
        for finding in findings:
            if finding.get("severity") in severity_counts:
                severity_counts[finding["severity"]] += 1
        network_summary = _network_risk_summary(hosts, services + udp_services, findings, 1)
        warnings = list(nmap_result.get("warnings", []))
        if discovery_warning:
            warnings.append(discovery_warning)
        if progress_callback:
            progress_callback(100, "Nmap assessment completed")
        return {
            "assessment": {"id": _assessment_id("NETWORK"), "type": "network", "started_at": started, "completed_at": _utc_now(), "authorized": bool(authorized), "public_authorized": bool(public_authorized), "read_only": True, "engine": "nmap"},
            "scope": str(network),
            "scope_details": {"hosts_requested": 1, "hosts_responding": network_summary["hosts_reachable"], "hosts_uncertain": network_summary["hosts_uncertain"], "engine": "nmap", "nmap_version": nmap_result.get("nmap_version", ""), "scan_timestamp": nmap_result.get("scan_timestamp"), "scan_method": nmap_result.get("scan_method"), "tcp_scope": nmap_result.get("tcp_scope", "all TCP ports"), "udp_scope": nmap_result.get("udp_scope", "top 100 UDP ports"), "phase_status": {**nmap_result.get("phase_status", {}), "discovery": discovery_status}, "warnings": warnings},
            "hosts": hosts, "services": services, "udp_services": udp_services, "findings": findings,
            "network_summary": network_summary,
            "raw_finding_count": len(raw_findings), "finding_count": len(findings),
            "verified_findings": sum(1 for f in findings if f.get("verified")),
            "candidate_findings": sum(1 for f in findings if not f.get("verified")),
            "severity_counts": severity_counts,
        }

    # A network assessment uses a cheap host-discovery pass first, then runs
    # detailed checks only against hosts that answered. Every address with no
    # response remains visible as uncertain in the returned coverage data.
    if network.num_addresses > 1 and nmap_scanner.find_nmap():
        if progress_callback:
            progress_callback(5, "Nmap host discovery starting")
        warnings: list[str] = []
        discovery_status = "completed"
        discovery_observations: list[dict[str, Any]] = []
        try:
            discovery = nmap_scanner.discover(str(network))
            discovered = discovery.get("hosts", [])
            discovery_observations = discovery.get("observations", [])
        except RuntimeError as exc:
            discovered = []
            discovery_status = "partial"
            warnings.append(f"Host discovery was incomplete: {exc}")
        warnings.extend(discovery.get("warnings", []) if discovery_status == "completed" else [])
        discovered_by_ip = {}
        for host in discovered:
            address = host.get("address", "")
            try:
                if address and ipaddress.ip_address(address) in network:
                    discovered_by_ip[address] = host
            except ValueError:
                continue
        observed_by_ip = {item.get("address"): item for item in discovery_observations if item.get("address")}
        all_addresses = [str(ip) for ip in network]
        host_records = []
        for address in all_addresses:
            if address in discovered_by_ip:
                host_records.append({**discovered_by_ip[address], "reachability": "reachable", "device_type": "Unknown / Unverified", "scan_coverage": {"discovery": "completed", "tcp": "pending", "udp": "pending"}})
            else:
                observation = observed_by_ip.get(address, {})
                reachability = observation.get("reachability", "discovery_uncertain" if discovery_status != "completed" else "no_response")
                host_records.append({"address": address, "hostname": "", "alive": False, "reachability": reachability, "discovery_state": observation.get("discovery_state", "unknown"), "discovery_reason": observation.get("discovery_reason", ""), "device_type": "Unknown / Unverified", "open_ports": [], "udp_services": [], "scan_coverage": {"discovery": discovery_status, "tcp": "not_scanned", "udp": "not_scanned"}})
        active_addresses = list(discovered_by_ip)
        if progress_callback:
            progress_callback(20, f"Host discovery found {len(active_addresses)} responsive address(es)")

        def assess_one(address: str) -> tuple[str, dict[str, Any] | None, str | None]:
            if cancelled and cancelled():
                return address, None, "cancelled"
            try:
                result = nmap_scanner.scan(address, full_tcp=False, udp_top=30)
                parsed_hosts = result.get("hosts", [])
                record = next((item for item in parsed_hosts if item.get("address") == address), None)
                if record is None:
                    record = {"address": address, "hostname": "", "alive": True, "open_ports": [], "udp_services": []}
                record["reachability"] = "reachable"
                record["device_type"] = "Unknown / Unverified"
                record["scan_coverage"] = result.get("phase_status", {"tcp": "completed", "udp": "unknown"})
                record["scan_method"] = result.get("scan_method", "nmap")
                record["warnings"] = result.get("warnings", [])
                return address, record, None
            except RuntimeError as exc:
                return address, {"address": address, "hostname": "", "alive": True, "reachability": "reachable", "device_type": "Unknown / Unverified", "open_ports": [], "udp_services": [], "scan_coverage": {"tcp": "partial", "udp": "partial"}}, str(exc)

        max_workers = min(8, max(1, len(active_addresses)))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(assess_one, address) for address in active_addresses]
            done_count = 0
            for future in futures:
                if cancelled and cancelled():
                    raise RuntimeError("Assessment cancelled")
                address, detail, error = future.result()
                done_count += 1
                if detail is not None:
                    host_records[all_addresses.index(address)] = detail
                if error:
                    warnings.append(f"Detailed assessment of {address} was incomplete: {error}")
                if progress_callback:
                    progress_callback(20 + int(done_count / max(1, len(futures)) * 65), f"Detailed assessment · {done_count}/{len(futures)} responsive hosts")

        assessed_hosts = [h for h in host_records if h.get("reachability") == "reachable"]
        raw_findings = _network_findings(assessed_hosts)
        findings = correlate_findings(raw_findings)
        services, udp_services = [], []
        for host in assessed_hosts:
            for service in host.get("open_ports", []):
                services.append({**service, "address": host["address"], "hostname": host.get("hostname", "")})
            for service in host.get("udp_services", []):
                udp_services.append({**service, "address": host["address"], "hostname": host.get("hostname", "")})
        severity_counts = {severity: 0 for severity in SEVERITIES}
        for finding in findings:
            if finding.get("severity") in severity_counts:
                severity_counts[finding["severity"]] += 1
        if progress_callback:
            progress_callback(100, "Network assessment completed")
        return {
            "assessment": {"id": _assessment_id("NETWORK"), "type": "network", "started_at": started, "completed_at": _utc_now(), "authorized": bool(authorized), "public_authorized": bool(public_authorized), "read_only": True, "engine": "nmap"},
            "scope": str(network),
            "scope_details": {"network": str(network), "address_count": network.num_addresses, "hosts_requested": network.num_addresses, "hosts_discovered": len(active_addresses), "hosts_assessed": len(assessed_hosts), "hosts_uncertain": sum(1 for h in host_records if h.get("reachability") != "reachable"), "engine": "nmap", "discovery_method": discovery.get("method", "nmap host discovery") if discovery_status == "completed" else "nmap host discovery", "discovery_status": discovery_status, "tcp_scope": "top 1000 TCP ports per discovered host", "udp_scope": "top 30 UDP ports per discovered host", "warnings": warnings},
            "hosts": host_records, "services": services, "udp_services": udp_services, "raw_findings": raw_findings, "findings": findings,
            "raw_finding_count": len(raw_findings), "finding_count": len(findings), "verified_findings": sum(1 for f in findings if f.get("verified")), "candidate_findings": sum(1 for f in findings if not f.get("verified")), "severity_counts": severity_counts,
            "network_summary": _network_risk_summary(host_records, services + udp_services, findings, network.num_addresses, discovery_status),
        }

    tcp_ports = tuple(
        sorted(
            COMMON_TCP_PORTS.keys()
        )
    )

    udp_ports = tuple(
        sorted(
            COMMON_UDP_PORTS.keys()
        )
    )

    # ---------------------------------------------------------------
    # Address list
    # ---------------------------------------------------------------

    if network.num_addresses == 1:

        addresses = [
            network.network_address
        ]

    else:

        addresses = list(
            network.hosts()
        )

    # ---------------------------------------------------------------
    # TCP discovery
    # ---------------------------------------------------------------

    hosts: list[
        dict[str, Any]
    ] = []

    workers = min(
        32,
        max(
            1,
            len(addresses),
        ),
    )

    if network.num_addresses == 1:
        # A selected single IP always receives a detailed assessment, even if
        # the initial reachability probes receive no response.
        with ThreadPoolExecutor(max_workers=1) as executor:
            result = executor.submit(_scan_tcp_host, str(addresses[0]), tcp_ports, cancelled).result()
        result.setdefault("reachability", "reachable" if result.get("alive") else "discovery_uncertain")
        result.setdefault("udp_services", [])
        hosts = [result]
    else:
        # Fallback to a lightweight discovery stage, then spend detailed TCP
        # and UDP probes only on hosts that answered one of the bounded probes.
        with ThreadPoolExecutor(max_workers=workers) as executor:
            discoveries = list(executor.map(lambda address: _discover_tcp_host(str(address), cancelled), addresses))
        responsive = [item for item in discoveries if item.get("alive")]
        details: dict[str, dict[str, Any]] = {}
        with ThreadPoolExecutor(max_workers=min(16, max(1, len(responsive)))) as executor:
            futures = {executor.submit(_scan_tcp_host, item["address"], tcp_ports, cancelled, item): item["address"] for item in responsive}
            completed = 0
            for future in as_completed(futures):
                if cancelled and cancelled():
                    for pending in futures:
                        pending.cancel()
                    raise RuntimeError("Assessment cancelled")
                address = futures[future]
                details[address] = future.result()
                completed += 1
                if progress_callback:
                    progress_callback(30 + int(completed / max(1, len(responsive)) * 50), f"Detailed TCP assessment · {completed}/{len(responsive)} responsive hosts")
        hosts = []
        for discovery in discoveries:
            record = details.get(discovery["address"], discovery)
            record.setdefault("udp_services", [])
            hosts.append(record)
        if progress_callback:
            progress_callback(25, f"Host discovery found {len(responsive)} responsive address(es)")

    # ---------------------------------------------------------------
    # UDP discovery
    # ---------------------------------------------------------------

    reachable_hosts = [host for host in hosts if host.get("reachability") == "reachable" or ("reachability" not in host and host.get("alive"))]
    for index,host in enumerate(reachable_hosts):

        if cancelled and cancelled(): raise RuntimeError("Assessment cancelled")

        host["udp_services"] = (
            _scan_udp_host(
                host["address"],
                udp_ports,
                cancelled,
            )
        )
        if progress_callback: progress_callback(80+int((index+1)/max(1,len(hosts))*15),f"UDP checks · {index+1}/{len(hosts)} responsive hosts")

    # ---------------------------------------------------------------
    # Findings & Correlation
    # ---------------------------------------------------------------

    raw_findings = _network_findings(reachable_hosts)

    findings = correlate_findings(
        raw_findings
    )

    # ---------------------------------------------------------------
    # Flatten TCP / UDP services
    # ---------------------------------------------------------------

    services = []
    udp_services = []

    for host in reachable_hosts:

        for service in host.get(
            "open_ports",
            [],
        ):

            item = dict(
                service
            )

            item["address"] = (
                host["address"]
            )

            item["hostname"] = (
                host["hostname"]
            )

            services.append(
                item
            )

        for service in host.get(
            "udp_services",
            [],
        ):

            item = dict(
                service
            )

            item["address"] = (
                host["address"]
            )

            item["hostname"] = (
                host["hostname"]
            )

            udp_services.append(
                item
            )

    # ---------------------------------------------------------------
    # Severity counts
    # ---------------------------------------------------------------

    severity_counts = {
        severity: 0
        for severity in SEVERITIES
    }

    for finding in findings:

        severity = finding.get(
            "severity",
            "info",
        )

        if severity in severity_counts:

            severity_counts[
                severity
            ] += 1

    network_summary = _network_risk_summary(hosts, services + udp_services, findings, len(addresses))

    return {
        "assessment": {
            "id": _assessment_id(
                "NETWORK"
            ),
            "type": "network",
            "started_at": started,
            "completed_at": _utc_now(),
            "authorized": bool(
                authorized
            ),
            "read_only": True,
        },
        "scope": str(
            network
        ),
        "scope_details": {
            "network": str(
                network.network_address
            ),
            "prefix_length": network.prefixlen,
            "broadcast": str(
                network.broadcast_address
            ),
            "address_count": network.num_addresses,
        },
        "hosts": hosts,
        "services": services,
        "udp_services": udp_services,
        "network_summary": network_summary,
        "raw_findings": raw_findings,
        "raw_observations": raw_findings,
        "findings": findings,
        "ports_checked": {
            "tcp": list(
                tcp_ports
            ),
            "udp": list(
                udp_ports
            ),
        },
        "summary": {
            "addresses_checked": len(
                addresses
            ),
            "hosts_discovered": len(
                reachable_hosts
            ),
            "reachability": {
                "method": "bounded TCP connect probes",
                "icmp_used": False,
                "targets_with_tcp_response": len(reachable_hosts),
                "note": (
                    "TCP responses were observed on tested ports."
                    if reachable_hosts
                    else "No TCP response was observed on tested ports. This does not prove the target is offline; a host firewall or hotspot client isolation may block peer traffic. ICMP ping is not used."
                ),
            },
            "tcp_services": len(
                services
            ),
            "udp_services": len(
                udp_services
            ),
            "raw_finding_count": len(
                raw_findings
            ),
            "finding_count": len(
                findings
            ),
            "verified_findings": sum(
                1
                for finding in findings
                if finding.get(
                    "verified"
                )
            ),
            "candidate_findings": sum(
                1
                for finding in findings
                if not finding.get(
                    "verified"
                )
            ),
            "severity_counts": severity_counts,
        },
    }


# ============================================================================
# UNIFIED ASSESSMENT
# ============================================================================

def run_assessment(
    target: str | None = None,
    authorized: bool = False,
    include_local: bool = True,
    include_network: bool = True,
) -> dict[str, Any]:
    """
    Unified assessment controller.

    This gives future API versions a single entry point.
    """

    started = _utc_now()

    result: dict[str, Any] = {
        "assessment": {
            "id": _assessment_id(),
            "type": "combined",
            "started_at": started,
            "completed_at": None,
            "authorized": bool(
                authorized
            ),
            "read_only": True,
        },
        "local": None,
        "network": None,
        "findings": [],
        "summary": {},
    }

    # ---------------------------------------------------------------
    # Local
    # ---------------------------------------------------------------

    if include_local:

        try:

            result["local"] = (
                local_assessment()
            )

            result["findings"].extend(
                result["local"].get(
                    "findings",
                    [],
                )
            )

        except Exception as exc:

            result["findings"].append(
                _finding(
                    title=(
                        "Local assessment "
                        "collection error"
                    ),
                    severity="low",
                    category="assessment",
                    description=(
                        "The local assessment "
                        "could not complete successfully."
                    ),
                    evidence={
                        "error": _safe_text(
                            exc,
                            1000,
                        )
                    },
                    verified=True,
                    remediation=(
                        "Review the assessment error "
                        "and verify that the application "
                        "has the required read-only permissions."
                    ),
                )
            )

    # ---------------------------------------------------------------
    # Network
    # ---------------------------------------------------------------

    if (
        include_network
        and target
    ):

        try:

            result["network"] = (
                network_assessment(
                    target,
                    authorized,
                )
            )

            result["findings"].extend(
                result["network"].get(
                    "findings",
                    [],
                )
            )

        except Exception as exc:

            result["network"] = {
                "error": _safe_text(
                    exc,
                    1000,
                )
            }

            result["findings"].append(
                _finding(
                    title=(
                        "Network assessment "
                        "error"
                    ),
                    severity="low",
                    category="assessment",
                    description=(
                        "The network assessment "
                        "could not complete successfully."
                    ),
                    evidence={
                        "target": target,
                        "error": _safe_text(
                            exc,
                            1000,
                        ),
                    },
                    verified=True,
                    remediation=(
                        "Verify authorization, target scope, "
                        "network reachability, and local "
                        "networking permissions."
                    ),
                )
            )

    # ---------------------------------------------------------------
    # Global summary & correlation
    # ---------------------------------------------------------------

    raw_findings = list(result["findings"])
    result["raw_findings"] = raw_findings
    result["raw_observations"] = raw_findings
    result["findings"] = correlate_findings(raw_findings)

    severity_counts = {
        severity: 0
        for severity in SEVERITIES
    }

    category_counts: dict[
        str,
        int,
    ] = {}

    verified = 0
    candidates = 0

    for finding in result[
        "findings"
    ]:

        severity = finding.get(
            "severity",
            "info",
        )

        if severity in severity_counts:

            severity_counts[
                severity
            ] += 1

        category = finding.get(
            "category",
            "other",
        )

        category_counts[
            category
        ] = (
            category_counts.get(
                category,
                0,
            )
            + 1
        )

        if finding.get(
            "verified"
        ):
            verified += 1
        else:
            candidates += 1

    result["summary"] = {
        "raw_finding_count": len(
            raw_findings
        ),
        "finding_count": len(
            result["findings"]
        ),
        "verified_findings": verified,
        "candidate_findings": candidates,
        "severity_counts": severity_counts,
        "category_counts": category_counts,
    }

    result["assessment"][
        "completed_at"
    ] = _utc_now()

    return result


# ============================================================================
# COMPATIBILITY FUNCTIONS
# ============================================================================

def assess_local() -> dict[str, Any]:
    """
    Backward-compatible local assessment alias.
    """

    return local_assessment()


def assess_network(
    target: str,
    authorized: bool,
) -> dict[str, Any]:
    """
    Backward-compatible network assessment alias.
    """

    return network_assessment(
        target,
        authorized,
    )


# ============================================================================
# PUBLIC API
# ============================================================================

__all__ = [
    "COMMON_TCP_PORTS",
    "COMMON_UDP_PORTS",
    "CLEAR_TEXT_SERVICES",
    "SENSITIVE_SERVICES",
    "local_assessment",
    "network_assessment",
    "run_assessment",
    "validate_scope",
    "assess_local",
    "assess_network",
]
