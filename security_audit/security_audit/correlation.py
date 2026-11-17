"""
Sentinel Audit Finding Correlation and Deduplication Engine
=============================================================

This module provides a correlation and deduplication layer for security findings.
It distinguishes raw scanner observations from correlated security findings,
ensuring professional, accurate, and GRC-friendly reporting without double-counting risk.

Core Principles:
1. Deduplicate/correlate overlapping findings for the same target IP, port, protocol, and service.
2. Distinct ports remain separate technical findings (e.g. 135, 139, 445).
3. Severity escalation: Critical > High > Medium > Low > Info (never downgrade).
4. Risk score: maximum relevant risk score (no double counting).
5. Evidence preservation: structured correlated_evidence with duplicate removal.
6. Service grouping for presentation without loss of port-level evidence.
7. Clear distinction between service reachability and confirmed vulnerabilities.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from . import risk


# Severity ranking
SEVERITY_ORDER: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

SEVERITY_FROM_ORDER: dict[int, str] = {
    5: "critical",
    4: "high",
    3: "medium",
    2: "low",
    1: "info",
}

# Known service normalization map
SERVICE_ALIASES: dict[str, str] = {
    # SMB / Windows Networking
    "microsoft-ds": "smb",
    "microsoft ds": "smb",
    "cifs": "smb",
    "smb service": "smb",
    "smb-service": "smb",
    "smb": "smb",
    # MS-RPC
    "msrpc": "ms-rpc",
    "ms-rpc": "ms-rpc",
    "rpc": "ms-rpc",
    "dcerpc": "ms-rpc",
    "dce-rpc": "ms-rpc",
    "microsoft rpc": "ms-rpc",
    "endpoint mapper": "ms-rpc",
    # NetBIOS
    "netbios": "netbios",
    "netbios-ssn": "netbios",
    "netbios-ns": "netbios-ns",
    "netbios-dgm": "netbios-dgm",
    # Databases
    "mysql": "mysql",
    "mariadb": "mysql",
    "mssql": "mssql",
    "ms-sql": "mssql",
    "ms-sql-s": "mssql",
    "microsoft sql server": "mssql",
    "oracle": "oracle",
    "oracle tns": "oracle",
    "oracle-tns": "oracle",
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "redis": "redis",
    "elasticsearch": "elasticsearch",
    # Web
    "http": "http",
    "http-alt": "http",
    "http-proxy": "http",
    "www": "http",
    "https": "https",
    "https-alt": "https",
    "ssl/http": "https",
    # Remote Access
    "ssh": "ssh",
    "openssh": "ssh",
    "secure shell": "ssh",
    "telnet": "telnet",
    "rdp": "rdp",
    "remote desktop": "rdp",
    "ms-wbt-server": "rdp",
    "vnc": "vnc",
    # File Transfer
    "ftp": "ftp",
    "tftp": "tftp",
    "nfs": "nfs",
    # Mail
    "smtp": "smtp",
    "smtp submission": "smtp",
    "smtps": "smtps",
    "pop3": "pop3",
    "imap": "imap",
    # Directory & Network
    "dns": "dns",
    "domain": "dns",
    "dhcp": "dhcp",
    "ntp": "ntp",
    "snmp": "snmp",
    "snmp-trap": "snmp-trap",
    "ldap": "ldap",
    "ldaps": "ldaps",
    "openvpn": "openvpn",
    "ike": "ike",
    "ipsec": "ipsec",
    "ipsec nat-t": "ipsec",
    "ssdp": "ssdp",
    "syslog": "syslog",
}

# Service presentation groups (Requirement 6)
SERVICE_GROUPS: dict[int, str] = {
    135: "Windows File & Network Services",
    137: "Windows File & Network Services",
    138: "Windows File & Network Services",
    139: "Windows File & Network Services",
    445: "Windows File & Network Services",
    80: "Web & Application Services",
    443: "Web & Application Services",
    8080: "Web & Application Services",
    8443: "Web & Application Services",
    1433: "Database & Storage Services",
    1521: "Database & Storage Services",
    3306: "Database & Storage Services",
    5432: "Database & Storage Services",
    6379: "Database & Storage Services",
    9200: "Database & Storage Services",
    22: "Remote Administration & Shells",
    23: "Remote Administration & Shells",
    3389: "Remote Administration & Shells",
    5900: "Remote Administration & Shells",
    21: "File Transfer & Storage Services",
    69: "File Transfer & Storage Services",
    2049: "File Transfer & Storage Services",
    25: "Mail Services",
    110: "Mail Services",
    143: "Mail Services",
    465: "Mail Services",
    587: "Mail Services",
    53: "Name & Directory Services",
    389: "Name & Directory Services",
    636: "Name & Directory Services",
    67: "Network Infrastructure Services",
    68: "Network Infrastructure Services",
    123: "Network Infrastructure Services",
    161: "Network Infrastructure Services",
    162: "Network Infrastructure Services",
}


def normalize_service_name(service: Any) -> str:
    """
    Normalize service names so equivalent designations (e.g. SMB, Microsoft-DS,
    CIFS, SMB service) map to the same normalized technical identifier.
    """
    if not service:
        return "unknown"
    s = str(service).strip().lower()
    # Strip common suffixes like 'service', 'server', 'daemon', 'protocol'
    cleaned = re.sub(r"\s+(service|server|daemon|protocol)$", "", s).strip()
    return SERVICE_ALIASES.get(cleaned, SERVICE_ALIASES.get(s, cleaned or "unknown"))


def get_service_group(port: int | None, service: str | None = None) -> str:
    """
    Return a presentation category for grouping related services without
    merging their underlying port-level technical findings.
    """
    if port and port in SERVICE_GROUPS:
        return SERVICE_GROUPS[port]
    norm = normalize_service_name(service or "")
    if norm in ("smb", "ms-rpc", "netbios", "netbios-ns", "netbios-dgm"):
        return "Windows File & Network Services"
    if norm in ("mysql", "mssql", "oracle", "postgresql", "redis", "elasticsearch"):
        return "Database & Storage Services"
    if norm in ("ssh", "rdp", "vnc", "telnet"):
        return "Remote Administration & Shells"
    if norm in ("http", "https"):
        return "Web & Application Services"
    if norm in ("ftp", "tftp", "nfs"):
        return "File Transfer & Storage Services"
    if norm in ("smtp", "smtps", "pop3", "imap"):
        return "Mail Services"
    if norm in ("dns", "ldap", "ldaps"):
        return "Name & Directory Services"
    return "Other Services"


def extract_finding_target_info(finding: dict[str, Any]) -> dict[str, Any]:
    """
    Extract target IP, hostname, port, protocol, and service name from a finding
    or its evidence record.
    """
    ev = finding.get("evidence")
    if not isinstance(ev, dict):
        ev = {}

    title = str(finding.get("title", ""))

    # 1. Address / IP
    address = (
        finding.get("target_ip")
        or finding.get("address")
        or ev.get("address")
        or ev.get("target_ip")
        or ev.get("target")
        or ""
    )
    if not address and "on " in title:
        m = re.search(r"on\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", title)
        if m:
            address = m.group(1)

    # 2. Hostname
    hostname = (
        finding.get("hostname")
        or ev.get("hostname")
        or ""
    )
    if not hostname and "(" in title:
        m = re.search(r"\(([^)]+)\)", title)
        if m:
            hostname = m.group(1)

    # 3. Port
    port = finding.get("port")
    if port is None:
        port = ev.get("port")
    if port is None:
        # Check title like :445 or 445/TCP
        m = re.search(r":(\d+)\b", title) or re.search(r"\b(\d+)/(?:tcp|udp)\b", title, re.IGNORECASE)
        if m:
            port = int(m.group(1))
    elif port is not None:
        try:
            port = int(port)
        except (ValueError, TypeError):
            pass

    # 4. Protocol
    protocol = finding.get("protocol") or ev.get("protocol")
    if not protocol:
        if "udp" in str(finding.get("category", "")).lower() or "/udp" in title.lower():
            protocol = "udp"
        else:
            protocol = "tcp"
    protocol = str(protocol).lower()

    # 5. Service
    service = finding.get("service") or ev.get("service") or ""
    if not service:
        # Check port in known ports
        if port == 445:
            service = "SMB"
        elif port == 135:
            service = "MS-RPC"
        elif port == 139:
            service = "NetBIOS"
        elif port == 3306:
            service = "MySQL"
        elif port == 1521:
            service = "Oracle"
        elif port == 1433:
            service = "MSSQL"
        elif port == 5432:
            service = "PostgreSQL"
        elif port == 3389:
            service = "RDP"
        elif port == 22:
            service = "SSH"
        elif port == 21:
            service = "FTP"
        elif port == 23:
            service = "Telnet"
        elif port == 80:
            service = "HTTP"
        elif port == 443:
            service = "HTTPS"
        else:
            # Check title for common names
            for name in ("SMB", "RPC", "NetBIOS", "MySQL", "Oracle", "MSSQL", "PostgreSQL", "RDP", "SSH", "FTP", "Telnet", "HTTP", "HTTPS", "DNS", "Redis", "VNC"):
                if re.search(rf"\b{name}\b", title, re.IGNORECASE):
                    service = name
                    break

    return {
        "address": str(address).strip(),
        "hostname": str(hostname).strip(),
        "port": port,
        "protocol": protocol,
        "service": str(service).strip(),
    }


def compute_correlation_key(finding: dict[str, Any]) -> str:
    """
    Generate a deterministic logical fingerprint.
    Network services: target_ip + port + protocol + normalized_service_name (+ cve if applicable).
    Host-level: address/local + category + normalized title.
    """
    info = extract_finding_target_info(finding)
    address = info["address"]
    port = info["port"]
    protocol = info["protocol"]
    normalized_service = normalize_service_name(info["service"])

    # If there is a specific CVE candidate, keep CVE in fingerprint so reachability
    # is never conflated with confirmed/candidate CVE vulnerabilities.
    cve = str(
        finding.get("cve")
        or (finding.get("evidence") or {}).get("cve", "")
        if isinstance(finding.get("evidence"), dict)
        else ""
    ).strip().upper()

    if address and port is not None:
        key = f"{address}:{port}/{protocol}:{normalized_service}"
        if cve:
            key += f":{cve}"
        return key

    # Non-port host or system checks
    category = str(finding.get("category", "configuration")).strip().lower()
    title = str(finding.get("title", "")).strip().lower()
    # Strip variable host info from title for fingerprinting if needed
    cleaned_title = re.sub(r"\s+on\s+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.*", "", title).strip()
    return f"{address or 'local'}:{category}:{cleaned_title}"


def deduplicate_evidence_records(evidence_list: list[Any]) -> list[Any]:
    """
    Deduplicate a list of evidence entries while preserving structure and order.
    """
    seen = set()
    result = []
    for item in evidence_list:
        if not item:
            continue
        try:
            # Normalize to JSON string for exact comparison
            serialized = json.dumps(item, sort_keys=True, default=str)
        except Exception:
            serialized = str(item)

        if serialized not in seen:
            seen.add(serialized)
            result.append(item)
    return result


def merge_findings_group(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Merge a group of overlapping findings with the same correlation fingerprint.
    Preserves highest severity, maximum relevant risk score, structured evidence,
    and correlation metadata.
    """
    if not findings:
        raise ValueError("Cannot merge empty findings group")

    if len(findings) == 1:
        single = dict(findings[0])
        info = extract_finding_target_info(single)
        key = compute_correlation_key(single)
        single.setdefault("correlation_key", key)
        single.setdefault("correlated_count", 1)
        single.setdefault("cve", "")
        if info["port"] is not None:
            single.setdefault("verification_status", "confirmed observation" if single.get("verified") else "candidate / unverified")
            single.setdefault("service_verification_status", (single.get("evidence") or {}).get("service_verification_status", "candidate / unverified"))
        if single.get("id"):
            single.setdefault("source_finding_ids", [single["id"]])
        if info["address"]:
            single.setdefault("target_ip", info["address"])
        if info["hostname"]:
            single.setdefault("hostname", info["hostname"])
        if info["port"] is not None:
            single.setdefault("port", info["port"])
            single.setdefault("protocol", info["protocol"])
            single.setdefault("service", info["service"])
            single.setdefault("service_group", get_service_group(info["port"], info["service"]))
            if info["protocol"] == "udp":
                st = str((single.get("evidence") or {}).get("state", "")).lower()
                if st not in ("open", "open|responding") and single.get("status") in ("open", "", "Open or Filtered (UDP)"):
                    single["status"] = "Open or Filtered (UDP)"
                    single["port_status"] = "Open or Filtered (UDP)"
                else:
                    single.setdefault("port_status", "Open")
            else:
                single.setdefault("port_status", "Open")
                single.setdefault("status", "open")
        return single

    # 1. Determine highest severity
    best_severity_val = max(
        SEVERITY_ORDER.get(str(f.get("severity", "info")).lower(), 1)
        for f in findings
    )
    final_severity = SEVERITY_FROM_ORDER.get(best_severity_val, "info")

    # 2. Risk Score: maximum relevant risk score (no double counting)
    calculated_scores = []
    for f in findings:
        if f.get("risk_score") is not None:
            try:
                calculated_scores.append(float(f["risk_score"]))
            except (ValueError, TypeError):
                pass
        else:
            sev = str(f.get("severity", "info")).lower()
            lik = f.get("likelihood", 3)
            imp = f.get("impact")
            calculated_scores.append(risk.score(sev, lik, imp)["score"])

    final_risk_score = round(max(calculated_scores) if calculated_scores else risk.score(final_severity, 3)["score"], 1)

    # 3. Maximum likelihood and impact
    max_likelihood = max(int(f.get("likelihood", 3)) for f in findings)
    max_impact = max(
        int(f.get("impact", risk.SEVERITY_SCORE.get(str(f.get("severity", "info")).lower(), 0)))
        for f in findings
    )

    # 4. Select primary finding (highest severity, highest risk, most specific title)
    def sort_key(f: dict[str, Any]) -> tuple:
        sev = SEVERITY_ORDER.get(str(f.get("severity", "info")).lower(), 1)
        r_score = float(f.get("risk_score", 0) or 0)
        # Prefer specific service title over generic "Sensitive service"
        t = str(f.get("title", ""))
        specific = 0 if t.startswith("Sensitive service reachable") else 1
        return (sev, r_score, specific)

    sorted_findings = sorted(findings, key=sort_key, reverse=True)
    primary = sorted_findings[0]

    # Target info from primary or any finding
    info = extract_finding_target_info(primary)
    for other in sorted_findings[1:]:
        other_info = extract_finding_target_info(other)
        if not info["address"] and other_info["address"]:
            info["address"] = other_info["address"]
        if not info["hostname"] and other_info["hostname"]:
            info["hostname"] = other_info["hostname"]
        if info["port"] is None and other_info["port"] is not None:
            info["port"] = other_info["port"]
        if not info["service"] and other_info["service"]:
            info["service"] = other_info["service"]

    # 5. Evidence collection and deduplication
    raw_ev_list = []
    assessment_id = None
    source = primary.get("evidence", {}).get("source") if isinstance(primary.get("evidence"), dict) else primary.get("source")

    for f in findings:
        ev = f.get("evidence")
        if isinstance(ev, dict):
            if "assessment_id" in ev and assessment_id is None:
                assessment_id = ev["assessment_id"]
            if "correlated_evidence" in ev and isinstance(ev["correlated_evidence"], list):
                raw_ev_list.extend(ev["correlated_evidence"])
            else:
                raw_ev_list.append(ev)
        elif ev:
            raw_ev_list.append({"details": str(ev)})

    deduped_evidence = deduplicate_evidence_records(raw_ev_list)

    # 6. Build correlation metadata
    corr_key = compute_correlation_key(primary)
    source_ids = [f["id"] for f in findings if f.get("id")]
    service_label = info["service"] or "service"

    corr_note = (
        f"This finding combines {len(findings)} overlapping scanner observations "
        f"for the same {service_label} exposure."
    )

    # Build composite evidence container
    final_evidence: dict[str, Any] = {
        "source": source or "security assessment engine",
        "correlation_key": corr_key,
        "correlated_count": len(findings),
        "source_finding_ids": source_ids,
        "correlated_evidence": deduped_evidence,
    }
    is_udp = info["protocol"] == "udp"
    raw_states = [
        str(f.get("evidence", {}).get("state", "")).lower()
        for f in findings
        if isinstance(f.get("evidence"), dict)
    ]
    if is_udp:
        if any(st in ("open", "open|responding") for st in raw_states):
            port_status = "Open"
            finding_status = primary.get("status", "open")
        else:
            port_status = "Open or Filtered (UDP)"
            finding_status = "Open or Filtered (UDP)"
    else:
        port_status = "Open"
        finding_status = primary.get("status", "open")

    if info["address"]:
        final_evidence["address"] = info["address"]
    if info["hostname"]:
        final_evidence["hostname"] = info["hostname"]
    if info["port"] is not None:
        final_evidence["port"] = info["port"]
        final_evidence["protocol"] = info["protocol"]
        final_evidence["service"] = info["service"]
        final_evidence["state"] = "open|filtered" if (is_udp and port_status != "Open") else "open"
        final_evidence["status"] = port_status
    if assessment_id is not None:
        final_evidence["assessment_id"] = assessment_id

    # Title: clean title preserving display
    merged_title = primary.get("title", "")
    # Check if primary title can be streamlined for professional report
    # If it was e.g. "SMB service reachable on 10.101.137.41 (DESKTOP-VR8A9R3)"
    # we keep it, but ensure it starts with the high severity context
    merged_desc = primary.get("description", "")
    merged_remediation = primary.get("remediation", "")
    category = primary.get("category", "network service")

    # If both SMB reachability and Sensitive service reachable, make sure reachability language is clean
    if info["port"] == 445 and "SMB" in info["service"].upper():
        if not merged_desc:
            merged_desc = (
                "TCP/445 is reachable within the authorized assessment scope. "
                "Reachability alone does not establish a vulnerability."
            )
        if not merged_remediation:
            merged_remediation = (
                "Restrict SMB access to required trusted networks and verify "
                "patching and SMB configuration."
            )

    merged: dict[str, Any] = {
        "id": primary.get("id", f"F-{corr_key}"),
        "title": merged_title,
        "severity": final_severity,
        "category": category,
        "likelihood": max_likelihood,
        "impact": max_impact,
        "risk_score": final_risk_score,
        "description": merged_desc,
        "remediation": merged_remediation,
        "evidence": final_evidence,
        "verified": any(f.get("verified") for f in findings),
        "verification_status": (
            "confirmed vulnerability evidence" if any(f.get("verification_status") == "confirmed vulnerability evidence" for f in findings)
            else "confirmed observation" if any(f.get("verification_status") == "confirmed observation" for f in findings)
            else "candidate / unverified"
        ),
        "service_verification_status": (
            "confirmed" if any((f.get("evidence") or {}).get("service_verification_status") == "confirmed" for f in findings if isinstance(f.get("evidence"), dict))
            else "candidate / unverified"
        ),
        "confidence": primary.get("confidence", "high"),
        "cve": primary.get("cve", ""),
        "cvss": max([f.get("cvss") for f in findings if f.get("cvss") is not None] or [None]),
        "references": primary.get("references", []),
        "status": finding_status,
        "port_status": port_status,
        # Top-level helper attributes for reports & UI
        "target_ip": info["address"],
        "hostname": info["hostname"],
        "port": info["port"],
        "protocol": info["protocol"],
        "service": info["service"],
        "service_group": get_service_group(info["port"], info["service"]),
        "correlation_key": corr_key,
        "correlated_count": len(findings),
        "source_finding_ids": source_ids,
        "correlation_note": corr_note,
    }

    # Pass through additional fields if present on primary
    for key in ("project_id", "assessment_id", "asset_id", "asset_criticality", "control_ids", "assignee", "due_date", "created_at", "updated_at", "asset_name"):
        if key in primary:
            merged[key] = primary[key]

    return merged


def correlate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Correlate a list of findings, merging duplicates and overlapping findings
    with the same fingerprint (target_ip + port + protocol + normalized_service_name).
    """
    if not findings:
        return []

    groups: dict[str, list[dict[str, Any]]] = {}
    order: list[str] = []

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        key = compute_correlation_key(finding)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(finding)

    correlated = []
    for key in order:
        group = groups[key]
        merged = merge_findings_group(group)
        correlated.append(merged)

    return correlated
