"""Safe Nmap integration for Sentinel Audit.

Read-only network discovery only. No NSE exploitation scripts are used.
Public targets must already have passed Sentinel Audit scope/authorization checks.
"""
from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
from datetime import datetime, timezone
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

DEFAULT_TIMEOUT = int(os.environ.get("NMAP_TIMEOUT", "900"))
TCP_TIMEOUT = int(os.environ.get("NMAP_TCP_TIMEOUT", str(min(DEFAULT_TIMEOUT, 180))))
UDP_TIMEOUT = int(os.environ.get("NMAP_UDP_TIMEOUT", str(min(DEFAULT_TIMEOUT, 45))))
DISCOVERY_TIMEOUT = int(os.environ.get("NMAP_DISCOVERY_TIMEOUT", "15"))


def find_nmap() -> str | None:
    configured = os.environ.get("NMAP_PATH", "").strip().strip('"')
    candidates = [configured] if configured else []
    candidates += [
        shutil.which("nmap"),
        r"C:\Program Files\Nmap\nmap.exe",
        r"C:\Program Files (x86)\Nmap\nmap.exe",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(candidate)
    return None


def version() -> str:
    path = find_nmap()
    if not path:
        return ""
    try:
        p = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=15)
        return (p.stdout or p.stderr).splitlines()[0].strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def _is_single_ipv4(target: str) -> bool:
    try:
        net = ipaddress.ip_network(target, strict=False)
        return net.version == 4 and net.num_addresses == 1
    except ValueError:
        return False


def _safe_text(value: str | None, limit: int = 512) -> str:
    return (value or "").strip()[:limit]


def _parse_host(host: ET.Element) -> dict[str, Any] | None:
    status = host.find("status")
    if status is not None and status.get("state") not in (None, "up"):
        return None

    address = ""
    for addr in host.findall("address"):
        if addr.get("addrtype") == "ipv4":
            address = addr.get("addr", "")
            break
    if not address:
        return None

    hostnames = []
    hn = host.find("hostnames")
    if hn is not None:
        hostnames = [x.get("name", "") for x in hn.findall("hostname") if x.get("name")]

    record: dict[str, Any] = {
        "address": address,
        "hostname": hostnames[0] if hostnames else "",
        "alive": True,
        "reachability": "reachable",
        "open_ports": [],
        "udp_services": [],
        "port_observations": [],
    }

    ports = host.find("ports")
    if ports is None:
        return record

    for port in ports.findall("port"):
        state = port.find("state")
        if state is None:
            continue
        state_name = state.get("state", "unknown").lower()
        protocol = port.get("protocol", "tcp")
        # Preserve ambiguous states. In particular, UDP open|filtered is not
        # equivalent to an open service and must remain a candidate observation.
        if state_name not in ("open", "open|filtered", "closed", "filtered"):
            continue
        try:
            number = int(port.get("portid", "0"))
        except ValueError:
            continue
        service = port.find("service")
        item: dict[str, Any] = {
            "port": number,
            "protocol": protocol,
            "state": state_name,
            "service": service.get("name", "unknown") if service is not None else "unknown",
            "product": _safe_text(service.get("product") if service is not None else ""),
            "version": _safe_text(service.get("version") if service is not None else ""),
            "extrainfo": _safe_text(service.get("extrainfo") if service is not None else ""),
            "cpe": [],
            "detection_method": "nmap -sV" if protocol == "tcp" else "nmap -sU",
        }
        record["port_observations"].append({"port": number, "protocol": protocol, "state": state_name, "evidence_source": "nmap XML", "scan_timestamp": None})
        if service is not None:
            item["cpe"] = list(dict.fromkeys(
                x.text.strip().lower() for x in service.findall("cpe")
                if x.text and x.text.strip().lower().startswith(("cpe:2.3:", "cpe:/"))
            ))
        item["cpe_source"] = "nmap" if item["cpe"] else "none"
        item["cpe_confidence"] = "high" if item["cpe"] else "none"
        item["scan_method"] = "nmap -sV --version-light"
        service_method = service.get("method", "") if service is not None else ""
        try:
            service_confidence = int(service.get("conf", "0")) if service is not None else 0
        except ValueError:
            service_confidence = 0
        item["verification_status"] = "confirmed observation" if state_name == "open" else "candidate / unverified"
        item["service_verification_status"] = "confirmed" if service_method == "probed" and service_confidence >= 8 else "candidate / unverified"
        item["service_confidence"] = service_confidence
        if state_name in ("closed", "filtered"):
            continue
        if protocol == "udp":
            record["udp_services"].append(item)
        else:
            record["open_ports"].append(item)
    return record


def _run_xml(args: list[str], timeout: int) -> ET.Element:
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Nmap scan timed out after {timeout} seconds") from exc
    except OSError as exc:
        raise RuntimeError(f"Unable to start Nmap: {exc}") from exc
    if proc.returncode not in (0, 1):
        detail = _safe_text(proc.stderr, 1000)
        raise RuntimeError(f"Nmap failed with exit code {proc.returncode}: {detail}")
    try:
        return ET.fromstring(proc.stdout or "")
    except ET.ParseError as exc:
        raise RuntimeError("Nmap returned invalid XML output") from exc


def scan(target: str, full_tcp: bool | None = None, udp_top: int = 100, timeout: int | None = None, udp_ports: list[int] | None = None) -> dict[str, Any]:
    """Run bounded, read-only TCP and UDP Nmap discovery for one IPv4 host."""
    path = find_nmap()
    if not path:
        raise RuntimeError("Nmap was not found. Install Nmap or set NMAP_PATH.")
    target = str(target).strip()
    if not target:
        raise ValueError("Nmap target cannot be empty")
    if not _is_single_ipv4(target):
        raise ValueError("Nmap integration currently requires a single IPv4 target")
    if full_tcp is None:
        full_tcp = os.environ.get("AUDIT_NMAP_FULL_TCP", "1").lower() in ("1", "true", "yes")
    tcp_timeout = timeout or TCP_TIMEOUT
    udp_timeout = timeout or UDP_TIMEOUT
    if udp_ports is None:
        configured_udp = os.environ.get("AUDIT_NMAP_UDP_PORTS", "").strip()
        if configured_udp:
            try:
                udp_ports = [int(part.strip()) for part in configured_udp.split(",") if part.strip()]
            except ValueError as exc:
                raise ValueError("AUDIT_NMAP_UDP_PORTS must be a comma-separated list of ports") from exc
    if udp_ports is not None:
        if not udp_ports or len(udp_ports) > 128 or any(not isinstance(p, int) or p < 1 or p > 65535 for p in udp_ports):
            raise ValueError("Custom UDP scans require 1-128 valid ports from 1 to 65535")
        udp_ports = sorted(set(udp_ports))
    else:
        try:
            udp_top = int(os.environ.get("AUDIT_NMAP_UDP_TOP", str(udp_top)))
        except ValueError as exc:
            raise ValueError("AUDIT_NMAP_UDP_TOP must be an integer") from exc
    scan_timestamp = datetime.now(timezone.utc).isoformat()

    tcp_ports = "-p-" if full_tcp else "--top-ports"
    tcp_args = [path, "-Pn", "-n", "-sV", "--version-light"]
    if tcp_ports == "-p-":
        tcp_args += ["-p-"]
    else:
        tcp_args += ["--top-ports", "1000"]
    tcp_args += ["-oX", "-", target]
    warnings: list[str] = []
    phase_status = {"tcp": "pending", "udp": "not_started"}
    try:
        tcp_root = _run_xml(tcp_args, tcp_timeout)
        tcp_hosts = [parsed for host in tcp_root.findall("host") if (parsed := _parse_host(host))]
        phase_status["tcp"] = "completed"
    except RuntimeError as exc:
        tcp_hosts = []
        phase_status["tcp"] = "partial"
        warnings.append(f"TCP discovery was incomplete: {exc}")

    hosts_by_address = {h["address"]: h for h in tcp_hosts}
    udp_scope = "disabled"
    if udp_ports is not None or udp_top > 0:
        udp_n = max(1, min(int(udp_top), 1000))
        udp_args = [path, "-Pn", "-n", "-sU", "-sV", "--version-light"]
        if udp_ports is not None:
            udp_args += ["-p", ",".join(str(port) for port in udp_ports)]
            udp_scope = "custom UDP ports " + ",".join(str(port) for port in udp_ports)
        else:
            udp_args += ["--top-ports", str(udp_n)]
            udp_scope = f"top {udp_n} UDP ports"
        udp_args += ["-oX", "-", target]
        try:
            udp_root = _run_xml(udp_args, udp_timeout)
            udp_hosts = [parsed for host in udp_root.findall("host") if (parsed := _parse_host(host))]
            phase_status["udp"] = "completed"
            for uh in udp_hosts:
                h = hosts_by_address.setdefault(uh["address"], {
                    "address": uh["address"], "hostname": uh.get("hostname", ""), "alive": True,
                    "open_ports": [], "udp_services": [], "port_observations": []
                })
                if not h.get("hostname"):
                    h["hostname"] = uh.get("hostname", "")
                h["udp_services"].extend(uh.get("udp_services", []))
        except RuntimeError as exc:
            # Nmap UDP probes may need elevated privileges or exceed a network's
            # response window. Keep the successful TCP evidence and make the
            # missing coverage explicit instead of failing the entire job.
            udp_scope = f"unavailable ({exc})"
            phase_status["udp"] = "partial"
            warnings.append(f"UDP discovery was unavailable: {exc}")
    else:
        phase_status["udp"] = "disabled"

    for host in hosts_by_address.values():
        for service in host.get("open_ports", []) + host.get("udp_services", []):
            service["scan_timestamp"] = scan_timestamp
            service["scan_method"] = "nmap -sV --version-light" if service.get("protocol") == "tcp" else "nmap -sU"
        for observation in host.get("port_observations", []):
            observation["scan_timestamp"] = scan_timestamp
        host["device_type"] = "Unknown / Unverified"
        host["reachability"] = "reachable" if host.get("open_ports") or any(s.get("state") in ("open", "open|responding") and s.get("verification_status") == "confirmed" for s in host.get("udp_services", [])) else "discovery_uncertain"

    return {
        "engine": "nmap",
        "scan_timestamp": scan_timestamp,
        "scan_method": "nmap -sV --version-light",
        "nmap_path": path,
        "nmap_version": version(),
        "target": target,
        "tcp_scope": "all TCP ports" if full_tcp else "top 1000 TCP ports",
        "udp_scope": udp_scope,
        "warnings": warnings,
        "phase_status": phase_status,
        "hosts": list(hosts_by_address.values()),
    }


def discover(target: str, timeout: int | None = None) -> dict[str, Any]:
    """Discover reachable hosts inside an already validated IPv4 scope.

    Nmap receives the exact supplied network. The function never infers a
    gateway or expands the target. No response remains uncertain, not secure.
    """
    try:
        network = ipaddress.ip_network(str(target).strip(), strict=True)
    except ValueError as exc:
        raise ValueError("Host discovery requires a literal IPv4 address or network") from exc
    if network.version != 4 or network.num_addresses > 256:
        raise ValueError("Host discovery is limited to IPv4 scopes of at most 256 addresses")
    path = find_nmap()
    if not path:
        raise RuntimeError("Nmap was not found. Install Nmap or set NMAP_PATH.")
    started = datetime.now(timezone.utc).isoformat()
    args = [path, "-sn", "-n", "-PE", "-PS22,80,443,445,3389", "-PA80,443", "--reason", "-oX", "-", str(network)]
    root = _run_xml(args, timeout or DISCOVERY_TIMEOUT)
    reachable = []
    observations = []
    for host in root.findall("host"):
        address = next((item.get("addr", "") for item in host.findall("address") if item.get("addrtype") == "ipv4"), "")
        if not address:
            continue
        status_node = host.find("status")
        state = status_node.get("state", "unknown") if status_node is not None else "unknown"
        reason = status_node.get("reason", "") if status_node is not None else ""
        if state == "up":
            reachability = "reachable"
        elif any(marker in reason.lower() for marker in ("admin-prohibited", "host-prohibited", "filtered")):
            reachability = "filtered"
        elif any(marker in reason.lower() for marker in ("host-unreach", "net-unreach", "port-unreach")):
            reachability = "unreachable"
        elif any(marker in reason.lower() for marker in ("no-response", "timeout")):
            reachability = "no_response"
        else:
            reachability = "discovery_uncertain"
        observations.append({"address": address, "reachability": reachability, "discovery_state": state, "discovery_reason": reason})
        record = _parse_host(host)
        if record:
            record["reachability"] = "reachable"
            reachable.append(record)
    return {"target": str(network), "scan_timestamp": started, "hosts": reachable, "observations": observations, "phase_status": "completed", "method": "nmap -sn TCP/ICMP discovery"}

