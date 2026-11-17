"""Safe, offline tests for structured Nmap evidence and NVD metadata."""
import os
import unittest
import xml.etree.ElementTree as ET
import requests
from unittest.mock import Mock, patch

from security_audit import nmap_scanner, vulnerability


TCP_XML = """<nmaprun><host><status state="up"/><address addr="192.0.2.8" addrtype="ipv4"/><hostnames><hostname name="audit-host"/></hostnames><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="Example Server" version="1.2.3"><cpe>cpe:2.3:a:example:server:1.2.3:*:*:*:*:*:*:*</cpe></service></port></ports></host></nmaprun>"""
UDP_XML = """<nmaprun><host><status state="up"/><address addr="192.0.2.8" addrtype="ipv4"/><ports><port protocol="udp" portid="53"><state state="open"/><service name="domain"/></port></ports></host></nmaprun>"""


class NmapEvidenceTests(unittest.TestCase):
    def test_structured_host_parser_preserves_cpe_provenance(self):
        host = nmap_scanner._parse_host(ET.fromstring(TCP_XML).find("host"))
        self.assertEqual(host["address"], "192.0.2.8")
        service = host["open_ports"][0]
        self.assertEqual(service["product"], "Example Server")
        self.assertEqual(service["version"], "1.2.3")
        self.assertEqual(service["cpe_source"], "nmap")
        self.assertEqual(service["cpe_confidence"], "high")
        self.assertEqual(service["cpe"][0], "cpe:2.3:a:example:server:1.2.3:*:*:*:*:*:*:*")

    def test_scan_uses_validated_custom_udp_ports_and_records_time(self):
        roots = [ET.fromstring(TCP_XML), ET.fromstring(UDP_XML)]
        with patch.object(nmap_scanner, "find_nmap", return_value="nmap.exe"),              patch.object(nmap_scanner, "version", return_value="Nmap 7.95"),              patch.object(nmap_scanner, "_run_xml", side_effect=roots) as run:
            result = nmap_scanner.scan("192.0.2.8", full_tcp=True, udp_ports=[123, 53, 53])
        self.assertEqual(result["udp_scope"], "custom UDP ports 53,123")
        self.assertIn("-p", run.call_args_list[1].args[0])
        self.assertIn("53,123", run.call_args_list[1].args[0])
        self.assertTrue(result["scan_timestamp"])
        self.assertTrue(result["hosts"][0]["open_ports"][0]["scan_timestamp"])
        self.assertTrue(result["hosts"][0]["udp_services"])

    def test_custom_udp_port_list_is_bounded(self):
        with patch.object(nmap_scanner, "find_nmap", return_value="nmap.exe"):
            with self.assertRaises(ValueError):
                nmap_scanner.scan("192.0.2.8", udp_ports=[0])
            with self.assertRaises(ValueError):
                nmap_scanner.scan("192.0.2.8", udp_ports=list(range(1, 130)))

    def test_udp_open_filtered_is_preserved_as_unverified(self):
        xml = ET.fromstring('<nmaprun><host><status state="up"/><address addr="192.0.2.8" addrtype="ipv4"/><ports><port protocol="udp" portid="53"><state state="open|filtered"/><service name="domain" method="table" conf="3"/></port></ports></host></nmaprun>')
        host = nmap_scanner._parse_host(xml.find("host"))
        service = host["udp_services"][0]
        self.assertEqual(service["state"], "open|filtered")
        self.assertEqual(service["verification_status"], "candidate / unverified")
        self.assertEqual(host["port_observations"][0]["state"], "open|filtered")

    def test_tcp_timeout_is_partial_and_does_not_discard_udp_evidence(self):
        udp = ET.fromstring(UDP_XML)
        with patch.object(nmap_scanner, "find_nmap", return_value="nmap.exe"), \
             patch.object(nmap_scanner, "version", return_value="Nmap fixture"), \
             patch.object(nmap_scanner, "_run_xml", side_effect=[RuntimeError("TCP timeout"), udp]):
            result = nmap_scanner.scan("192.0.2.8", full_tcp=True, udp_top=5)
        self.assertEqual(result["phase_status"]["tcp"], "partial")
        self.assertEqual(result["phase_status"]["udp"], "completed")
        self.assertTrue(result["hosts"][0]["udp_services"])
        self.assertTrue(result["warnings"])

    def test_discovery_uses_exact_network_and_keeps_only_reported_hosts(self):
        root = ET.fromstring('<nmaprun><host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/></host></nmaprun>')
        with patch.object(nmap_scanner, "find_nmap", return_value="nmap.exe"), \
             patch.object(nmap_scanner, "_run_xml", return_value=root) as run:
            result = nmap_scanner.discover("10.0.0.0/30")
        self.assertEqual(result["hosts"][0]["address"], "10.0.0.1")
        self.assertEqual(result["observations"][0]["reachability"], "reachable")
        self.assertEqual(run.call_args.args[0][-1], "10.0.0.0/30")


    def test_nvd_retries_transient_rate_limit(self):
        first = Mock(status_code=429)
        second = Mock(status_code=200)
        second.json.return_value = {"vulnerabilities": []}
        with patch("security_audit.vulnerability.requests.get", side_effect=[first, second]) as get, \
             patch("security_audit.vulnerability.time.sleep"):
            self.assertEqual(vulnerability._nvd_get({"cpeName": "cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:*"}), {"vulnerabilities": []})
        self.assertEqual(get.call_count, 2)

    def test_nvd_failure_is_graceful_and_not_cached_as_a_permanent_empty_result(self):
        vulnerability.nvd_lookup.cache_clear()
        with patch("security_audit.vulnerability._nvd_get", side_effect=requests.Timeout("offline")), \
             patch("security_audit.vulnerability.time.sleep"):
            self.assertEqual(vulnerability.nvd_lookup("example server", "1.2.3"), ())
        self.assertEqual(vulnerability.nvd_lookup.cache_info().currsize, 0)

    def test_cvss_versions_are_preserved(self):
        cve = {"metrics": {
            "cvssMetricV40": [{"cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH", "vectorString": "CVSS:4.0/example"}}],
            "cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/example"}}],
        }}
        metrics = vulnerability.extract_cvss_metrics(cve)
        self.assertEqual([m["version"] for m in metrics], ["4.0", "3.1"])
        self.assertEqual(vulnerability.extract_cvss(cve), (8.1, "HIGH", "CVSS:4.0/example"))


if __name__ == "__main__":
    unittest.main()
