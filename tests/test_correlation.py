"""
Unit and integration tests for Sentinel Audit:
A. TCP scanning status (Open)
B. UDP scanning status (Open or Filtered (UDP))
C. Duplicate/correlation logic (445 SMB Medium + Low -> 1 Medium)
D. Different ports remain separate (135, 139, 445 -> 3 findings)
E. CVE/CPE/vulnerability distinction (service observed != vulnerability)
F. Risk aggregation (deterministic max, no double-counting)
G. Report generation (JSON, HTML, PDF, correlated counts)
"""

import json
from unittest.mock import patch
import unittest

from security_audit import assessments, correlation, reports, risk
from security_audit.db import connect


class FindingCorrelationAndScanTests(unittest.TestCase):

    def test_a_tcp_scan_status_is_open(self):
        """
        A. TCP scanning: Confirm a TCP-open service is correctly represented as open.
        """
        fake_hosts = [
            {
                "address": "10.101.137.41",
                "hostname": "DESKTOP-VR8A9R3",
                "alive": True,
                "open_ports": [
                    {"port": 21, "service": "FTP", "state": "open"}
                ],
                "udp_services": [],
            }
        ]
        raw = assessments._network_findings(fake_hosts)
        correlated = correlation.correlate_findings(raw)
        self.assertGreaterEqual(len(correlated), 1)
        tcp_finding = correlated[0]
        self.assertEqual(tcp_finding["port"], 21)
        self.assertEqual(tcp_finding["protocol"], "tcp")
        self.assertEqual(tcp_finding["port_status"], "Open")
        self.assertEqual(tcp_finding["status"], "open")
        self.assertEqual(reports.get_display_status(tcp_finding), "Open")

    def test_b_udp_scan_uncertain_status_open_or_filtered(self):
        """
        B. UDP scanning: Confirm an uncertain UDP result is represented as 'Open or Filtered (UDP)'.
        """
        fake_hosts = [
            {
                "address": "10.101.137.41",
                "hostname": "DESKTOP-VR8A9R3",
                "alive": True,
                "open_ports": [],
                "udp_services": [
                    {"port": 53, "service": "DNS", "state": "open|filtered"}
                ],
            }
        ]
        raw = assessments._network_findings(fake_hosts)
        correlated = correlation.correlate_findings(raw)
        self.assertEqual(len(correlated), 1)
        udp_finding = correlated[0]
        self.assertEqual(udp_finding["port"], 53)
        self.assertEqual(udp_finding["protocol"], "udp")
        self.assertEqual(udp_finding["port_status"], "Open or Filtered (UDP)")
        self.assertEqual(udp_finding["status"], "Open or Filtered (UDP)")
        self.assertEqual(reports.get_display_status(udp_finding), "Open or Filtered (UDP)")
        # Check description and remediation clean separation
        self.assertIn("reports Open or Filtered (UDP) for UDP/53", udp_finding["description"])
        self.assertIn("service label DNS is a candidate", udp_finding["description"])
        self.assertNotIn("protocol-specificRemediation", udp_finding["description"])
        self.assertIn("Confirm whether the UDP service is required", udp_finding["remediation"])

    def test_udp_open_state_remains_open_but_service_is_unverified(self):
        raw = assessments._network_findings([{"address":"192.0.2.9","hostname":"","open_ports":[],"udp_services":[{"port":53,"protocol":"udp","service":"DNS","state":"open","verification_status":"candidate"}]}])
        finding = correlation.correlate_findings(raw)[0]
        self.assertEqual(finding["port_status"], "Open")
        self.assertTrue(finding["verified"])
        self.assertEqual(finding["verification_status"], "confirmed observation")
        self.assertEqual(finding["service_verification_status"], "candidate / unverified")
        self.assertEqual(reports.get_display_status(finding), "Open")

    def test_c_duplicate_correlation_smb(self):
        """
        C. Duplicate/correlation logic:
        10.101.137.41:445/TCP SMB Medium
        10.101.137.41:445/TCP SMB Low
        Expected: 1 correlated Medium finding.
        """
        raw = [
            {
                "id": "F-001",
                "title": "SMB service reachable on 10.101.137.41 (DESKTOP-VR8A9R3)",
                "severity": "medium",
                "category": "network service",
                "description": "TCP/445 is reachable within the authorized assessment scope. Reachability does not establish a vulnerability.",
                "remediation": "Restrict SMB access to required trusted networks and verify patching and SMB configuration.",
                "evidence": {
                    "source": "bounded TCP connect check",
                    "address": "10.101.137.41",
                    "hostname": "DESKTOP-VR8A9R3",
                    "port": 445,
                    "protocol": "tcp",
                    "service": "SMB",
                    "state": "open",
                },
                "verified": True,
            },
            {
                "id": "F-002",
                "title": "Sensitive service reachable: SMB on 10.101.137.41 (DESKTOP-VR8A9R3)",
                "severity": "low",
                "category": "network exposure",
                "description": "A potentially sensitive administrative or data service is reachable within the authorized scope.",
                "remediation": "Restrict access to trusted management hosts or networks.",
                "evidence": {
                    "source": "bounded TCP connect check",
                    "address": "10.101.137.41",
                    "hostname": "DESKTOP-VR8A9R3",
                    "port": 445,
                    "protocol": "tcp",
                    "service": "SMB",
                    "state": "open",
                },
                "verified": True,
            },
        ]

        correlated = correlation.correlate_findings(raw)
        self.assertEqual(len(correlated), 1)
        finding = correlated[0]
        self.assertEqual(finding["severity"], "medium")
        self.assertEqual(finding["port"], 445)
        self.assertEqual(finding["protocol"], "tcp")
        self.assertEqual(finding["target_ip"], "10.101.137.41")
        self.assertEqual(finding["hostname"], "DESKTOP-VR8A9R3")
        self.assertEqual(finding["correlated_count"], 2)
        self.assertIn("F-001", finding["source_finding_ids"])
        self.assertIn("F-002", finding["source_finding_ids"])
        # Risk score is maximum (medium = 3.0), not added (3.0 + 1.2 = 4.2)
        self.assertEqual(finding["risk_score"], 3.0)
        self.assertIn("combines 2 overlapping scanner observations", finding["correlation_note"])

    def test_d_distinct_ports_remain_separate(self):
        """
        D. Different ports remain separate:
        135/TCP RPC
        139/TCP NetBIOS
        445/TCP SMB
        Expected: 3 findings.
        """
        raw = [
            {
                "id": "F-135",
                "title": "Sensitive service reachable: MS-RPC on 10.101.137.41",
                "severity": "low",
                "category": "network exposure",
                "evidence": {"address": "10.101.137.41", "port": 135, "protocol": "tcp", "service": "MS-RPC"},
            },
            {
                "id": "F-139",
                "title": "Sensitive service reachable: NetBIOS on 10.101.137.41",
                "severity": "low",
                "category": "network exposure",
                "evidence": {"address": "10.101.137.41", "port": 139, "protocol": "tcp", "service": "NetBIOS"},
            },
            {
                "id": "F-445",
                "title": "SMB service reachable on 10.101.137.41",
                "severity": "medium",
                "category": "network service",
                "evidence": {"address": "10.101.137.41", "port": 445, "protocol": "tcp", "service": "SMB"},
            },
        ]

        correlated = correlation.correlate_findings(raw)
        self.assertEqual(len(correlated), 3)
        ports = {f["port"] for f in correlated}
        self.assertEqual(ports, {135, 139, 445})
        for f in correlated:
            self.assertEqual(f["service_group"], "Windows File & Network Services")

    def test_e_service_observed_vs_confirmed_vulnerability(self):
        """
        E. CVE/CPE/vulnerability distinction:
        - Service observation without vulnerability evidence must NOT become a confirmed vulnerability.
        - Existing confirmed vulnerability evidence must remain a vulnerability.
        """
        raw = [
            {
                "id": "F-SVC",
                "title": "SMB service reachable on 10.101.137.41:445",
                "severity": "medium",
                "category": "network service",
                "description": "TCP/445 is reachable within the authorized assessment scope. Reachability alone does not establish a vulnerability.",
                "evidence": {"address": "10.101.137.41", "port": 445, "protocol": "tcp", "service": "SMB"},
                "verified": True,
            },
            {
                "id": "F-CVE",
                "title": "CVE candidate for OpenSSL 3.0.7: CVE-2023-0286",
                "severity": "high",
                "category": "vulnerability candidate",
                "description": "A read-only service banner exposed a product/version string that matches an advisory range.",
                "cve": "CVE-2023-0286",
                "cvss": 7.4,
                "evidence": {"address": "10.101.137.41", "port": 445, "protocol": "tcp", "service": "SMB", "cve": "CVE-2023-0286"},
                "verified": False,
            },
        ]
        correlated = correlation.correlate_findings(raw)
        # Service observation and CVE vulnerability are NOT merged together
        self.assertEqual(len(correlated), 2)
        categories = {f["category"] for f in correlated}
        self.assertIn("network service", categories)
        self.assertIn("vulnerability candidate", categories)

        svc_f = next(f for f in correlated if f["category"] == "network service")
        self.assertNotIn("vulnerability", svc_f["title"].lower())
        self.assertEqual(svc_f["cve"], "")

        cve_f = next(f for f in correlated if f["category"] == "vulnerability candidate")
        self.assertEqual(cve_f["cve"], "CVE-2023-0286")
        self.assertEqual(cve_f["severity"], "high")

    def test_f_risk_aggregation_no_double_counting(self):
        """
        F. Risk aggregation:
        Duplicate observations must not double-count risk.
        Preserve the existing risk model.
        """
        raw = [
            {"severity": "medium", "risk_score": 3.0, "evidence": {"address": "10.0.0.1", "port": 445, "protocol": "tcp", "service": "SMB"}},
            {"severity": "low", "risk_score": 1.2, "evidence": {"address": "10.0.0.1", "port": 445, "protocol": "tcp", "service": "SMB"}},
        ]
        correlated = correlation.correlate_findings(raw)
        self.assertEqual(len(correlated), 1)
        self.assertEqual(correlated[0]["risk_score"], 3.0)

        summary = risk.risk_summary(correlated)
        self.assertEqual(summary["total_findings"], 1)
        self.assertEqual(summary["medium"], 1)
        self.assertEqual(summary["low"], 0)
        self.assertEqual(summary["total_risk_score"], 3.0)

    def test_g_report_generation_and_counts(self):
        """
        G. Report generation:
        - Verify JSON, HTML, PDF report generation still works.
        - Verify severity/count statistics are generated from correlated findings.
        """
        db = connect(":memory:")
        db.execute("INSERT INTO organizations(name) VALUES('TestOrg')")
        db.execute("INSERT INTO projects(organization_id, name) VALUES(1, 'TestProject')")

        ev_smb1 = {"address": "10.101.137.41", "port": 445, "protocol": "tcp", "service": "SMB"}
        ev_smb2 = {"address": "10.101.137.41", "port": 445, "protocol": "tcp", "service": "SMB"}
        ev_udp = {"address": "10.101.137.41", "port": 53, "protocol": "udp", "service": "DNS", "state": "open|filtered"}

        db.execute("INSERT INTO findings(project_id, title, severity, risk_score, evidence, status) VALUES(1, 'SMB reachable', 'medium', 3.0, ?, 'open')", (json.dumps(ev_smb1),))
        db.execute("INSERT INTO findings(project_id, title, severity, risk_score, evidence, status) VALUES(1, 'Sensitive: SMB', 'low', 1.2, ?, 'open')", (json.dumps(ev_smb2),))
        db.execute("INSERT INTO findings(project_id, title, severity, risk_score, evidence, status) VALUES(1, 'UDP DNS observed', 'info', 0.0, ?, 'Open or Filtered (UDP)')", (json.dumps(ev_udp),))
        db.commit()

        collected = reports.collect(db, 1, "technical")
        self.assertEqual(collected["executive_summary"]["open_findings"], 2)  # 1 SMB + 1 UDP
        self.assertEqual(collected["executive_summary"]["severity_counts"]["medium"], 1)
        self.assertEqual(collected["executive_summary"]["severity_counts"]["low"], 0)
        self.assertEqual(collected["executive_summary"]["severity_counts"]["info"], 1)
        self.assertEqual(len(collected["findings"]), 2)

        # JSON
        json_data = reports.json_bytes(collected)
        parsed = json.loads(json_data.decode("utf-8"))
        self.assertEqual(parsed["executive_summary"]["open_findings"], 2)

        # PDF
        pdf_data = reports.pdf_bytes(collected)
        self.assertTrue(pdf_data.startswith(b"%PDF-1.4"))
        self.assertIn(b"%%EOF", pdf_data)

        # HTML
        html_data = reports.html_bytes(collected)
        html_text = html_data.decode("utf-8")
        self.assertIn("<!DOCTYPE html>", html_text)
        self.assertIn("Open or Filtered (UDP)", html_text)
        self.assertIn("SMB", html_text)
        db.close()


if __name__ == "__main__":
    unittest.main()
