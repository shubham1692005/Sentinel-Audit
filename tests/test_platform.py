import http.client, json, os, shutil, threading, time, unittest
from pathlib import Path

from security_audit import assessments, grc, reports, risk, vulnerability
from security_audit.db import connect
from security_audit.api import Handler, create_admin, pw_hash
from http.server import ThreadingHTTPServer
from unittest.mock import patch

class EngineTests(unittest.TestCase):
    def test_proxy_client_ip_is_trusted_only_when_explicitly_enabled_and_valid(self):
        class Request:
            client_address=("172.20.0.3",8080)
            headers={"X-Real-IP":"198.51.100.24"}
        request=Request()
        with patch.dict(os.environ,{"TRUST_PROXY_HEADERS":"1"}):
            self.assertEqual(Handler.client_ip(request),"198.51.100.24")
            request.headers={"X-Real-IP":"not-an-ip"}
            self.assertEqual(Handler.client_ip(request),"172.20.0.3")
        with patch.dict(os.environ,{"TRUST_PROXY_HEADERS":"0"}):
            request.headers={"X-Real-IP":"198.51.100.24"}
            self.assertEqual(Handler.client_ip(request),"172.20.0.3")

    def test_windows_collection_labels_permission_errors_instead_of_clean_results(self):
        facts={}; coverage={}
        with patch("security_audit.assessments._optional_powershell",return_value={"collection_error":"Access denied: elevation required"}):
            value=assessments._collect_windows_check(facts,coverage,"bitlocker_volumes","Get-BitLockerVolume","Get-BitLockerVolume")
        self.assertIn("collection_error",value)
        self.assertEqual(coverage["bitlocker_volumes"]["status"],"permission_required")
        self.assertEqual(facts["bitlocker_volumes"],value)

    def test_windows_posture_findings_and_gaps_use_mocked_collector_data(self):
        values=[
            {"Caption":"Windows Fixture","Version":"10","BuildNumber":"1"},
            [{"Name":"Domain","Enabled":True}],
            {"AntivirusEnabled":True,"RealTimeProtectionEnabled":True},
            [], [], [], [],
            {"ResultCode":2,"PendingCount":0,"Updates":[]},
            [{"MountPoint":"C:","VolumeType":"OperatingSystem","ProtectionStatus":"Off"}],
            {"Supported":True,"Enabled":False},
            {"TpmPresent":True,"TpmReady":True},
            {"EnableLUA":0}, [], [], {"EnabledLocalAccountCount":1,"GuestAccountEnabled":False},
        ]
        with patch("security_audit.assessments._optional_powershell",side_effect=values):
            facts,findings=assessments._windows_assessment()
        titles={finding["title"] for finding in findings}
        self.assertIn("Secure Boot is disabled",titles)
        self.assertIn("User Account Control is disabled",titles)
        self.assertIn("BitLocker protection is off for C:",titles)
        self.assertEqual(facts["collection_coverage"]["appx_packages"]["status"],"collected")
        self.assertEqual(facts["collection_coverage"]["windows_app_permissions"]["status"],"not_available")

    def test_risk_bands_and_input_validation(self):
        self.assertEqual(risk.score("critical",5)["band"],"critical")
        self.assertEqual(risk.score("high",3)["band"],"high")
        self.assertEqual(risk.score("medium",3)["band"],"medium")
        grid=risk.matrix([{"likelihood":5,"impact":10},{"likelihood":1,"impact":0}])
        self.assertEqual(grid[4][4],1); self.assertEqual(grid[0][0],1)
        bands=risk.matrix_risk_bands(); self.assertEqual((len(bands),len(bands[0])),(5,5)); self.assertEqual(bands[4][4],"critical")
        score=risk.score("high",3,8,asset_criticality="low",cvss_score=9.8)
        self.assertEqual(score["score"],2.9); self.assertEqual(score["band"],"medium"); self.assertEqual(score["cvss_score"],9.8)
        self.assertIn("impact (8) × likelihood (3) / 5",score["explanation"])
        with self.assertRaises(ValueError):risk.score("high",0)
    def test_nmap_mock_keeps_tcp_results_when_udp_phase_fails(self):
        import xml.etree.ElementTree as ET
        tcp=ET.fromstring('<nmaprun><host><status state="up"/><address addr="8.8.8.8" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="Fixture" version="1.0"/></port></ports></host></nmaprun>')
        with patch("security_audit.nmap_scanner.find_nmap",return_value="nmap"), patch("security_audit.nmap_scanner.version",return_value="fixture"), patch("security_audit.nmap_scanner._run_xml",side_effect=[tcp,RuntimeError("permission denied in UDP fixture")]) as run:
            result=assessments.nmap_scanner.scan("8.8.8.8",full_tcp=True,udp_top=100)
        self.assertEqual(len(result["hosts"]),1); self.assertEqual(result["hosts"][0]["open_ports"][0]["port"],443)
        self.assertIn("unavailable",result["udp_scope"]); self.assertIn("permission denied",result["warnings"][0]); self.assertEqual(run.call_count,2)
    def test_cve_candidate_requires_parseable_version(self):
        hits=vulnerability.match("OpenSSL library","3.0.7")
        self.assertTrue(any(x["cve"]=="CVE-2023-0286" and x["verified"] is False for x in hits))
        self.assertEqual(vulnerability.match("OpenSSL","3.0.8"),[])
        self.assertEqual(vulnerability.match("OpenSSL","unknown"),[])
    def test_network_scope_enforces_authorization_and_size(self):
        with self.assertRaises(ValueError):assessments.validate_scope("127.0.0.1",False)
        with self.assertRaises(ValueError):assessments.validate_scope("10.0.0.0/16",True)
        with self.assertRaises(ValueError):assessments.validate_scope("8.8.8.8",True)
        self.assertEqual(str(assessments.validate_scope("127.0.0.1/32",True)),"127.0.0.1/32")
        self.assertEqual(str(assessments.validate_scope("8.8.8.8",True,True)),"8.8.8.8/32")
        self.assertEqual(str(assessments.validate_scope("8.8.8.8/32",True,True)),"8.8.8.8/32")
        with self.assertRaises(ValueError):assessments.validate_scope("8.8.8.0/24",True,True)
        with patch("security_audit.assessments.socket.gethostbyname",side_effect=AssertionError("public validation must not perform DNS")):
            for target in ("203.0.113.10","192.0.2.7","8.8.8.0/24","8.8.8.8/31","169.254.1.1","224.0.0.1"):
                with self.assertRaises(ValueError,msg=target):assessments.validate_scope(target,True,True)
            self.assertEqual(str(assessments.validate_scope("8.8.8.8",True,True)),"8.8.8.8/32")
        with patch("security_audit.assessments.socket.getaddrinfo",return_value=[(None,None,None,None,("8.8.8.8",0))]):
            self.assertEqual(str(assessments.validate_scope("audit.example.com",True,True)),"8.8.8.8/32")
        with patch("security_audit.assessments.socket.getaddrinfo",return_value=[(None,None,None,None,("8.8.8.8",0)),(None,None,None,None,("1.1.1.1",0))]):
            with self.assertRaises(ValueError):assessments.validate_scope("audit.example.com",True,True)
        with patch("security_audit.assessments.socket.getaddrinfo",return_value=[(None,None,None,None,("192.168.1.2",0))]):
            with self.assertRaises(ValueError):assessments.validate_scope("private.example.com",True,True)
        with self.assertRaises(ValueError):assessments.validate_scope("8.8.8.8",True,False)
        with self.assertRaises(ValueError):assessments.validate_scope("10.0.0.7/24",True)

    def test_network_discovery_assesses_only_reachable_hosts_inside_scope(self):
        discovery={"hosts":[{"address":"10.0.0.1","hostname":"host1","alive":True}, {"address":"10.0.0.5","hostname":"outside","alive":True}],"method":"fixture discovery"}
        host_scan={"hosts":[{"address":"10.0.0.1","hostname":"host1","alive":True,"open_ports":[{"port":445,"protocol":"tcp","state":"open","service":"microsoft-ds"}],"udp_services":[]}],"phase_status":{"tcp":"completed","udp":"completed"},"warnings":[]}
        with patch("security_audit.assessments.nmap_scanner.find_nmap",return_value="nmap"), \
             patch("security_audit.assessments.nmap_scanner.discover",return_value=discovery), \
             patch("security_audit.assessments.nmap_scanner.scan",return_value=host_scan) as scanner:
            result=assessments.network_assessment("10.0.0.0/30",True)
        scanner.assert_called_once()
        self.assertEqual(scanner.call_args.args[0],"10.0.0.1")
        self.assertNotIn("10.0.0.5",[h["address"] for h in result["hosts"]])
        self.assertEqual(result["scope_details"]["hosts_discovered"],1)
        self.assertEqual(result["scope_details"]["hosts_uncertain"],3)
        self.assertTrue(any("SMB" in f["title"] for f in result["findings"]))

    def test_single_reachable_host_with_zero_open_services_is_successful(self):
        with patch("security_audit.assessments.nmap_scanner.find_nmap",return_value="nmap"), \
             patch("security_audit.assessments.nmap_scanner.discover",return_value={"hosts":[{"address":"10.0.0.41"}],"method":"fixture"}), \
             patch("security_audit.assessments.nmap_scanner.scan",return_value={"hosts":[{"address":"10.0.0.41","hostname":"phone","alive":True,"open_ports":[],"udp_services":[]}],"phase_status":{"tcp":"completed","udp":"completed"},"warnings":[]}) as scanner:
            result=assessments.network_assessment("10.0.0.41",True)
        scanner.assert_called_once()
        self.assertEqual(result["scope"],"10.0.0.41/32")
        self.assertEqual(result["network_summary"]["hosts_reachable"],1)
        self.assertEqual(result["network_summary"]["exposed_ports"],0)
        self.assertEqual(result["findings"],[])

    def test_candidate_cve_keeps_cvss_separate_and_reduces_internal_likelihood(self):
        def enrich(service, use_nvd=True):
            service["cves"]=[{"cve":"CVE-2024-0001","severity":"high","cvss":8.8,"verified":False,"confidence":"candidate","match_type":"keyword"}]
            return service
        hosts=[{"address":"10.0.0.9","hostname":"","open_ports":[{"port":443,"protocol":"tcp","state":"open","service":"https","product":"Example","version":"1.0"}],"udp_services":[]}]
        with patch("security_audit.assessments.enrich_service",side_effect=enrich):
            findings=assessments._network_findings(hosts)
        finding=next(item for item in findings if item.get("cve"))
        self.assertEqual(finding["severity"],"high")
        self.assertEqual(finding["cvss"],8.8)
        self.assertFalse(finding["verified"])
        self.assertEqual(finding["likelihood"],1)
        self.assertEqual(risk.calculate_finding_risk(finding)["risk_score"],1.6)
    def test_network_scan_explains_no_tcp_response_without_using_ping(self):
        with patch("security_audit.assessments.nmap_scanner.find_nmap",return_value=None), patch("security_audit.assessments._tcp_open",return_value=False), patch("security_audit.assessments._reverse_dns",return_value=""):
            result=assessments.network_assessment("127.0.0.1/32",True)
        self.assertEqual(result["summary"]["reachability"]["icmp_used"],False)
        self.assertEqual(result["summary"]["reachability"]["targets_with_tcp_response"],0)
        self.assertIn("firewall or hotspot client isolation",result["summary"]["reachability"]["note"])
    def test_public_ipv4_assessment_uses_mocked_nmap_without_network_access(self):
        fixture={"hosts":[{"address":"8.8.8.8","hostname":"","alive":True,"open_ports":[{"port":443,"protocol":"tcp","state":"open","service":"https","product":"Fixture","version":"1.0","cpe":[],"cpe_source":"none","cpe_confidence":"none"}],"udp_services":[]}],"scan_timestamp":"2026-10-02T00:00:00+00:00","scan_method":"mock fixture","tcp_scope":"all TCP ports","udp_scope":"unavailable","warnings":["mocked public scope; no packets sent"]}
        with patch("security_audit.assessments.nmap_scanner.find_nmap",return_value="mock-nmap"), patch("security_audit.assessments.nmap_scanner.discover",return_value={"hosts":[{"address":"8.8.8.8"}],"method":"fixture"}), patch("security_audit.assessments.nmap_scanner.scan",return_value=fixture) as scanner:
            result=assessments.network_assessment("8.8.8.8/32",True,True)
        scanner.assert_called_once_with("8.8.8.8",full_tcp=None,udp_top=100)
        self.assertEqual(result["scope"],"8.8.8.8/32")
        self.assertEqual(result["assessment"]["engine"],"nmap")
        self.assertEqual(result["services"][0]["address"],"8.8.8.8")
    def test_framework_seed_and_pdf_output(self):
        db=connect(":memory:"); grc.seed(db); db.commit()
        self.assertGreaterEqual(db.execute("SELECT count(*) FROM controls").fetchone()[0],10)
        self.assertGreaterEqual(len(grc.mapped_control_ids(db,"vulnerability")),2)
        db.execute("INSERT INTO organizations(name) VALUES('Acme')"); oid=db.execute("SELECT id FROM organizations").fetchone()[0]
        db.execute("INSERT INTO projects(organization_id,name) VALUES(?,'Review')",(oid,)); db.commit()
        pid=db.execute("SELECT id FROM projects").fetchone()[0]
        db.execute("INSERT INTO assets(project_id,name) VALUES(?,'Unaddressed host one')",(pid,)); db.execute("INSERT INTO assets(project_id,name) VALUES(?,'Unaddressed host two')",(pid,)); db.commit()
        self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0],9)
        p=reports.collect(db,1,"executive"); raw=reports.pdf_bytes(p)
        self.assertTrue(raw.startswith(b"%PDF-1.4")); self.assertIn(b"%%EOF",raw)
        db.close()

class APIWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=Path(__file__).resolve().parent.parent/"work"/"test-run"; shutil.rmtree(cls.temp,ignore_errors=True); cls.temp.mkdir(parents=True,exist_ok=True); os.environ["AUDIT_DB"]=str(cls.temp/"workflow.db")
        db=connect(); create_admin(db,"admin@example.test","long-test-password-123"); db.close()
        cls.server=ThreadingHTTPServer(("127.0.0.1",0),Handler); cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True); cls.thread.start(); cls.port=cls.server.server_address[1]
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join(timeout=2); shutil.rmtree(cls.temp,ignore_errors=True); os.environ.pop("AUDIT_DB",None)
    def request(self,path,method="GET",data=None,auth=True):
        c=http.client.HTTPConnection("127.0.0.1",self.port,timeout=45); headers={}
        if auth and hasattr(self,"session"):headers["Cookie"]=self.session
        if method in ("POST","PATCH"):
            headers["Content-Type"]="application/json"
            if auth and hasattr(self,"csrf"):headers["X-CSRF-Token"]=self.csrf
        c.request(method,path,json.dumps(data) if data is not None else None,headers); r=c.getresponse(); body=r.read(); status=r.status; hdr=r.getheaders(); c.close(); return status,hdr,body
    def test_authenticated_asset_assessment_and_reports(self):
        status,_,_=self.request("/healthz",auth=False); self.assertEqual(status,200)
        status,_,body=self.request("/readyz",auth=False); self.assertEqual(status,200); self.assertEqual(json.loads(body),{"status":"ready","database":"ok"})
        status,headers,body=self.request("/api/auth/login","POST",{"email":"admin@example.test","password":"long-test-password-123"},False)
        self.assertEqual(status,200); self.session="; ".join(v.split(";",1)[0] for k,v in headers if k.lower()=="set-cookie"); self.csrf=[v.split(";",1)[0].split("=",1)[1] for k,v in headers if k.lower()=="set-cookie" and v.startswith("audit_csrf=")][0]
        status,_,body=self.request("/api/projects"); self.assertEqual(status,200); project=json.loads(body)["projects"][0]["id"]
        status,_,body=self.request("/api/assets","POST",{"project_id":project,"name":"Loopback Test","address":"127.0.0.2","criticality":"high"}); self.assertEqual(status,201)
        asset_id=json.loads(body)["id"]
        status,_,_=self.request(f"/api/assets/{asset_id}","PATCH",{"name":"Loopback Test Updated"}); self.assertEqual(status,200)
        with patch("security_audit.api.assessments.nmap_scanner.find_nmap",return_value=None):
            status,_,body=self.request("/api/assessments/network","POST",{"project_id":project,"target":"127.0.0.1/32","authorized":True})
        self.assertEqual(status,200); self.assertEqual(json.loads(body)["result"]["scope"],"127.0.0.1/32")
        db=connect(); network_assessment_id=db.execute("SELECT id FROM assessments WHERE project_id=? ORDER BY id DESC LIMIT 1",(project,)).fetchone()[0]; db.close()
        status,_,_=self.request("/api/assessments/local","POST",{"project_id":project}); self.assertEqual(status,400)
        with patch("security_audit.api.assessments.local_assessment",return_value={"facts":{"platform":"mock Windows","hostname":"fixture","collection_coverage":{"windows_app_permissions":{"status":"not_available","detail":"fixture limitation"}}},"findings":[],"summary":{"finding_count":0}}):
            status,_,body=self.request("/api/assessments/local","POST",{"project_id":project,"consent_confirmed":True})
        self.assertEqual(status,200); local=json.loads(body)["result"]; self.assertIn("platform",local["facts"])
        db=connect(); assessment_id=db.execute("SELECT id FROM assessments WHERE project_id=? ORDER BY id DESC LIMIT 1",(project,)).fetchone()[0]
        evidence={"source":"software inventory","product":"OpenSSL","version":"3.0.7","confidence":"candidate"}
        db.execute("INSERT INTO findings(project_id,assessment_id,title,category,severity,likelihood,impact,risk_score,description,evidence,verified,cve,cvss,remediation) VALUES(?,?,?,'vulnerability','high',3,8,4.8,?,?,0,'CVE-2023-0286',7.4,'Update to a supported fixed release')",(project,assessment_id,"Potentially affected OpenSSL","Candidate advisory match",json.dumps(evidence)))
        finding_id=db.execute("SELECT id FROM findings WHERE project_id=? ORDER BY id DESC LIMIT 1",(project,)).fetchone()[0]
        mapped_ids=grc.mapped_control_ids(db,"vulnerability")
        db.execute("UPDATE findings SET control_ids=? WHERE id=?",(json.dumps(mapped_ids),finding_id))
        db.execute("INSERT INTO evidence(finding_id,source,content,verified) VALUES(?,?,?,0)",(finding_id,"software inventory",json.dumps(evidence))); db.commit(); db.close()
        db=connect(); db.execute("INSERT INTO findings(project_id,assessment_id,title,category,severity,likelihood,impact,risk_score,description,evidence) VALUES(?,?,?,'network_exposure','info',3,0,0,?,'{}')",(project,network_assessment_id,"Network-only report marker","Must not leak into another assessment report")); db.execute("INSERT INTO evidence(finding_id,source,content,verified) VALUES(?,?,?,1)",(finding_id,"retest",json.dumps({"assessment_id":network_assessment_id,"passed":True,"notes":"OTHER_ASSESSMENT_RETEST_MARKER"}))); db.commit(); db.close()
        status,_,body=self.request(f"/api/findings?project_id={project}"); self.assertEqual(status,200); self.assertEqual(json.loads(body)["findings"][0]["cve"],"CVE-2023-0286")
        status,_,body=self.request(f"/api/findings/{finding_id}"); self.assertEqual(status,200); self.assertFalse(json.loads(body)["finding"]["verified"])
        status,_,_=self.request(f"/api/findings/{finding_id}","PATCH",{"status":"in_progress","severity":"critical"}); self.assertEqual(status,200)
        status,_,body=self.request(f"/api/findings?project_id={project}&q=OpenSSL"); self.assertEqual(json.loads(body)["findings"][0]["risk_score"],6.0)
        status,_,_=self.request(f"/api/findings/{finding_id}","PATCH",{"likelihood":5,"impact":9}); self.assertEqual(status,200)
        status,_,body=self.request(f"/api/findings?project_id={project}&q=OpenSSL"); self.assertEqual(json.loads(body)["findings"][0]["risk_score"],9.0)
        status,_,_=self.request(f"/api/findings/{finding_id}","PATCH",{"likelihood":8}); self.assertEqual(status,400)
        status,_,body=self.request(f"/api/dashboard?project_id={project}"); self.assertEqual(status,200); self.assertEqual(json.loads(body)["assessments"],2); self.assertEqual(len(json.loads(body)["risk_matrix"]),5)
        status,headers,body=self.request(f"/api/reports/json?project_id={project}&type=executive"); self.assertEqual(status,200); self.assertEqual(json.loads(body)["report_type"],"executive")
        status,headers,body=self.request(f"/api/reports/pdf?project_id={project}&type=technical"); self.assertEqual(status,200); self.assertTrue(body.startswith(b"%PDF-1.4"))
        status,headers,body=self.request(f"/api/reports/json?project_id={project}&type=technical&assessment_id={assessment_id}"); self.assertEqual(status,200)
        local_report=json.loads(body); self.assertEqual(local_report["assessment_id"],assessment_id); self.assertEqual([a["id"] for a in local_report["assessments"]],[assessment_id]); self.assertEqual([f["title"] for f in local_report["findings"]],["Potentially affected OpenSSL"]); self.assertIsNone(local_report["executive_summary"]["compliance_percentage"])
        self.assertEqual(local_report["executive_summary"]["total_findings"],1); self.assertEqual(local_report["executive_summary"]["status_counts"],{"in_progress":1}); self.assertEqual(local_report["executive_summary"]["total_risk_score"],9.0)
        self.assertIsNone(local_report["compliance"]["assessment"]["percentage"]); self.assertEqual(local_report["compliance"]["assessment"]["determination"],"Not assessed"); self.assertTrue(any(c["control_key"]=="7.1" for c in local_report["compliance"]["assessment"]["controls"]))
        self.assertNotIn("OTHER_ASSESSMENT_RETEST_MARKER",json.dumps(local_report))
        status,_,body=self.request(f"/api/findings?project_id={project}&assessment_id={assessment_id}"); self.assertEqual(status,200); self.assertEqual([f["title"] for f in json.loads(body)["findings"]],["Potentially affected OpenSSL"])
        status,_,body=self.request(f"/api/findings?project_id={project}&assessment_id={network_assessment_id}"); self.assertEqual(status,200); network_titles=[f["title"] for f in json.loads(body)["findings"]]; self.assertIn("Network-only report marker",network_titles); self.assertNotIn("Potentially affected OpenSSL",network_titles)
        status,headers,body=self.request(f"/api/reports/pdf?project_id={project}&type=technical&assessment_id={assessment_id}"); self.assertEqual(status,200); self.assertTrue(body.startswith(b"%PDF-1.4")); self.assertIn(f"security-technical-assessment-{assessment_id}.pdf",dict(headers)["Content-Disposition"]); self.assertIn(f"Report scope: Assessment #{assessment_id}".encode(),body); self.assertIn(b"Potentially affected OpenSSL",body); self.assertNotIn(b"Network-only report marker",body)
        self.assertIn(b"ASSESSMENT-LINKED COMPLIANCE EVIDENCE",body); self.assertIn(b"CIS v8 7.1",body); self.assertIn(b"Assessment compliance: Not assessed as pass/fail",body); self.assertIn(b"Asset criticality: medium",body); self.assertNotIn(b"OTHER_ASSESSMENT_RETEST_MARKER",body)
        status,_,body=self.request(f"/api/reports/json?project_id={project}&type=technical&assessment_id={network_assessment_id}"); self.assertEqual(status,200); network_report=json.loads(body); self.assertIn("Network-only report marker",[f["title"] for f in network_report["findings"]]); self.assertNotIn("Potentially affected OpenSSL",json.dumps(network_report))
        status,_,network_pdf=self.request(f"/api/reports/pdf?project_id={project}&type=technical&assessment_id={network_assessment_id}"); self.assertEqual(status,200); self.assertIn(b"Network-only report marker",network_pdf); self.assertNotIn(b"Potentially affected OpenSSL",network_pdf)
        status,_,_=self.request(f"/api/reports/pdf?project_id={project}&assessment_id=invalid"); self.assertEqual(status,400)
        status,_,_=self.request(f"/api/reports/pdf?project_id={project}&assessment_id=99999999"); self.assertEqual(status,404)
        db=connect(); organization_id=db.execute("SELECT organization_id FROM projects WHERE id=?",(project,)).fetchone()[0]; other_project=db.execute("INSERT INTO projects(organization_id,name,description) VALUES(?,?,?)",(organization_id,"Other report project","Test isolation")).lastrowid; other_assessment=db.execute("INSERT INTO assessments(project_id,kind,summary) VALUES(?,'local','{}')",(other_project,)).lastrowid; db.commit(); db.close()
        status,_,_=self.request(f"/api/reports/pdf?project_id={project}&assessment_id={other_assessment}"); self.assertEqual(status,404)
        status,_,_=self.request(f"/api/reports/pdf?project_id={project}&assessment_id={assessment_id}",auth=False); self.assertEqual(status,401)
        status,_,_=self.request("/api/assessments/network","POST",{"project_id":project,"target":"8.8.8.8","authorized":True}); self.assertEqual(status,400)
        status,_,body=self.request("/api/organizations"); org=json.loads(body)["organizations"][0]["id"]
        status,_,_=self.request("/api/users","POST",{"email":"viewer@example.test","password":"ViewerPassword!2026","organization_id":org,"organization_role":"viewer"}); self.assertEqual(status,201)
        status,headers,_=self.request("/api/auth/login","POST",{"email":"viewer@example.test","password":"ViewerPassword!2026"},False); self.assertEqual(status,200)
        self.session="; ".join(v.split(";",1)[0] for k,v in headers if k.lower()=="set-cookie"); self.csrf=[v.split(";",1)[0].split("=",1)[1] for k,v in headers if k.lower()=="set-cookie" and v.startswith("audit_csrf=")][0]
        status,_,body=self.request(f"/api/assessments?project_id={project}"); self.assertEqual(status,200); self.assertEqual(json.loads(body)["assessments"],[])
        status,_,body=self.request(f"/api/findings?project_id={project}"); self.assertEqual(status,200); self.assertEqual(json.loads(body)["findings"],[])
        status,_,_=self.request(f"/api/reports/pdf?project_id={project}"); self.assertEqual(status,403)
        status,_,_=self.request(f"/api/reports/pdf?project_id={project}&assessment_id={assessment_id}"); self.assertEqual(status,404)
        status,_,_=self.request(f"/api/assets?project_id={project}"); self.assertEqual(status,200)
        status,_,_=self.request("/api/assets","POST",{"project_id":project,"name":"Viewer must not create"}); self.assertEqual(status,403)
        status,_,_=self.request(f"/api/assets?project_id={project}",auth=False); self.assertEqual(status,401)

class ScanJobWorkflowTests(unittest.TestCase):
    def test_background_scan_retry_cancel_evidence_and_lifecycle(self):
        path=Path(__file__).resolve().parent.parent/"work"/"scan-jobs-test.db"
        for suffix in ("","-wal","-shm"): Path(str(path)+suffix).unlink(missing_ok=True)
        old=os.environ.get("AUDIT_DB"); os.environ["AUDIT_DB"]=str(path); db=connect(); create_admin(db,"scan-admin@example.test","long-scan-password-123"); db.close()
        server=ThreadingHTTPServer(("127.0.0.1",0),Handler); thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        try:
            def request(path,method="GET",data=None,cookies="",csrf="",extra_headers=None):
                conn=http.client.HTTPConnection("127.0.0.1",server.server_address[1],timeout=10); headers={}
                if cookies: headers["Cookie"]=cookies
                if method!="GET": headers.update({"Content-Type":"application/json","X-CSRF-Token":csrf})
                headers.update(extra_headers or {})
                conn.request(method,path,json.dumps(data) if data is not None else None,headers); r=conn.getresponse(); result=(r.status,r.getheaders(),r.read()); conn.close(); return result
            status,headers,_=request("/api/auth/login","POST",{"email":"scan-admin@example.test","password":"long-scan-password-123"}); self.assertEqual(status,200)
            cookies="; ".join(v.split(";",1)[0] for k,v in headers if k.lower()=="set-cookie"); csrf=[v.split(";",1)[0].split("=",1)[1] for k,v in headers if k.lower()=="set-cookie" and v.startswith("audit_csrf=")][0]
            project=json.loads(request("/api/projects",cookies=cookies)[2])["projects"][0]["id"]
            status,_,_=request("/api/scan-jobs","POST",{"project_id":project,"kind":"local"},cookies,csrf); self.assertEqual(status,400)
            with patch("security_audit.api.assessments.local_assessment",return_value={"facts":{"hostname":"Mock local host","collection_coverage":{"windows_app_permissions":{"status":"not_available","detail":"fixture limitation"}}},"findings":[],"summary":{"finding_count":0}}):
                status,_,body=request("/api/scan-jobs","POST",{"project_id":project,"kind":"local","consent_confirmed":True},cookies,csrf); self.assertEqual(status,202)
                local_id=json.loads(body)["job_id"]
                local_deadline=time.monotonic()+10
                while time.monotonic()<local_deadline:
                    status,_,body=request("/api/scan-jobs/"+local_id,cookies=cookies); self.assertEqual(status,200); local_job=json.loads(body)["job"]
                    if local_job["status"] in ("completed","failed","cancelled"): break
                    time.sleep(.03)
                self.assertEqual(local_job["status"],"completed"); self.assertTrue(local_job["authorized"])
            audit=connect(); self.assertTrue(audit.execute("SELECT 1 FROM audit_log WHERE action='scan.consent_authorized' AND project_id=?",(project,)).fetchone()); audit.close()
            def staged_scan(target,authorized,public_authorized,progress,cancelled):
                if not staged_scan.calls: staged_scan.calls+=1; raise RuntimeError("controlled worker failure")
                progress(50,"Test fixture collector step")
                return {"scope":target,"hosts":[],"services":[],"findings":[{"title":"Test evidence-backed candidate","severity":"high","category":"vulnerability candidate","description":"Candidate only","evidence":{"source":"test collector","product":"OpenSSL","version":"3.0.7","confidence":"candidate"},"verified":False,"cve":"CVE-2023-0286","cvss":7.4,"remediation":"Verify against the vendor advisory."}],"summary":{"finding_count":1}}
            staged_scan.calls=0
            with patch("security_audit.api.assessments.network_assessment",side_effect=staged_scan):
                status,_,body=request("/api/scan-jobs","POST",{"project_id":project,"kind":"network","target":"127.0.0.1/32","authorized":True},cookies,csrf); self.assertEqual(status,202); failed_id=json.loads(body)["job_id"]
                status,_,_=request("/api/scan-jobs","POST",{"project_id":project,"kind":"network","target":"8.8.8.8","authorized":True},cookies,csrf); self.assertEqual(status,400)
                def poll(job_id,expected):
                    end=time.monotonic()+30
                    while time.monotonic()<end:
                        status,_,body=request("/api/scan-jobs/"+job_id,cookies=cookies); self.assertEqual(status,200); job=json.loads(body)["job"]
                        if job["status"] in ("failed","completed","cancelled"): break
                        time.sleep(.03)
                    self.assertEqual(job["status"],expected); return job
                first=poll(failed_id,"failed"); self.assertIn("controlled worker failure",first["error"])
                status,_,body=request("/api/scan-jobs/"+failed_id+"/retry","POST",{},cookies,csrf); self.assertEqual(status,202); done=poll(json.loads(body)["job_id"],"completed"); self.assertEqual(done["progress"],100)
                with patch("security_audit.api.assessments.network_assessment",return_value={"scope":"8.8.8.8/32","hosts":[],"services":[],"findings":[],"warnings":["mocked public-scope fixture"]}):
                    status,_,body=request("/api/scan-jobs","POST",{"project_id":project,"kind":"network","target":"8.8.8.8/32","authorized":True,"public_authorized":True},cookies,csrf); self.assertEqual(status,202); public_fixture=poll(json.loads(body)["job_id"],"completed"); self.assertEqual(public_fixture["target"],"8.8.8.8/32")
                with patch("security_audit.api.assessments.network_assessment",side_effect=AssertionError("invalid public target reached worker")):
                    for target in ("203.0.113.10","8.8.8.8/24"):
                        status,_,_=request("/api/scan-jobs","POST",{"project_id":project,"kind":"network","target":target,"authorized":True,"public_authorized":True},cookies,csrf); self.assertEqual(status,400)
                    original_validate=assessments.validate_scope
                    def reject_ambiguous_domain(target,authorized,public_authorized=False):
                        if target=="example.com": raise ValueError("domain resolves to multiple public addresses")
                        return original_validate(target,authorized,public_authorized)
                    with patch("security_audit.api.assessments.validate_scope",side_effect=reject_ambiguous_domain):
                        status,_,_=request("/api/scan-jobs","POST",{"project_id":project,"kind":"network","target":"example.com","authorized":True,"public_authorized":True},cookies,csrf); self.assertEqual(status,400)
                assessment_id=json.loads(done["result"]["summary"] and request("/api/assessments?project_id="+str(project),cookies=cookies)[2])["assessments"][0]["id"]
                status,_,body=request("/api/findings?project_id="+str(project),cookies=cookies); self.assertEqual(status,200); finding=json.loads(body)["findings"][0]; self.assertFalse(finding["verified"]); self.assertEqual(finding["cve"],"CVE-2023-0286"); self.assertIn("assessment_id",finding["evidence"])
                status,_,_=request(f"/api/findings/{finding['id']}","PATCH",{"status":"remediation"},cookies,csrf); self.assertEqual(status,200)
                status,_,_=request(f"/api/findings/{finding['id']}","PATCH",{"status":"retest"},cookies,csrf); self.assertEqual(status,200)
                status,_,_=request(f"/api/findings/{finding['id']}","PATCH",{"status":"closed"},cookies,csrf); self.assertEqual(status,400)
                status,_,body=request(f"/api/findings/{finding['id']}/retest","POST",{"passed":True,"source":"test verifier","evidence":"Fix rechecked; expected secure state observed.","assessment_id":assessment_id},cookies,csrf); self.assertEqual(status,200); self.assertEqual(json.loads(body)["status"],"closed")
                report=json.loads(request(f"/api/reports/json?project_id={project}&type=technical",cookies=cookies)[2]); self.assertEqual(len(report["findings"]),1)
                self.assertTrue(any("windows app permissions" in item.lower() for item in report["assessment_limitations"]))
                self.assertIn("plain_what",report["findings"][0]); self.assertIn("plain_why",report["findings"][0]); self.assertIn("plain_fix_check",report["findings"][0]); self.assertTrue(report["findings"][0]["cve_candidate"]); self.assertIn("CVSS",report["risk_methodology"]["cvss_note"])
                report_html=reports.html_bytes(report).decode("utf-8"); self.assertIn("What was detected",report_html); self.assertIn("Why it matters",report_html); self.assertIn("How to check the fix",report_html); self.assertIn("Scope and authorization",report_html); self.assertIn("Assessment coverage",report_html); self.assertIn("windows app permissions",report_html.lower()); self.assertIn("Glossary",report_html); self.assertIn("candidate advisory",report_html.lower())
                report_pdf=reports.pdf_bytes(report); self.assertIn(b"SCOPE AND AUTHORIZATION",report_pdf); self.assertIn(b"windows app permissions",report_pdf.lower()); self.assertIn(b"GLOSSARY",report_pdf); self.assertIn(b"How to check the fix",report_pdf)
                def wait_for_cancel(target,authorized,pub,progress,cancelled):
                    while not cancelled(): progress(20,"Still checking scoped hosts"); time.sleep(.01)
                    raise RuntimeError("Assessment cancelled")
                with patch("security_audit.api.assessments.network_assessment",side_effect=wait_for_cancel):
                    status,_,body=request("/api/scan-jobs","POST",{"project_id":project,"kind":"network","target":"127.0.0.1/32","authorized":True},cookies,csrf); self.assertEqual(status,202); job=json.loads(body)["job_id"]
                    status,_,_=request("/api/scan-jobs/"+job,"DELETE",cookies=cookies,csrf=csrf); self.assertEqual(status,202); poll(job,"cancelled")
                organization=json.loads(request("/api/organizations",cookies=cookies)[2])["organizations"][0]["id"]
                status,_,body=request("/api/scanner-agents","POST",{"organization_id":organization,"name":"Test LAN agent"},cookies,csrf); self.assertEqual(status,201); agent=json.loads(body); bearer={"Authorization":"Bearer "+agent["token"]}
                status,_,body=request("/api/agent/next",extra_headers=bearer); self.assertEqual(status,200); self.assertIsNone(json.loads(body)["job"])
                old_agent_required=os.environ.get("AUDIT_REQUIRE_SCANNER_AGENT"); os.environ["AUDIT_REQUIRE_SCANNER_AGENT"]="1"
                isolated=connect(); isolated.execute("INSERT INTO organizations(name) VALUES('Isolated agent test organization')"); isolated_org=isolated.execute("SELECT id FROM organizations WHERE name='Isolated agent test organization'").fetchone()[0]; isolated.execute("INSERT INTO projects(organization_id,name) VALUES(?,'Isolated project')",(isolated_org,)); isolated_project=isolated.execute("SELECT id FROM projects WHERE organization_id=?",(isolated_org,)).fetchone()[0]; isolated.commit(); isolated.close()
                status,_,response_body=request("/api/scan-jobs","POST",{"project_id":isolated_project,"kind":"network","target":"192.168.2.7/32","authorized":True},cookies,csrf); self.assertEqual(status,503,response_body)
                status,_,body=request("/api/scan-jobs","POST",{"project_id":project,"kind":"network","target":"192.168.1.7/32","authorized":True},cookies,csrf); self.assertEqual(status,202); assigned=json.loads(body); self.assertEqual(assigned["scanner_agent_id"],agent["id"])
                status,_,body=request("/api/agent/next",extra_headers=bearer); self.assertEqual(status,200); task=json.loads(body)["job"]; self.assertEqual(task["target"],"192.168.1.7/32")
                status,_,body=request("/api/agent/jobs/"+task["id"]+"/progress","POST",{"progress":20,"message":"Checking authorized host"},extra_headers=bearer); self.assertEqual(status,200); self.assertFalse(json.loads(body)["cancelled"])
                endpoint="/api/agent/jobs/"+task["id"]+"/result"; invalid={"scope":"192.168.1.7/32","hosts":[{"address":"192.168.1.8"}],"findings":[]}
                status,_,_=request(endpoint,"POST",{"result":invalid},extra_headers=bearer); self.assertEqual(status,400)
                valid={"scope":"192.168.1.7/32","hosts":[],"services":[],"findings":[],"summary":{"finding_count":0},"scope_details":{"checks_completed":1,"checks_unavailable":[]}}
                status,_,body=request(endpoint,"POST",{"result":valid},extra_headers=bearer); self.assertEqual(status,200); self.assertEqual(json.loads(body)["status"],"completed")
                status,_,body=request("/api/scan-jobs/"+task["id"],cookies=cookies); self.assertEqual(status,200); self.assertEqual(json.loads(body)["job"]["result"]["source"],"organization scanner agent")
                report=json.loads(request(f"/api/reports/json?project_id={project}&assessment_id={json.loads(body)['job']['result']['assessment_id']}&type=technical",cookies=cookies)[2]); self.assertEqual(report["scope_authorization"][0]["source"],"organization scanner agent")
                status,_,_=request("/api/scanner-agents/"+agent["id"],"DELETE",{},cookies,csrf); self.assertEqual(status,200)
                status,_,_=request("/api/agent/next",extra_headers=bearer); self.assertEqual(status,401)
                if old_agent_required is None: os.environ.pop("AUDIT_REQUIRE_SCANNER_AGENT",None)
                else: os.environ["AUDIT_REQUIRE_SCANNER_AGENT"]=old_agent_required
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2); os.environ.pop("AUDIT_DB",None) if old is None else os.environ.__setitem__("AUDIT_DB",old)
            for suffix in ("","-wal","-shm"): Path(str(path)+suffix).unlink(missing_ok=True)

class ResetWorkflowTests(unittest.TestCase):
    def test_admin_reset_requires_confirmation_clears_assessment_records_and_preserves_setup(self):
        tmp=Path(__file__).resolve().parent.parent/"work"/"reset-run"; tmp.mkdir(parents=True,exist_ok=True); db_path=tmp/"reset.db"
        for suffix in ("","-wal","-shm"):
            Path(str(db_path)+suffix).unlink(missing_ok=True)
        old_db=os.environ.get("AUDIT_DB"); os.environ["AUDIT_DB"]=str(db_path)
        try:
            db=connect(); admin=create_admin(db,"reset-admin@example.test","long-reset-password-123"); project=db.execute("SELECT id FROM projects LIMIT 1").fetchone()[0]; control=db.execute("SELECT id FROM controls LIMIT 1").fetchone()[0]
            org=db.execute("SELECT organization_id FROM projects WHERE id=?",(project,)).fetchone()[0]; viewer=db.execute("INSERT INTO users(email,password_hash,role) VALUES(?,?,'member') RETURNING id",("reset-viewer@example.test",pw_hash("long-viewer-password-123"))).fetchone()[0]; db.execute("INSERT INTO memberships(user_id,organization_id,role) VALUES(?,?,'viewer')",(viewer,org))
            assessment=db.execute("INSERT INTO assessments(project_id,kind,summary) VALUES(?,'local','{}') RETURNING id",(project,)).fetchone()[0]
            asset=db.execute("INSERT INTO assets(project_id,name) VALUES(?,'Reset fixture') RETURNING id",(project,)).fetchone()[0]
            finding=db.execute("INSERT INTO findings(project_id,assessment_id,asset_id,title,severity) VALUES(?,?,?,'Reset fixture finding','high') RETURNING id",(project,assessment,asset)).fetchone()[0]
            db.execute("INSERT INTO evidence(finding_id,source,content) VALUES(?,?,?)",(finding,"test","fixture")); db.execute("INSERT INTO control_results(project_id,control_id,status) VALUES(?,?,'partial')",(project,control)); db.execute("INSERT INTO audit_log(user_id,project_id,action,entity) VALUES(?,?,'fixture.event','test')",(admin,project)); db.commit(); db.close()
            server=ThreadingHTTPServer(("127.0.0.1",0),Handler); thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
            try:
                def request(path,method="GET",data=None,cookies="",csrf=""):
                    conn=http.client.HTTPConnection("127.0.0.1",server.server_address[1],timeout=10); headers={}
                    if cookies: headers["Cookie"]=cookies
                    if method!="GET": headers.update({"Content-Type":"application/json","X-CSRF-Token":csrf})
                    conn.request(method,path,json.dumps(data) if data is not None else None,headers); response=conn.getresponse(); result=(response.status,response.getheaders(),response.read()); conn.close(); return result
                status,headers,_=request("/api/auth/login","POST",{"email":"reset-admin@example.test","password":"long-reset-password-123"}); self.assertEqual(status,200)
                cookies="; ".join(v.split(";",1)[0] for k,v in headers if k.lower()=="set-cookie"); csrf=[v.split(";",1)[0].split("=",1)[1] for k,v in headers if k.lower()=="set-cookie" and v.startswith("audit_csrf=")][0]
                status,_,_=request("/api/reset","POST",{"confirmation":"wrong"},cookies,csrf); self.assertEqual(status,400)
                status,viewer_headers,_=request("/api/auth/login","POST",{"email":"reset-viewer@example.test","password":"long-viewer-password-123"}); self.assertEqual(status,200)
                viewer_cookies="; ".join(v.split(";",1)[0] for k,v in viewer_headers if k.lower()=="set-cookie"); viewer_csrf=[v.split(";",1)[0].split("=",1)[1] for k,v in viewer_headers if k.lower()=="set-cookie" and v.startswith("audit_csrf=")][0]
                status,_,_=request("/api/reset","POST",{"confirmation":"ERASE ALL SAVED ASSESSMENT DATA"},viewer_cookies,viewer_csrf); self.assertEqual(status,403)
                status,_,_=request("/api/reset","POST",{"confirmation":"ERASE ALL SAVED ASSESSMENT DATA"},cookies,csrf); self.assertEqual(status,200)
                status,_,dashboard=request(f"/api/dashboard?project_id={project}",cookies=cookies); self.assertEqual(status,200); dashboard=json.loads(dashboard); self.assertEqual(dashboard["assets"],0); self.assertEqual(dashboard["findings"],0); self.assertEqual(dashboard["assessments"],0); self.assertTrue(all(value==0 for value in dashboard["severity"].values()))
                db=connect()
                for table in ("assets","assessments","findings","evidence","control_results"): self.assertEqual(db.execute(f"SELECT count(*) FROM {table}").fetchone()[0],0,table)
                self.assertEqual(db.execute("SELECT count(*) FROM audit_log").fetchone()[0],1); self.assertEqual(db.execute("SELECT action FROM audit_log").fetchone()[0],"workspace.data_reset"); self.assertEqual(db.execute("SELECT count(*) FROM users").fetchone()[0],2); self.assertEqual(db.execute("SELECT count(*) FROM organizations").fetchone()[0],1); self.assertEqual(db.execute("SELECT count(*) FROM projects").fetchone()[0],1); self.assertGreater(db.execute("SELECT count(*) FROM templates").fetchone()[0],0); self.assertGreater(db.execute("SELECT count(*) FROM controls").fetchone()[0],0); db.close()
            finally:
                server.shutdown(); server.server_close(); thread.join(timeout=2)
        finally:
            if old_db is None: os.environ.pop("AUDIT_DB",None)
            else: os.environ["AUDIT_DB"]=old_db
            for suffix in ("","-wal","-shm"):
                Path(str(db_path)+suffix).unlink(missing_ok=True)

if __name__=="__main__":unittest.main()
