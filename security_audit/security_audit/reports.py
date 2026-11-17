"""
JSON, PDF, and HTML report generation with finding correlation support.
"""
from __future__ import annotations

import datetime
import html
import json
import os
import re
import textwrap
from typing import Any

from .correlation import correlate_findings, get_service_group
from . import android_device, grc, risk


ASSESSMENT_CHECK_CONTROL_MAP = {
    "device_info": (("NIST CSF 2.0", "ID.AM-01"),),
    "visible_app_inventory": (("NIST CSF 2.0", "ID.AM-02"),),
    "security_patch": (("CIS v8", "7.1"), ("ISO 27001:2022", "A.8.8"), ("SOC 2", "CC7.1")),
    "secure_screen_lock": (("CIS v8", "4.1"), ("NIST CSF 2.0", "PR.PS-01"), ("ISO 27001:2022", "A.8.9")),
    "adb_debugging": (("CIS v8", "4.1"), ("NIST CSF 2.0", "PR.PS-01"), ("ISO 27001:2022", "A.8.9")),
    "developer_options": (("CIS v8", "4.1"), ("NIST CSF 2.0", "PR.PS-01"), ("ISO 27001:2022", "A.8.9")),
    "storage_encryption": (("CIS v8", "4.1"), ("NIST CSF 2.0", "PR.PS-01"), ("ISO 27001:2022", "A.8.9")),
}


def _assessment_compliance(db, assessment: dict[str, Any], raw_findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Return evidence-linked framework references, never a compliance verdict."""
    mapped: dict[int, dict[str, Any]] = {}

    def add_mapping(framework: str, control_key: str, evidence: dict[str, Any]) -> None:
        control = db.execute(
            "SELECT id,framework,control_key,title,description FROM controls WHERE framework=? AND control_key=?",
            (framework, control_key),
        ).fetchone()
        if not control:
            return
        entry = mapped.setdefault(int(control["id"]), {
            "framework": control["framework"], "control_key": control["control_key"],
            "title": control["title"], "description": control["description"],
            "assessment_status": "mapped_evidence_review_required", "evidence": [],
        })
        if evidence not in entry["evidence"]:
            entry["evidence"].append(evidence)

    for finding in raw_findings:
        for control_id in finding.get("control_ids", []):
            try:
                control = db.execute(
                    "SELECT framework,control_key FROM controls WHERE id=?", (int(control_id),)
                ).fetchone()
            except (TypeError, ValueError):
                control = None
            if control:
                add_mapping(control["framework"], control["control_key"], {
                    "source_type": "assessment_finding", "finding_id": finding.get("id"),
                    "finding_title": finding.get("title"), "category": finding.get("category"),
                    "severity": finding.get("severity"),
                })

    summary = assessment.get("summary") if isinstance(assessment.get("summary"), dict) else {}
    facts = summary.get("facts") if isinstance(summary.get("facts"), dict) else {}
    checks = facts.get("check_results") if isinstance(facts.get("check_results"), dict) else {}
    for check_name, check in checks.items():
        if not isinstance(check, dict) or check.get("status") != "checked":
            continue
        for framework, control_key in ASSESSMENT_CHECK_CONTROL_MAP.get(check_name, ()):
            add_mapping(framework, control_key, {
                "source_type": "assessment_check", "check": check_name,
                "status": check.get("status"),
                **({"value": check["value"]} if isinstance(check.get("value"), (str, int, bool)) else {}),
                **({"detail": check["detail"]} if isinstance(check.get("detail"), str) else {}),
            })

    controls = sorted(mapped.values(), key=lambda item: (item["framework"], item["control_key"]))
    return {
        "assessment_scoped": True,
        "determination": "Not assessed",
        "percentage": None,
        "mapped_controls_count": len(controls),
        "controls": controls,
        "method_note": "These framework references are mapped from evidence collected by this assessment. They are review pointers only, not pass/fail results or a certification determination.",
        "excluded_project_level_data": "Project-level or manually recorded control results are excluded unless directly linked to evidence from this assessment.",
    }


def get_display_status(f: dict[str, Any]) -> str:
    status_val = str(f.get("status") or f.get("port_status") or "open").strip()
    if status_val in ("Open or Filtered (UDP)", "open or filtered (udp)"):
        return "Open or Filtered (UDP)"
    proto = str(f.get("protocol") or (f.get("evidence") or {}).get("protocol") or "").lower()
    state = str((f.get("evidence") or {}).get("state") or "").lower()
    if proto == "udp" and state not in ("open", "open|responding"):
        return "Open or Filtered (UDP)"
    if f.get("port_status"):
        return str(f["port_status"])
    return status_val.replace("_", " ").title()


def format_evidence_bullets(finding: dict[str, Any]) -> list[str]:
    """
    Format evidence for human-readable and GRC-friendly reporting.
    """
    bullets: list[str] = []
    ev = finding.get("evidence") or {}
    if not isinstance(ev, dict):
        return [str(ev)[:120]] if ev else ["Scanner observation recorded"]

    corr_ev = ev.get("correlated_evidence")
    if corr_ev and isinstance(corr_ev, list):
        for entry in corr_ev:
            if isinstance(entry, dict):
                src = str(entry.get("source", "")).strip()
                svc = str(entry.get("service", "")).strip()
                port = entry.get("port")
                prod = entry.get("product")
                ver = entry.get("version")
                if "tcp" in src.lower() and "connect" in src.lower():
                    bullets.append("Bounded TCP connectivity check")
                elif "udp" in src.lower():
                    bullets.append(f"Conservative UDP probe ({svc or 'port ' + str(port)})")
                elif "service detection" in src.lower() or "service banner" in src.lower():
                    if prod and ver:
                        bullets.append(f"Service identification ({prod} {ver})")
                    else:
                        bullets.append(f"Service identification ({svc or 'detected'})")
                elif svc and not src:
                    bullets.append(f"Service identification ({svc})")
                elif src:
                    bullets.append(src)
                elif entry.get("details"):
                    bullets.append(str(entry.get("details"))[:120])
            elif entry:
                bullets.append(str(entry)[:120])

    if not bullets:
        for rec in finding.get("evidence_records", []):
            src = rec.get("source", "")
            cnt = rec.get("content", {})
            if isinstance(cnt, dict) and cnt.get("source"):
                bullets.append(str(cnt["source"]))
            elif src:
                bullets.append(str(src))

    if not bullets:
        if ev.get("source"):
            src = str(ev["source"])
            if "tcp" in src.lower() and "connect" in src.lower():
                bullets.append("Bounded TCP connectivity check")
            else:
                bullets.append(src)
        if ev.get("service"):
            bullets.append(f"Service identification ({ev['service']})")
        if ev.get("details"):
            bullets.append(str(ev["details"])[:120])

    # Deduplicate while preserving order
    seen: set[str] = set()
    deduped: list[str] = []
    for b in bullets:
        cleaned = b.strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            deduped.append(cleaned)

    return deduped or ["Bounded security check observation recorded"]


def collect(db, project_id: int, mode: str = "technical", assessment_id: int | None = None) -> dict[str, Any]:
    project = db.execute(
        "SELECT p.*, o.name organization FROM projects p JOIN organizations o ON o.id=p.organization_id WHERE p.id=?",
        (project_id,),
    ).fetchone()
    if not project:
        raise ValueError("Project not found")

    if assessment_id is not None and not db.execute(
        "SELECT 1 FROM assessments WHERE id=? AND project_id=?",
        (assessment_id, project_id),
    ).fetchone():
        raise ValueError("Assessment not found in this project")

    findings_sql = "SELECT f.*, a.name asset_name, a.criticality asset_criticality FROM findings f LEFT JOIN assets a ON a.id=f.asset_id WHERE f.project_id=?"
    findings_args: tuple[Any, ...] = (project_id,)
    if assessment_id is not None:
        findings_sql += " AND f.assessment_id=?"
        findings_args += (assessment_id,)
    findings_sql += " ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.created_at DESC"

    raw_findings = [
        dict(x)
        for x in db.execute(findings_sql, findings_args)
    ]
    for x in raw_findings:
        try:
            x["evidence"] = json.loads(x["evidence"])
        except Exception:
            pass
        try:
            x["control_ids"] = json.loads(x["control_ids"])
        except Exception:
            x["control_ids"] = []
        x["evidence_records"] = []
        for evidence_row in db.execute(
            "SELECT id, source, content, verified, collected_at FROM evidence WHERE finding_id=? ORDER BY id",
            (x["id"],),
        ):
            try:
                evidence_content = json.loads(evidence_row["content"])
            except (TypeError, ValueError, json.JSONDecodeError):
                evidence_content = evidence_row["content"]
            if assessment_id is not None and evidence_row["source"] == "retest" and isinstance(evidence_content, dict) and evidence_content.get("assessment_id") not in (None, assessment_id):
                continue
            x["evidence_records"].append(dict(evidence_row, content=evidence_content))

    # Correlate duplicate observations, then calculate with the same shared model
    # used by API updates and assessment persistence (never reuse stale scores).
    findings = [risk.calculate_finding_risk(f, {"criticality": f.get("asset_criticality")}) for f in correlate_findings(raw_findings)]
    retests_by_finding: dict[int, list[dict[str, Any]]] = {}
    for row in db.execute("SELECT finding_id, content FROM evidence WHERE source='retest' ORDER BY id",()):
        try:
            retest = json.loads(row["content"])
            if assessment_id is not None and retest.get("assessment_id") not in (None, assessment_id):
                continue
            retests_by_finding.setdefault(int(row["finding_id"]), []).append(retest)
        except (TypeError, ValueError, json.JSONDecodeError): pass
    for finding in findings:
        finding["retest_results"] = [entry for source_id in finding.get("source_finding_ids", [finding.get("id")]) for entry in retests_by_finding.get(int(source_id), []) if isinstance(entry, dict)]
        # Everyday wording deliberately describes observations rather than claiming
        # an exploitable vulnerability from a reachable service or version guess.
        service = finding.get("service") or (finding.get("evidence") or {}).get("service") or "service"
        port = finding.get("port") or (finding.get("evidence") or {}).get("port")
        protocol = str(finding.get("protocol") or (finding.get("evidence") or {}).get("protocol") or "tcp").lower()
        if port and protocol == "udp" and finding.get("port_status") == "Open or Filtered (UDP)":
            finding["plain_what"] = f"UDP/{port} was reported Open or Filtered. The available evidence does not establish that a UDP service is open or identify it as {service}."
        elif port and protocol == "udp" and finding.get("service_verification_status") != "confirmed":
            finding["plain_what"] = f"UDP/{port} returned an open-state response, but protocol-specific identification of {service} remains unverified. This response alone does not prove a security weakness."
        elif port and finding.get("service_verification_status") != "confirmed":
            finding["plain_what"] = f"TCP/{port} is confirmed reachable; {service} is a candidate service identification. Reachability does not by itself prove a security weakness."
        else:
            finding["plain_what"] = (f"The assessment observed {service} responding on {protocol.upper()} port {port}. A response means the service is reachable; it does not by itself prove a security weakness." if port else str(finding.get("description") or "The assessment recorded a security-related observation for this asset."))
        if finding.get("cve") and not (finding.get("cve_verified") or finding.get("advisory_verified")):
            finding["plain_what"] = f"The observed software details resemble candidate advisory {finding['cve']}. The match has not been confirmed against the vendor's affected-version guidance."
        finding["plain_why"] = ("If this service is not needed or is reachable by too many people, it can create an unnecessary path into the organization. Confirm its business need and restrict access." if port else "Reviewing this observation helps determine whether the system's protection or configuration needs attention.")
        finding["risk"] = finding.get("risk") or risk.calculate_finding_risk(finding)["risk"]
        finding["plain_risk"] = f"Internal risk is {finding['risk_score']:.1f}/10 ({finding['risk_band']}). Likelihood {finding['likelihood']}/5 and impact {finding['impact']}/10 are combined using the documented Sentinel formula. This is separate from CVSS."
        finding["plain_evidence"] = format_evidence_bullets(finding)
        finding["plain_fix_check"] = ("After restricting or disabling the service, rerun the same authorized assessment and confirm the service is no longer reachable from the tested location; if it must remain available, verify access is limited to approved systems." if port else "Apply the vendor-approved corrective change, then rerun the relevant check and compare the new evidence with this finding.")
        finding["plain_uncertainty"] = ("Service reachability is an observation, not proof of a vulnerability. Network filtering, UDP response behavior, version-detection limits, and the point-in-time nature of this assessment can affect results." if port else "Scanner evidence and candidate advisory matches do not alone establish exploitability. Confirm the asset, software version, and current vendor guidance.")
        # `verified` describes collection evidence, not proof that an advisory
        # applies. Only a dedicated advisory-verification flag may clear candidate status.
        finding["cve_candidate"] = bool(finding.get("cve") and not (finding.get("cve_verified") or finding.get("advisory_verified")))

    assessments_sql = "SELECT id, project_id, asset_id, authorized_by, kind, status, started_at, completed_at, summary FROM assessments WHERE project_id=?"
    assessments_args: tuple[Any, ...] = (project_id,)
    if assessment_id is not None:
        assessments_sql += " AND id=?"
        assessments_args += (assessment_id,)
    assessments_sql += " ORDER BY id DESC LIMIT 50"
    assessments = [
        dict(x)
        for x in db.execute(assessments_sql, assessments_args)
    ]
    for x in assessments:
        try:
            x["summary"] = json.loads(x["summary"])
            if x.get("kind") == "android_device":
                if mode == "technical":
                    x["summary"] = android_device.restore_inventory(x["summary"], os.environ.get("AUDIT_SECRET", "").strip())
                else:
                    facts = x["summary"].get("facts", {})
                    facts.pop("apps_encrypted", None)
                    facts["apps_inventory_included_in_report"] = False
        except Exception:
            pass

    scope_authorization = []
    assessment_limitations = []
    for assessment in assessments:
        summary = assessment.get("summary") if isinstance(assessment.get("summary"), dict) else {}
        facts = summary.get("facts") if isinstance(summary.get("facts"), dict) else {}
        coverage = facts.get("collection_coverage") if isinstance(facts.get("collection_coverage"), dict) else {}
        device_details = {"device": facts.get("device", {}), "apps": facts.get("apps", []), "checks": facts.get("check_results", {}), "visible_app_count": facts.get("visible_app_count", 0), "inventory_scope": facts.get("inventory_scope", "launcher_visible_apps"), "inventory_truncated": facts.get("inventory_truncated", False), "collection_method": facts.get("collection_method", "android_companion")} if mode == "technical" and assessment.get("kind") == "android_device" else {}
        detail = {"assessment_id": assessment.get("id"), "project_id": assessment.get("project_id"), "asset_id": assessment.get("asset_id"), "authorized_by": assessment.get("authorized_by"), "kind": assessment.get("kind"), "status": assessment.get("status"), "started_at": assessment.get("started_at"), "completed_at": assessment.get("completed_at"), "scope": summary.get("scope", "Local system" if assessment.get("kind") == "local" else "Not recorded"), "authorized": summary.get("assessment", {}).get("authorized"), "public_authorized": summary.get("assessment", {}).get("public_authorized"), "source": summary.get("source", summary.get("assessment", {}).get("engine", summary.get("scope_details", {}).get("engine", assessment.get("kind")))), "method": summary.get("scope_details", {}).get("engine", assessment.get("kind")), "coverage": coverage, "scope_details": summary.get("scope_details", {}), "network_summary": summary.get("network_summary", {}), "android_device": device_details}
        scope_authorization.append(detail)
        for check, state in coverage.items():
            if isinstance(state, dict) and state.get("status") in ("unavailable", "permission_required", "not_available", "not_checked"):
                label = check.replace("_", " ")
                assessment_limitations.append(f"Assessment #{assessment.get('id')}: {label} check {state.get('status')}: {state.get('detail') or state.get('limitation') or 'coverage was limited.'}")
        for warning in summary.get("warnings", []) or summary.get("scope_details", {}).get("warnings", []):
            assessment_limitations.append(f"Assessment #{assessment.get('id')}: {warning}")

    counts = {
        s: sum(
            1
            for f in findings
            if f.get("severity") == s
            and f.get("status") not in ("closed", "accepted", "resolved", "false_positive")
        )
        for s in ("critical", "high", "medium", "low", "info")
    }
    status_counts: dict[str, int] = {}
    for finding in findings:
        status = str(finding.get("status") or "open")
        status_counts[status] = status_counts.get(status, 0) + 1

    controls = grc.evaluate(db, project_id) if assessment_id is None else []
    compliance_counts = {
        status: sum(1 for c in controls if c.get("status") == status)
        for status in ("implemented", "partial", "not_implemented", "not_applicable", "not_assessed")
    }
    assessed_controls = len(controls) - compliance_counts["not_assessed"]
    applicable_controls = len(controls) - compliance_counts["not_applicable"]
    compliance_pct = None if assessment_id is not None else round(
        (compliance_counts["implemented"] / max(1, applicable_controls)) * 100, 1
    )
    assessment_compliance = _assessment_compliance(db, assessments[0], raw_findings) if assessment_id is not None and assessments else None

    active_findings = [f for f in findings if f.get("status") not in ("closed", "accepted", "resolved", "false_positive")]
    risk_band_counts = {band: 0 for band in ("critical", "high", "medium", "low", "info")}
    for finding in active_findings:
        derived = risk.calculate_finding_risk(finding, {"criticality": finding.get("asset_criticality")})
        risk_band_counts[derived["risk_band"]] += 1
    risk_matrix = risk.matrix(active_findings)
    open_findings = sum(counts.values())
    total_risk_score = round(
        sum(
            float(risk.calculate_finding_risk(f, {"criticality": f.get("asset_criticality")}).get("risk_score", 0))
            for f in findings
            if f.get("status") not in ("closed", "accepted", "resolved", "false_positive")
        ),
        1,
    )

    result = {
        "report_type": mode,
        "assessment_id": assessment_id,
        "organization": project["organization"],
        "project": project["name"],
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "executive_summary": {
            "open_findings": open_findings,
            "total_findings": len(findings),
            "status_counts": status_counts,
            "severity_counts": counts,
            "risk_band_counts": risk_band_counts,
            "total_risk_score": total_risk_score,
            "assessments": len(assessments),
            "compliance_percentage": compliance_pct,
            "controls_assessed": assessed_controls,
            "key_risks": [
                f["title"]
                for f in findings
                if f.get("severity") in ("critical", "high")
                and f.get("status") not in ("accepted", "resolved")
            ][:5],
        },
        "findings": findings if mode == "technical" else [f for f in findings if f.get("severity") in ("critical", "high")],
        "raw_findings_count": len(raw_findings),
        "assessments": assessments,
        "scope_authorization": scope_authorization,
        "assessment_limitations": list(dict.fromkeys(assessment_limitations)),
        "risk_methodology": {"name": "Sentinel internal risk score", "formula": "impact × likelihood ÷ 5 × asset criticality multiplier", "range": "0–10", "bands": "critical ≥8; high ≥4.5; medium ≥2; low ≥0.1; info = 0", "cvss_note": "CVSS is a separate technical vulnerability severity score; it is not the Sentinel business-risk score."},
        "risk_matrix": risk_matrix,
        "risk_matrix_bands": risk.matrix_risk_bands(),
        "glossary": {"Finding": "An item that needs review; it may be a confirmed issue or an observation.", "Evidence": "Information collected during the assessment; evidence verification does not prove exploitability.", "Severity": "A category describing how serious the observed issue may be.", "Likelihood": "How plausible it is that the event could happen, scored 1–5.", "Impact": "How much harm it could cause, scored 0–10.", "CVSS": "A separate standardized technical severity score when available.", "Retest": "A follow-up check after a fix is applied."},
        "compliance": {
            "percentage": compliance_pct,
            "counts": compliance_counts,
            "controls": controls,
            "assessment": assessment_compliance,
        },
    }
    return result


def json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")


def pdf_bytes(payload: dict[str, Any]) -> bytes:
    lines = [
        "SENTINEL AUDIT | SECURITY ASSESSMENT",
        f"Organization: {payload['organization']}",
        f"Project: {payload['project']}",
        f"Report scope: Assessment #{payload['assessment_id']}" if payload.get("assessment_id") is not None else "Report scope: Entire project",
        f"Generated: {payload['generated_at']}",
        "",
        "EXECUTIVE SUMMARY",
        f"Open findings: {payload['executive_summary']['open_findings']}",
        f"Total internal risk points (sum of active findings): {payload['executive_summary'].get('total_risk_score', 0.0)}",
        "Risk method: impact x likelihood / 5 x asset criticality factor; 0-10. CVSS is separate.",
        f"Project-wide compliance: {payload['executive_summary'].get('compliance_percentage')}%" if payload['assessment_id'] is None and payload['executive_summary'].get('compliance_percentage') is not None else "Assessment compliance: Not assessed as pass/fail; see evidence-linked control mappings below.",
        f"Findings in report: {payload['executive_summary'].get('total_findings', len(payload.get('findings', [])))}; active: {payload['executive_summary']['open_findings']}",
    ]
    lines += [f"{s.title()}: {n}" for s, n in payload["executive_summary"]["severity_counts"].items()]
    if payload["executive_summary"].get("status_counts"):
        lines += ["Finding counts by workflow status:"] + [f"{status.replace('_', ' ').title()}: {count}" for status, count in sorted(payload["executive_summary"]["status_counts"].items())]
    lines += ["", "SCOPE AND AUTHORIZATION"]
    for scope in payload.get("scope_authorization", []):
        lines.append(f"Assessment #{scope.get('assessment_id')} | Type: {scope.get('kind')} | Status: {scope.get('status')} | Scope: {scope.get('scope')}")
        lines.append(f"Started: {scope.get('started_at')} | Completed: {scope.get('completed_at')} | Source: {scope.get('source')}")
        lines.append(f"Explicit authorization recorded: {scope.get('authorized')} | Public authorization: {scope.get('public_authorized')} | Method: {scope.get('method')}")
        coverage = scope.get("coverage", {})
        if coverage:
            lines.append("Coverage: " + "; ".join(f"{name.replace('_', ' ')}={state.get('status', 'unknown') if isinstance(state, dict) else 'unknown'}" for name, state in coverage.items()))
        details = scope.get("scope_details", {})
        net = scope.get("network_summary", {})
        if net:
            lines.append(f"Network summary: {net.get('hosts_discovered', 0)} discovered; {net.get('hosts_reachable', 0)} reachable; {net.get('hosts_uncertain', 0)} uncertain; {net.get('exposed_ports', 0)} exposed ports; {net.get('services_identified', 0)} services identified.")
            counts = net.get("severity_counts", {})
            if counts:
                lines.append("Finding counts: " + "; ".join(f"{name.title()} {counts.get(name, 0)}" for name in ("critical", "high", "medium", "low", "info")))
        elif details.get("hosts_requested") is not None:
            lines.append(f"Host coverage: {details.get('hosts_assessed', details.get('hosts_responding', 0))} assessed of {details.get('hosts_requested', 0)} requested; {details.get('hosts_uncertain', 0)} uncertain.")
    if not payload.get("scope_authorization"): lines.append("No assessment scope or authorization record is available.")
    lines += ["", "SEVERITY SUMMARY"] + [f"{s.title()}: {n}" for s, n in payload["executive_summary"]["severity_counts"].items()]
    lines += ["", "INTERNAL RISK BAND SUMMARY"] + [f"{s.title()}: {n}" for s,n in payload["executive_summary"].get("risk_band_counts",{}).items()]
    lines.append("5x5 risk matrix contains active finding counts by likelihood row (1-5) and impact band column (0-2, 3-4, 5-6, 7-8, 9-10).")
    lines += [" ".join(str(cell) for cell in row) for row in payload.get("risk_matrix", [])]
    lines += ["", "KEY RISKS"] + [
        "- " + x for x in payload["executive_summary"]["key_risks"] or ["No critical or high open findings."]
    ]

    compliance = payload.get("compliance", {})
    if payload.get("assessment_id") is not None:
        assessment_compliance = compliance.get("assessment") or {}
        lines += ["", "ASSESSMENT-LINKED COMPLIANCE EVIDENCE"]
        lines.append(str(assessment_compliance.get("method_note", "No compliance control mapping was recorded for this assessment.")))
        lines.append(str(assessment_compliance.get("excluded_project_level_data", "Project-level control results are not attributed to this assessment.")))
        mapped_controls = assessment_compliance.get("controls", [])
        if mapped_controls:
            for control in mapped_controls:
                lines.append(f"{control.get('framework')} {control.get('control_key')} | {control.get('title')} | Assessment status: {control.get('assessment_status')}")
                for evidence in control.get("evidence", []):
                    if evidence.get("source_type") == "assessment_finding":
                        lines.append(f"- Mapped from finding #{evidence.get('finding_id')} ({evidence.get('severity')}): {evidence.get('finding_title')} [category: {evidence.get('category')}]")
                    else:
                        value = f" value={evidence.get('value')}" if "value" in evidence else ""
                        lines.append(f"- Mapped from check {evidence.get('check')} ({evidence.get('status')}{value}){': ' + evidence['detail'] if evidence.get('detail') else ''}")
        else:
            lines.append("No evidence-linked control mappings were recorded for this assessment.")
        lines.append("A mapping is a review pointer, not a control pass/fail result or a compliance certification.")
    else:
        lines += ["", "PROJECT-WIDE COMPLIANCE RESULTS"]
        lines.append(f"Project-wide control results: {len(compliance.get('controls', []))} controls; {compliance.get('percentage')}% of applicable controls marked implemented.")
        for control in compliance.get("controls", []):
            lines.append(f"{control.get('framework')} {control.get('control_key')} | {control.get('title')} | Project status: {control.get('status')} | Assessor: {control.get('assessor') or 'not recorded'} | Updated: {control.get('updated_at') or 'not recorded'}")

    android_scopes = [item for item in payload.get("scope_authorization", []) if payload["report_type"] == "technical" and item.get("kind") == "android_device"]
    for item in android_scopes:
        device_data = item.get("android_device", {})
        device = device_data.get("device", {})
        lines += ["", "ANDROID DEVICE AUDIT", f"Assessment #{item.get('assessment_id')} | {item.get('scope')}"]
        lines.append(f"Manufacturer / model: {device.get('manufacturer', 'Unavailable')} / {device.get('model', 'Unavailable')}")
        lines.append(f"Android version / API level: {device.get('android_version', 'Unavailable')} / {device.get('sdk_int', 'Unavailable')}")
        lines.append(f"Security patch level: {device.get('security_patch') or 'Unavailable'}")
        check_source = "authorized Android Debug Bridge" if item.get("method") in ("adb_usb", "adb_wireless") else "Android public APIs"
        lines.append(f"Supported check results (source: {check_source}):")
        for check_name, check in device_data.get("checks", {}).items():
            value = f"; value: {check['value']}" if "value" in check else ""
            detail = f"; detail: {check['detail']}" if check.get("detail") else ""
            lines.append(f"- {check_name.replace('_', ' ').title()}: {check.get('status', 'unknown')}{value}{detail}")
        inventory_label = "Third-party app inventory collected by ADB" if device_data.get("inventory_scope") == "adb_third_party_packages" else "Launcher-visible app inventory"
        lines.append(f"{inventory_label}: {device_data.get('visible_app_count', 0)} apps; inventory is encrypted at rest and available only in this authenticated report.")
        for app in device_data.get("apps", []):
            lines.append(f"- {app.get('name') or app.get('package_name')} | {app.get('package_name')} | {app.get('version_name') or 'version unavailable'}")
        if device_data.get("inventory_truncated"):
            lines.append("Inventory limitation: collector reached its package-count limit; the list above is not the full device inventory.")
        for warning in item.get("scope_details", {}).get("warnings", []):
            lines.append(f"Limitation: {warning}")

    if payload["report_type"] == "technical":
        lines += ["", "CORRELATED TECHNICAL FINDINGS"]
        for f in payload["findings"]:
            lines.append("")
            lines.append(f"[{str(f.get('severity', 'info')).upper()}] {f.get('title', '')}")
            target = f.get("target_ip") or f.get("address")
            if f.get("asset_name"):
                lines.append(f"Asset: {f.get('asset_name')} | Criticality: {f.get('asset_criticality', 'medium')}")
            if target:
                lines.append(f"Target: {target}")
            if f.get("hostname"):
                lines.append(f"Hostname: {f['hostname']}")
            if f.get("port") is not None:
                proto = str(f.get("protocol", "tcp")).upper()
                lines.append(f"Port: {f['port']}/{proto}")
            status_val = get_display_status(f)
            lines.append(f"Status: {status_val} | Severity: {str(f.get('severity','info')).title()} | Sentinel internal risk: {f.get('risk_score',0)}/10 ({f.get('risk_band','info')})")
            lines.append(f"Likelihood: {f.get('likelihood',3)}/5 | Impact: {f.get('impact',5)}/10")
            risk_detail = f.get("risk", {})
            lines.append(f"Asset criticality: {risk_detail.get('asset_criticality', f.get('asset_criticality', 'medium'))} | Criticality multiplier: {risk_detail.get('criticality_multiplier', 1.0)} | Priority: {f.get('priority', risk_detail.get('priority', 'not recorded'))}")
            lines.append(f"Risk explanation: {f.get('risk',{}).get('explanation','Impact x likelihood / 5, adjusted by asset criticality. CVSS is separate.')}")
            lines.append(f"What was detected: {f.get('plain_what','Observation recorded; confirm with the owner.')}")
            lines.append(f"Why it matters: {f.get('plain_why','Review business relevance and exposure.')}")
            if f.get("cve"):
                lines.append(f"Candidate advisory: {f.get('cve')} | CVSS: {f.get('cvss') if f.get('cvss') is not None else 'not available'} | Candidate/unverified: {f.get('cve_candidate',False)}. CVSS is not the Sentinel internal score.")
            evidence_records = f.get("evidence_records", [])
            if evidence_records:
                lines.append("Evidence record sources:")
                for record in evidence_records:
                    lines.append(f"- {record.get('source', 'source not recorded')} | verified collection: {'yes' if record.get('verified') else 'no'} | collected: {record.get('collected_at', 'date not recorded')}")

            corr_count = f.get("correlated_count", 1)
            corr_note = f.get("correlation_note")
            if corr_count > 1 or corr_note:
                lines.append("")
                lines.append("Correlation:")
                note = (
                    corr_note
                    or f"This finding combines {corr_count} overlapping scanner observations for the same exposure."
                )
                for l in textwrap.wrap(note, width=72):
                    lines.append(l)

            lines.append("")
            lines.append("Description:")
            desc = str(f.get("description", "")).strip()
            for l in textwrap.wrap(desc, width=72) or ["No description provided."]:
                lines.append(l)

            lines.append("")
            lines.append("Recommended fix:")
            rem = str(f.get("remediation", "")).strip()
            for l in textwrap.wrap(rem, width=72) or ["No remediation guidance provided."]:
                lines.append(l)

            lines.append("")
            owner = f.get("assignee")
            due_date = f.get("due_date")
            if owner: lines.append(f"Responsible owner: {owner}")
            if due_date: lines.append(f"Due date: {due_date}")
            lines.append("How to check the fix:")
            for l in textwrap.wrap(str(f.get("plain_fix_check", "Repeat the relevant authorized check and compare the evidence.")), width=72): lines.append(l)
            lines.append("Uncertainty / limitation:")
            for l in textwrap.wrap(str(f.get("plain_uncertainty", "Point-in-time assessment; confirm results.")), width=72): lines.append(l)
            if f.get("retest_results"):
                lines.append("Retest results:")
                for retest in f["retest_results"]:
                    lines.append(f"- {'Passed' if retest.get('passed') else 'Failed'} on {retest.get('timestamp','date not recorded')} via {retest.get('source','source not recorded')}: {retest.get('notes','')}")
            lines.append("Evidence:")
            ev_bullets = f.get("plain_evidence") or format_evidence_bullets(f)
            for b in ev_bullets:
                for idx, bl in enumerate(textwrap.wrap(b, width=68)):
                    prefix = "- " if idx == 0 else "  "
                    lines.append(f"{prefix}{bl}")
            if evidence_records:
                lines.append("Evidence record details:")
                for record in evidence_records:
                    content = record.get("content", {})
                    if isinstance(content, dict):
                        content = json.dumps(content, ensure_ascii=True, sort_keys=True)
                    for wrapped in textwrap.wrap(str(content), width=68) or [""]:
                        lines.append(f"- {wrapped}")

    if payload.get("assessment_limitations"):
        lines += ["", "ASSESSMENT LIMITATIONS"] + ["- " + str(x) for x in payload["assessment_limitations"]]
    lines += ["", "REPORT LIMITATIONS", "Results are point-in-time and limited to the scope, visibility, and checks recorded in this report. They are not a guarantee of security or a complete audit of the environment."]
    if payload.get("report_type") == "technical":
        lines += ["", "GLOSSARY"]
        lines += [f"{term}: {meaning}" for term, meaning in payload.get("glossary", {}).items()]

    # Keep PDF text printable in the built-in Helvetica font
    pages = [lines[i : i + 48] for i in range(0, max(len(lines), 1), 48)]
    objects = []

    def add(x: bytes) -> int:
        objects.append(x)
        return len(objects)

    font = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    page_ids = []
    for page in pages:
        stream = (
            "BT /F1 9 Tf 48 790 Td 13 TL "
            + " ".join(
                "("
                + re.sub(r"[^\x20-\x7e]", "?", line).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
                + ") Tj T*"
                for line in page
            )
            + " ET"
        )
        content = add(f"<< /Length {len(stream.encode('latin-1'))} >>\nstream\n{stream}\nendstream".encode("latin-1"))
        page_ids.append(
            add(
                f"<< /Type /Page /Parent PAGES /MediaBox [0 0 612 842] /Resources << /Font << /F1 {font} 0 R >> >> /Contents {content} 0 R >>".encode()
            )
        )
    pages_id = add(
        ("<< /Type /Pages /Count %d /Kids [%s] >>" % (len(page_ids), " ".join(f"{x} 0 R" for x in page_ids))).encode()
    )
    catalog_id = add(f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode())
    for i in page_ids:
        objects[i - 1] = objects[i - 1].replace(b"PAGES", f"{pages_id} 0 R".encode())
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for i, obj in enumerate(objects, 1):
        offsets.append(len(out))
        out.extend(f"{i} 0 obj\n".encode() + obj + b"\nendobj\n")
    xref = len(out)
    out.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode())
    for off in offsets[1:]:
        out.extend(f"{off:010d} 00000 n \n".encode())
    out.extend(f"trailer\n<< /Size {len(offsets)} /Root {catalog_id} 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return bytes(out)


def html_bytes(payload: dict[str, Any]) -> bytes:
    """
    Generate a modern, responsive, and standalone HTML report.
    """
    org = html.escape(payload.get("organization", ""))
    proj = html.escape(payload.get("project", ""))
    gen = html.escape(payload.get("generated_at", ""))
    summary = payload.get("executive_summary", {})
    open_findings = summary.get("open_findings", 0)
    sev_counts = summary.get("severity_counts", {})
    key_risks = summary.get("key_risks", [])
    total_risk = summary.get("total_risk_score", 0.0)
    report_type = payload.get("report_type", "technical")

    findings_html = []
    for f in payload.get("findings", []):
        sev = html.escape(str(f.get("severity", "info")).lower())
        title = html.escape(str(f.get("title", "")))
        desc = html.escape(str(f.get("description", "")))
        remed = html.escape(str(f.get("remediation", "")))
        target = html.escape(str(f.get("target_ip") or f.get("address") or "N/A"))
        hostname = html.escape(str(f.get("hostname", "")))
        port = f.get("port")
        proto = html.escape(str(f.get("protocol", "tcp")).upper())
        port_display = f"{port}/{proto}" if port is not None else "Host / OS check"
        status_disp = html.escape(get_display_status(f))
        risk_score = f.get("risk_score", 0.0)
        risk_band = html.escape(str(f.get("risk_band", "info")))
        risk_detail = html.escape(str(f.get("risk", {}).get("explanation", "Impact x likelihood / 5, adjusted by asset criticality.")))
        what = html.escape(str(f.get("plain_what", f.get("description") or "Assessment observation recorded.")))
        why = html.escape(str(f.get("plain_why", "Review the business relevance and exposure.")))
        fix_check = html.escape(str(f.get("plain_fix_check", "Repeat the relevant authorized check after remediation.")))
        uncertainty = html.escape(str(f.get("plain_uncertainty", "Confirm this point-in-time observation with the asset owner.")))
        cve_html = (f"<p>Candidate advisory: {html.escape(str(f.get('cve')))}. CVSS: {html.escape(str(f.get('cvss') if f.get('cvss') is not None else 'not available'))} (separate from Sentinel internal risk). Applicability verified: {'No' if f.get('cve_candidate') else 'Yes'}.</p>" if f.get("cve") else "")
        owner_html = f"<div><b>Responsible owner:</b> {html.escape(str(f.get('assignee')))}</div>" if f.get("assignee") else ""
        due_html = f"<div><b>Due date:</b> {html.escape(str(f.get('due_date')))}</div>" if f.get("due_date") else ""
        retest_html = "".join(f"<li>{'Passed' if x.get('passed') else 'Failed'} — {html.escape(str(x.get('timestamp','')))} — {html.escape(str(x.get('notes','')))}</li>" for x in f.get("retest_results", [])) or "<li>No retest recorded.</li>"
        corr_count = f.get("correlated_count", 1)
        corr_note = html.escape(
            f.get("correlation_note")
            or (f"Combines {corr_count} overlapping observations." if corr_count > 1 else "")
        )

        bullets = format_evidence_bullets(f)
        ev_items = "".join(f"<li>{html.escape(b)}</li>" for b in bullets)

        corr_banner = (
            f'<div class="corr-box"><b>Correlation:</b> {corr_note}</div>'
            if corr_note
            else ""
        )

        findings_html.append(
            f"""
            <div class="finding-card {sev}">
              <div class="finding-header">
                <span class="badge {sev}">{sev.upper()}</span>
                <h3>{title}</h3>
              </div>
              <div class="finding-meta">
                <div><b>Target:</b> {target}</div>
                {f'<div><b>Hostname:</b> {hostname}</div>' if hostname else ''}
                <div><b>Port:</b> {port_display}</div>
                <div><b>Status:</b> {status_disp}</div>
                <div><b>Sentinel internal risk:</b> {risk_score}/10 ({risk_band})</div>
                <div><b>Likelihood / impact:</b> {f.get('likelihood',3)}/5 / {f.get('impact',5)}/10</div>
                {owner_html}{due_html}
              </div>
              {corr_banner}
              <div class="section-block"><h4>What was detected</h4><p>{what}</p></div>
              <div class="section-block"><h4>Why it matters</h4><p>{why}</p></div>
              <div class="section-block"><h4>Risk score explained</h4><p>{risk_detail} CVSS is a separate technical score, not the Sentinel internal risk score.</p></div>
              {f'<div class="section-block"><h4>Advisory candidate</h4>{cve_html}</div>' if f.get('cve') else ''}
              <div class="section-block"><h4>Technical description</h4><p>{desc or 'No additional technical description was recorded.'}</p></div>
              <div class="section-block">
                <h4>Remediation</h4>
                <p>{remed}</p>
              </div>
              <div class="section-block"><h4>Evidence and affected asset / service</h4><p>{target} · {port_display} · {status_disp}</p><ul>{ev_items}</ul></div>
              <div class="section-block"><h4>How to check the fix</h4><p>{fix_check}</p></div>
              <div class="section-block"><h4>Uncertainty / limitations</h4><p>{uncertainty}</p></div>
              <div class="section-block"><h4>Retest results</h4><ul>{retest_html}</ul></div>
            </div>
            """
        )

    scope_html = "".join(f"<li>Assessment #{html.escape(str(x.get('assessment_id')))} — {html.escape(str(x.get('scope')))} — authorized: {html.escape(str(x.get('authorized')))} — public authorization: {html.escape(str(x.get('public_authorized')))} — {html.escape(str(x.get('method')))}</li>" for x in payload.get("scope_authorization", [])) or "<li>No assessment scope or authorization record is available.</li>"
    coverage_html = "".join("<li>Assessment #" + html.escape(str(x.get("assessment_id"))) + ": " + html.escape("; ".join(f"{name.replace('_', ' ')} — {state.get('status', 'unknown') if isinstance(state, dict) else 'unknown'}" for name, state in x.get("coverage", {}).items())) + "</li>" for x in payload.get("scope_authorization", []) if x.get("coverage")) or "<li>No detailed collector coverage was recorded.</li>"
    android_html_parts = []
    for item in payload.get("scope_authorization", []):
        if report_type != "technical" or item.get("kind") != "android_device":
            continue
        details = item.get("android_device", {})
        device = details.get("device", {})
        check_rows = "".join(f"<li><b>{html.escape(str(name.replace('_', ' ').title()))}:</b> {html.escape(str(check.get('status', 'unknown')))}" + (f" · {html.escape(str(check['value']))}" if "value" in check else "") + (f" · {html.escape(str(check['detail']))}" if check.get("detail") else "") + "</li>" for name, check in details.get("checks", {}).items())
        app_rows = "".join(f"<li>{html.escape(str(app.get('name') or app.get('package_name')))} · {html.escape(str(app.get('package_name')))} · {html.escape(str(app.get('version_name') or 'version unavailable'))}</li>" for app in details.get("apps", [])[:100])
        if len(details.get("apps", [])) > 100:
            app_rows += f"<li>First 100 of {len(details['apps'])} apps shown.</li>"
        check_source = "authorized Android Debug Bridge" if item.get("method") in ("adb_usb", "adb_wireless") else "Android public APIs"
        inventory_label = "Third-party app inventory collected by ADB" if details.get("inventory_scope") == "adb_third_party_packages" else "Launcher-visible apps"
        android_html_parts.append(f"<section class=\"finding-card\"><h2>Android device audit</h2><p>{html.escape(str(item.get('scope')))} · Android {html.escape(str(device.get('android_version', 'unavailable')))} · patch {html.escape(str(device.get('security_patch') or 'unavailable'))}</p><h3>Checks (source: {check_source})</h3><ul>{check_rows or '<li>No device check results were recorded.</li>'}</ul><p>{inventory_label}: {int(details.get('visible_app_count', 0))}. Inventory is encrypted at rest and included only in this authenticated report.</p><ul>{app_rows or '<li>No launcher-visible apps were returned.</li>'}</ul><p>This is a limited Android audit, not a complete device scan. App version inventory alone does not establish CVE applicability.</p></section>")
    android_html = "".join(android_html_parts)
    limitations_html = "".join(f"<li>{html.escape(str(x))}</li>" for x in payload.get("assessment_limitations", [])) or "<li>No additional scan warning was recorded. Results are point-in-time and depend on network visibility.</li>"
    glossary_html = "".join(f"<li><b>{html.escape(str(k))}:</b> {html.escape(str(v))}</li>" for k,v in payload.get("glossary", {}).items())
    severity_html = "".join(f"<li>{html.escape(str(k.title()))}: {int(v)}</li>" for k,v in sev_counts.items())
    risk_bands_html = "".join(f"<li>{html.escape(str(k.title()))}: {int(v)}</li>" for k,v in summary.get("risk_band_counts",{}).items())
    risk_rows = "".join("<tr>"+"".join(f"<td>{int(cell)}</td>" for cell in row)+"</tr>" for row in payload.get("risk_matrix", []))
    content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinel Audit Report - {proj}</title>
<style>
  :root {{
    --bg: #0f172a; --panel: #1e293b; --text: #f8fafc; --muted: #94a3b8;
    --border: #334155; --critical: #ef4444; --high: #f97316;
    --medium: #f59e0b; --low: #3b82f6; --info: #64748b;
  }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 2rem; }}
  .container {{ max-width: 960px; margin: 0 auto; }}
  header {{ border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }}
  h1 {{ margin: 0 0 0.5rem 0; font-size: 1.8rem; color: #38bdf8; }}
  .meta-sub {{ color: var(--muted); font-size: 0.9rem; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .metric-card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; text-align: center; }}
  .metric-val {{ font-size: 1.8rem; font-weight: bold; margin-bottom: 0.25rem; }}
  .metric-lbl {{ color: var(--muted); font-size: 0.8rem; text-transform: uppercase; }}
  .finding-card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }}
  .finding-card.critical {{ border-left: 5px solid var(--critical); }}
  .finding-card.high {{ border-left: 5px solid var(--high); }}
  .finding-card.medium {{ border-left: 5px solid var(--medium); }}
  .finding-card.low {{ border-left: 5px solid var(--low); }}
  .finding-card.info {{ border-left: 5px solid var(--info); }}
  .finding-header {{ display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem; }}
  .finding-header h3 {{ margin: 0; font-size: 1.2rem; }}
  .badge {{ padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; color: #fff; }}
  .badge.critical {{ background: var(--critical); }}
  .badge.high {{ background: var(--high); }}
  .badge.medium {{ background: var(--medium); color: #000; }}
  .badge.low {{ background: var(--low); }}
  .badge.info {{ background: var(--info); }}
  .finding-meta {{ display: flex; flex-wrap: wrap; gap: 1.5rem; font-size: 0.9rem; margin-bottom: 1rem; color: var(--muted); background: rgba(0,0,0,0.2); padding: 0.75rem; border-radius: 6px; }}
  .finding-meta b {{ color: var(--text); }}
  .corr-box {{ background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 6px; padding: 0.75rem 1rem; font-size: 0.88rem; margin-bottom: 1rem; }}
  .section-block {{ margin-top: 1rem; }}
  .section-block h4 {{ margin: 0 0 0.4rem 0; font-size: 0.95rem; color: #38bdf8; text-transform: uppercase; letter-spacing: 0.05em; }}
  .section-block p {{ margin: 0; font-size: 0.95rem; line-height: 1.5; color: #cbd5e1; }}
  .section-block ul {{ margin: 0; padding-left: 1.2rem; color: #cbd5e1; font-size: 0.95rem; }}
  .section-block li {{ margin-bottom: 0.25rem; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>SENTINEL AUDIT | {report_type.upper()} REPORT</h1>
    <div class="meta-sub">
      <strong>Organization:</strong> {org} &nbsp;|&nbsp;
      <strong>Project:</strong> {proj} &nbsp;|&nbsp;
      <strong>Generated:</strong> {gen}
    </div>
  </header>

  <div class="summary-grid">
    <div class="metric-card"><div class="metric-val">{open_findings}</div><div class="metric-lbl">Open Findings</div></div>
    <div class="metric-card"><div class="metric-val" style="color:var(--critical);">{sev_counts.get('critical', 0)}</div><div class="metric-lbl">Critical</div></div>
    <div class="metric-card"><div class="metric-val" style="color:var(--high);">{sev_counts.get('high', 0)}</div><div class="metric-lbl">High</div></div>
    <div class="metric-card"><div class="metric-val" style="color:var(--medium);">{sev_counts.get('medium', 0)}</div><div class="metric-lbl">Medium</div></div>
    <div class="metric-card"><div class="metric-val" style="color:var(--low);">{sev_counts.get('low', 0)}</div><div class="metric-lbl">Low</div></div>
    <div class="metric-card"><div class="metric-val">{total_risk}</div><div class="metric-lbl">Total Risk Score</div></div>
  </div>

  <section class="finding-card"><h2>Executive summary</h2><p>{open_findings} active finding records; risk-point total {total_risk}. Risk calculation: impact × likelihood ÷ 5, adjusted by asset criticality. Severity and internal risk are not CVSS.</p><h3>Severity summary</h3><ul>{severity_html}</ul><h3>Internal risk bands</h3><ul>{risk_bands_html}</ul><p>Risk matrix: active finding counts. Rows are likelihood 1–5; columns are impact bands 0–2, 3–4, 5–6, 7–8, 9–10.</p><table>{risk_rows}</table><h3>Scope and authorization</h3><ul>{scope_html}</ul><h3>Assessment coverage</h3><ul>{coverage_html}</ul><h3>Remediation plan</h3><p>Prioritize critical and high items, assign only the owner and due date recorded in each finding, apply the suggested change, then record a retest.</p><h3>Assessment limitations</h3><ul>{limitations_html}</ul></section>
  {android_html}
  <h2>Findings ({len(payload.get('findings', []))})</h2>
  {''.join(findings_html) if findings_html else '<p>No findings recorded.</p>'}
  <section class="finding-card"><h2>Glossary</h2><ul>{glossary_html}</ul></section>
</div>
</body>
</html>
"""
    return content.encode("utf-8")
