"""
Report Generator
Produces JSON and HTML reports from enriched session data.
"""
import json
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)
REPORTS_DIR = "reports"

SEV_COLORS = {
    "Critical": "#dc2626",
    "High":     "#ea580c",
    "Medium":   "#d97706",
    "Low":      "#2563eb",
    "Info":     "#6b7280",
}

STATUS_COLORS = {
    "approve":  "#16a34a",
    "reject":   "#dc2626",
    "escalate": "#9333ea",
    "pending":  "#6b7280",
}


def generate_report(session: dict, format: str = "json") -> list:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    base = f"{REPORTS_DIR}/report_{session.get('session_id', 'unknown')}_{ts}"

    paths = []
    if format in ("json", "both"):
        paths.append(_generate_json(session, base))
    if format in ("html", "both"):
        paths.append(_generate_html(session, base))

    return paths


def _generate_json(session: dict, base: str) -> str:
    path = base + ".json"
    report = {
        "report_meta": {
            "generated_at":  datetime.utcnow().isoformat(),
            "tool":          "AI Security Testing Agent v1.0",
            "session_id":    session.get("session_id"),
            "target":        session.get("target"),
            "scan_duration": session.get("duration_seconds"),
        },
        "executive_summary": session.get("summary", {}),
        "findings":          session.get("enriched_findings", []),
        "modules_executed":  session.get("modules_executed", []),
        "recon_data":        session.get("raw_results", {}).get("recon", {}),
    }
    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info(f"[REPORT] JSON written: {path}")
    return path


def _generate_html(session: dict, base: str) -> str:
    path = base + ".html"
    summary  = session.get("summary", {})
    findings = session.get("enriched_findings", [])
    target   = session.get("target", "Unknown")
    gen_at   = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    bd       = summary.get("severity_breakdown", {})
    modules  = ", ".join(session.get("modules_executed", []))

    # Build findings HTML
    findings_html = ""
    for f in findings:
        sev    = f.get("severity", "Info")
        col    = SEV_COLORS.get(sev, "#6b7280")
        status = f.get("validation_status", "pending")
        sc     = STATUS_COLORS.get(status, "#6b7280")
        cve_badge = (f'<span style="background:#7c3aed;color:#fff;padding:2px 8px;border-radius:10px;font-size:11px">'
                     f'CVE: {f["cve"]}</span>') if f.get("cve") else ""
        port_info = f'Port {f["port"]} | ' if f.get("port") else ""
        compliance_tags = " ".join(
            f'<span style="background:#0f172a;color:#64748b;border:1px solid #334155;padding:1px 7px;border-radius:8px;font-size:10px">{c}</span>'
            for c in (f.get("compliance") or [])
        )

        findings_html += f"""
<div style="border-left:4px solid {col};background:#1e293b;border-radius:0 8px 8px 0;padding:1.2rem 1.4rem;margin-bottom:1rem">
  <div style="display:flex;gap:8px;align-items:flex-start;margin-bottom:10px;flex-wrap:wrap">
    <span style="font-weight:600;flex:1;color:#f1f5f9;font-size:14px">{f.get('name','Unknown')}</span>
    <span style="background:{col};color:#fff;padding:2px 10px;border-radius:12px;font-size:11px;white-space:nowrap">{sev}</span>
    <span style="background:{sc};color:#fff;padding:2px 10px;border-radius:12px;font-size:11px;white-space:nowrap">{status.upper()}</span>
    {cve_badge}
  </div>
  <div style="font-size:11px;color:#64748b;margin-bottom:10px;font-family:monospace">
    {port_info}Module: {f.get('module','-')} | CVSS: {f.get('cvss_score','-')} | {f.get('exploitability','-')} | ID: {f.get('id','-')}
  </div>
  <p style="font-size:13px;color:#cbd5e1;margin:0 0 6px"><strong style="color:#94a3b8">Description: </strong>{f.get('description','-')}</p>
  <p style="font-size:13px;color:#cbd5e1;margin:0 0 8px"><strong style="color:#94a3b8">Recommendation: </strong>{f.get('solution','-')}</p>
  <div style="font-size:12px;background:#0f172a;border-left:3px solid #6366f1;padding:8px 10px;border-radius:0 4px 4px 0;color:#a5b4fc;margin-bottom:8px">
    <strong>Analyst Note:</strong> {f.get('analyst_note','-')}
  </div>
  <div style="display:flex;gap:4px;flex-wrap:wrap">{compliance_tags}</div>
</div>"""

    # Severity section grouping
    grouped_html = ""
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        sev_group = [f for f in findings if f.get("severity") == sev]
        if not sev_group:
            continue
        col = SEV_COLORS[sev]
        sev_findings_html = ""
        for f in sev_group:
            status = f.get("validation_status", "pending")
            sc = STATUS_COLORS.get(status, "#6b7280")
            cve_tag = f' <span style="color:#a78bfa;font-size:10px">{f["cve"]}</span>' if f.get("cve") else ""
            port_info = f'Port {f["port"]} | ' if f.get("port") else ""
            compliance_tags = " ".join(
                f'<span style="background:#0f172a;color:#64748b;border:1px solid #334155;padding:1px 6px;border-radius:8px;font-size:10px">{c}</span>'
                for c in (f.get("compliance") or [])
            )
            sev_findings_html += f"""
<div style="border-left:4px solid {col};background:#1e293b;border-radius:0 8px 8px 0;padding:1.1rem 1.3rem;margin-bottom:.8rem">
  <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px">
    <span style="font-weight:600;flex:1;color:#f1f5f9;font-size:13.5px">{f.get('name','Unknown')}{cve_tag}</span>
    <span style="background:{sc};color:#fff;padding:2px 9px;border-radius:10px;font-size:11px">{status.upper()}</span>
  </div>
  <div style="font-size:11px;color:#64748b;font-family:monospace;margin-bottom:8px">{port_info}Module: {f.get('module','-')} | CVSS: {f.get('cvss_score','-')} | ID: {f.get('id','-')}</div>
  <p style="font-size:13px;color:#cbd5e1;margin:0 0 5px"><strong style="color:#94a3b8">Description: </strong>{f.get('description','-')}</p>
  <p style="font-size:13px;color:#cbd5e1;margin:0 0 8px"><strong style="color:#94a3b8">Fix: </strong>{f.get('solution','-')}</p>
  <div style="font-size:12px;background:#0f172a;border-left:3px solid #6366f1;padding:7px 10px;border-radius:0 4px 4px 0;color:#a5b4fc;margin-bottom:7px">
    <strong>Note:</strong> {f.get('analyst_note','-')}
  </div>
  <div style="display:flex;gap:4px;flex-wrap:wrap">{compliance_tags}</div>
</div>"""
        grouped_html += f"""
<div style="margin-bottom:1.5rem">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:.8rem;padding-bottom:6px;border-bottom:1px solid #334155">
    <span style="width:12px;height:12px;border-radius:50%;background:{col};display:inline-block"></span>
    <span style="font-size:1rem;font-weight:600;color:{col}">{sev}</span>
    <span style="font-size:12px;color:#64748b">{len(sev_group)} finding{'s' if len(sev_group)>1 else ''}</span>
  </div>
  {sev_findings_html}
</div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Report — {target}</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; line-height: 1.5; }}
.container {{ max-width: 1020px; margin: 0 auto; }}
.card {{ background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 1.5rem; margin-bottom: 1.5rem; }}
@media (max-width: 600px) {{ body {{ padding: 1rem; }} }}
@media print {{
  body {{ background: #fff; color: #000; }}
  .card {{ border-color: #ccc; background: #f9f9f9; }}
}}
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="card">
    <div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:1rem">
      <div>
        <h1 style="font-size:1.5rem;color:#f8fafc;font-weight:700">Security Scan Report</h1>
        <p style="color:#64748b;font-size:13px;margin-top:4px">AI Security Testing Agent v1.0 — Authorized Testing Only</p>
      </div>
      <div style="text-align:right;font-size:12px;color:#64748b">
        <div>Generated: {gen_at}</div>
        <div>Duration: {session.get('duration_seconds', '-')}s</div>
        <div>Session: {session.get('session_id', '-')}</div>
      </div>
    </div>
    <div style="display:flex;gap:2rem;margin-top:1rem;flex-wrap:wrap;font-size:13px">
      <span><span style="color:#64748b">Target: </span><span style="color:#e2e8f0;font-weight:500">{target}</span></span>
      <span><span style="color:#64748b">Modules: </span><span style="color:#e2e8f0">{modules}</span></span>
    </div>
  </div>

  <!-- Risk Rating -->
  <div class="card" style="text-align:center">
    <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:2px">Overall Risk Rating</div>
    <div style="font-size:3.5rem;font-weight:800;margin:10px 0;color:{'#dc2626' if summary.get('risk_rating')=='CRITICAL' else '#ea580c' if summary.get('risk_rating')=='HIGH' else '#d97706' if summary.get('risk_rating')=='MEDIUM' else '#2563eb' if summary.get('risk_rating')=='LOW' else '#16a34a'}">{summary.get('risk_rating', 'UNKNOWN')}</div>
    <div style="font-size:13px;color:#64748b">Risk Score: {summary.get('overall_risk_score', 0)} | Total Findings: {summary.get('total_findings', 0)}</div>
  </div>

  <!-- Severity breakdown -->
  <div style="display:grid;grid-template-columns:repeat(5,1fr);gap:.8rem;margin-bottom:1.5rem">
    <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;padding:1rem;text-align:center">
      <div style="font-size:2rem;font-weight:700;color:#dc2626">{bd.get('Critical',0)}</div>
      <div style="font-size:11px;color:#64748b;margin-top:2px">Critical</div>
    </div>
    <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;padding:1rem;text-align:center">
      <div style="font-size:2rem;font-weight:700;color:#ea580c">{bd.get('High',0)}</div>
      <div style="font-size:11px;color:#64748b;margin-top:2px">High</div>
    </div>
    <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;padding:1rem;text-align:center">
      <div style="font-size:2rem;font-weight:700;color:#d97706">{bd.get('Medium',0)}</div>
      <div style="font-size:11px;color:#64748b;margin-top:2px">Medium</div>
    </div>
    <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;padding:1rem;text-align:center">
      <div style="font-size:2rem;font-weight:700;color:#2563eb">{bd.get('Low',0)}</div>
      <div style="font-size:11px;color:#64748b;margin-top:2px">Low</div>
    </div>
    <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;padding:1rem;text-align:center">
      <div style="font-size:2rem;font-weight:700;color:#6b7280">{bd.get('Info',0)}</div>
      <div style="font-size:11px;color:#64748b;margin-top:2px">Info</div>
    </div>
  </div>

  <!-- Findings by severity -->
  <h2 style="color:#f1f5f9;font-size:1rem;font-weight:600;border-bottom:1px solid #334155;padding-bottom:8px;margin-bottom:1.2rem">Findings</h2>
  {grouped_html if grouped_html else '<p style="color:#64748b">No findings recorded.</p>'}

  <div style="text-align:center;color:#334155;font-size:11px;margin-top:2rem;padding-top:1rem;border-top:1px solid #1e293b">
    Generated by AI Security Testing Agent v1.0 | For authorized testing only | {gen_at}
  </div>

</div>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    logger.info(f"[REPORT] HTML written: {path}")
    return path
