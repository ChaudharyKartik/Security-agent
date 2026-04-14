"""
Report Generator — JSON, HTML, PDF, CSV
All formats include PoC evidence, exploitation narratives, real CVSS scores.
"""
import json
import os
import csv
import logging
from datetime import datetime

logger = logging.getLogger(__name__)
REPORTS_DIR = "reports"

SEV_COLORS = {"Critical":"#dc2626","High":"#ea580c","Medium":"#d97706","Low":"#2563eb","Info":"#6b7280"}
STATUS_COLORS = {"approve":"#16a34a","reject":"#dc2626","escalate":"#9333ea","pending":"#6b7280"}


def generate_report(session: dict, format: str = "json") -> list:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    ts   = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    base = f"{REPORTS_DIR}/report_{session.get('session_id','unknown')}_{ts}"
    paths = []
    if format in ("json","both","all"):  paths.append(_gen_json(session, base))
    if format in ("html","both","all"):  paths.append(_gen_html(session, base))
    if format in ("pdf","all"):          paths.append(_gen_pdf(session, base))
    if format in ("csv","all"):          paths.append(_gen_csv(session, base))
    return paths


# ══════════════════════════════════════════════════════════════════════════════
# JSON
# ══════════════════════════════════════════════════════════════════════════════

def _gen_json(session: dict, base: str) -> str:
    path = base + ".json"
    report = {
        "report_meta": {
            "generated_at":  datetime.utcnow().isoformat(),
            "tool":          "AI Security Testing Agent v2.0",
            "session_id":    session.get("session_id"),
            "target":        session.get("target"),
            "auth_used":     session.get("auth_used","Unauthenticated"),
            "scan_duration": session.get("duration_seconds"),
        },
        "executive_summary":  session.get("summary",{}),
        "findings":           session.get("enriched_findings",[]),
        "modules_executed":   session.get("modules_executed",[]),
        "recon_data":         session.get("raw_results",{}).get("recon",{}),
    }
    with open(path,"w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info(f"[REPORT] JSON: {path}")
    return path


# ══════════════════════════════════════════════════════════════════════════════
# CSV
# ══════════════════════════════════════════════════════════════════════════════

def _gen_csv(session: dict, base: str) -> str:
    path     = base + ".csv"
    findings = session.get("enriched_findings",[])
    cols     = ["id","name","severity","cvss_score","cvss_vector","type","module","tool_used",
                "url","port","service","cve","cwe","exploitability","description",
                "solution","validation_status","validated_by","compliance","evidence_curl_poc"]

    with open(path,"w",newline="",encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for finding in findings:
            row = {col: finding.get(col,"") for col in cols}
            # Flatten compliance list
            row["compliance"] = " | ".join(finding.get("compliance",[]))
            # Pull curl PoC out of evidence dict
            row["evidence_curl_poc"] = (finding.get("evidence") or {}).get("curl_poc","")
            w.writerow(row)

    logger.info(f"[REPORT] CSV: {path}")
    return path


# ══════════════════════════════════════════════════════════════════════════════
# PDF
# ══════════════════════════════════════════════════════════════════════════════

def _gen_pdf(session: dict, base: str) -> str:
    path = base + ".pdf"
    try:
        from fpdf import FPDF

        class PDF(FPDF):
            def header(self):
                self.set_font("Helvetica","B",10)
                self.set_text_color(220,38,38)
                self.cell(0,8,"AI Security Testing Agent v2.0 — CONFIDENTIAL",0,1,"C")
                self.set_draw_color(51,65,85)
                self.line(10, self.get_y(), 200, self.get_y())
                self.ln(2)

            def footer(self):
                self.set_y(-12)
                self.set_font("Helvetica","I",8)
                self.set_text_color(100,116,139)
                self.cell(0,8,f"Page {self.page_no()} — Authorized Testing Only — {datetime.utcnow().strftime('%Y-%m-%d')}",0,0,"C")

        pdf = PDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        summary  = session.get("summary",{})
        findings = session.get("enriched_findings",[])
        target   = session.get("target","Unknown")
        bd       = summary.get("severity_breakdown",{})

        # ── Cover block ──────────────────────────────────────────────────────
        pdf.set_font("Helvetica","B",20)
        pdf.set_text_color(15,23,42)
        pdf.cell(0,12,"Security Assessment Report",0,1,"C")
        pdf.set_font("Helvetica","",12)
        pdf.set_text_color(100,116,139)
        pdf.cell(0,6,f"Target: {target}",0,1,"C")
        pdf.cell(0,6,f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",0,1,"C")
        pdf.cell(0,6,f"Auth: {session.get('auth_used','Unauthenticated')}",0,1,"C")
        pdf.ln(6)

        # ── Risk rating ──────────────────────────────────────────────────────
        rating = summary.get("risk_rating","UNKNOWN")
        rating_colors = {"CRITICAL":(220,38,38),"HIGH":(234,88,12),"MEDIUM":(217,119,6),
                         "LOW":(37,99,235),"CLEAN":(22,163,74)}
        rc = rating_colors.get(rating,(100,116,139))
        pdf.set_fill_color(*rc)
        pdf.set_text_color(255,255,255)
        pdf.set_font("Helvetica","B",16)
        pdf.cell(0,12,f"Overall Risk: {rating}",0,1,"C",True)
        pdf.ln(4)

        # ── Severity summary ─────────────────────────────────────────────────
        pdf.set_text_color(15,23,42)
        pdf.set_font("Helvetica","B",11)
        pdf.cell(0,8,"Severity Breakdown",0,1)
        pdf.set_font("Helvetica","",10)
        for sev, col in [("Critical",(220,38,38)),("High",(234,88,12)),
                         ("Medium",(217,119,6)),("Low",(37,99,235)),("Info",(107,114,128))]:
            count = bd.get(sev,0)
            pdf.set_fill_color(*col)
            pdf.set_text_color(255,255,255)
            pdf.cell(30,7,f"  {sev}",0,0,"L",True)
            pdf.set_text_color(15,23,42)
            pdf.set_fill_color(248,250,252)
            pdf.cell(20,7,str(count),0,0,"C",True)
            pdf.ln(8)
        pdf.ln(4)

        # ── Findings ─────────────────────────────────────────────────────────
        pdf.set_font("Helvetica","B",12)
        pdf.set_text_color(15,23,42)
        pdf.cell(0,8,"Findings",0,1)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(2)

        for idx, f in enumerate(findings, 1):
            sev    = f.get("severity","Info")
            sc     = {"Critical":(220,38,38),"High":(234,88,12),"Medium":(217,119,6),
                      "Low":(37,99,235),"Info":(107,114,128)}.get(sev,(107,114,128))

            # Finding header
            pdf.set_fill_color(*sc)
            pdf.set_text_color(255,255,255)
            pdf.set_font("Helvetica","B",10)
            title = f.get('name','Unknown')[:80]
            pdf.cell(0,8,f"  [{idx}] {title}",0,1,"L",True)

            # Metadata row
            pdf.set_text_color(100,116,139)
            pdf.set_font("Helvetica","",8)
            pdf.set_fill_color(248,250,252)
            meta = (f"ID: {f.get('id','-')}  |  CVSS: {f.get('cvss_score','-')}  |  "
                    f"Vector: {f.get('cvss_vector','-')[:40]}  |  "
                    f"Tool: {f.get('tool_used','-')}  |  Module: {f.get('module','-')}")
            pdf.multi_cell(0,5,meta,0,1)

            # Description
            pdf.set_text_color(15,23,42)
            pdf.set_font("Helvetica","B",9)
            pdf.cell(0,6,"Description:",0,1)
            pdf.set_font("Helvetica","",9)
            desc = f.get("description","")[:500]
            pdf.multi_cell(0,5,desc,0,1)

            # Exploitation narrative
            narr = f.get("exploitation_narrative","")
            if narr:
                pdf.set_font("Helvetica","B",9)
                pdf.set_text_color(127,0,0)
                pdf.cell(0,6,"Exploitation Narrative:",0,1)
                pdf.set_font("Helvetica","",8)
                pdf.set_text_color(50,50,50)
                # Strip markdown bold markers for PDF
                clean_narr = narr.replace("**","").replace("__","")[:700]
                pdf.multi_cell(0,4,clean_narr,0,1)

            # PoC Evidence
            evidence = f.get("evidence",{})
            poc = evidence.get("curl_poc","")
            if poc:
                pdf.set_font("Courier","B",8)
                pdf.set_text_color(99,102,241)
                pdf.cell(0,5,"PoC Command:",0,1)
                pdf.set_font("Courier","",7)
                pdf.set_fill_color(15,23,42)
                pdf.set_text_color(165,180,252)
                pdf.multi_cell(0,5,f"  {poc[:120]}",0,1,True)

            # Solution
            pdf.set_font("Helvetica","B",9)
            pdf.set_text_color(22,163,74)
            pdf.cell(0,6,"Recommendation:",0,1)
            pdf.set_font("Helvetica","",9)
            pdf.set_text_color(15,23,42)
            pdf.multi_cell(0,5,f.get("solution","")[:400],0,1)

            pdf.ln(4)
            pdf.set_draw_color(226,232,240)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(3)

        pdf.output(path)
        logger.info(f"[REPORT] PDF: {path}")
        return path

    except ImportError:
        logger.warning("[REPORT] fpdf2 not installed — generating placeholder PDF")
        with open(path,"w") as f:
            f.write(f"PDF generation requires fpdf2.\nRun: pip install fpdf2\n\nSession: {session.get('session_id')}")
        return path


# ══════════════════════════════════════════════════════════════════════════════
# HTML
# ══════════════════════════════════════════════════════════════════════════════

def _gen_html(session: dict, base: str) -> str:
    path     = base + ".html"
    summary  = session.get("summary",{})
    findings = session.get("enriched_findings",[])
    target   = session.get("target","Unknown")
    gen_at   = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    bd       = summary.get("severity_breakdown",{})
    modules  = ", ".join(session.get("modules_executed",[]))
    auth     = session.get("auth_used","Unauthenticated")

    def _badge(text, color):
        return f'<span style="background:{color};color:#fff;padding:2px 9px;border-radius:10px;font-size:11px;white-space:nowrap">{text}</span>'

    def _finding_block(f):
        sev    = f.get("severity","Info")
        col    = SEV_COLORS.get(sev,"#6b7280")
        status = f.get("validation_status","pending")
        sc     = STATUS_COLORS.get(status,"#6b7280")
        ev     = f.get("evidence",{}) or {}
        poc    = ev.get("curl_poc","")
        req    = ev.get("request","")
        resp_s = ev.get("response_snippet","") or ev.get("response_headers","")
        narr   = (f.get("exploitation_narrative","") or "").replace("\n","<br>").replace("**","<strong>").replace("**","</strong>")
        # Simple bold replacement
        import re
        narr = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', f.get("exploitation_narrative","") or "")
        narr = narr.replace("\n","<br>")

        compliance_tags = "".join(
            f'<span style="background:#0f172a;color:#64748b;border:1px solid #334155;'
            f'padding:1px 6px;border-radius:8px;font-size:10px;margin-right:3px">{c}</span>'
            for c in (f.get("compliance") or [])
        )

        cvss_metrics = f.get("cvss_metrics",{})
        cvss_detail = " | ".join(f"{k}:{v}" for k,v in cvss_metrics.items()) if cvss_metrics else ""

        poc_block = ""
        if poc:
            poc_block = f'''
<div style="margin-top:8px">
  <div style="font-size:11px;color:#a5b4fc;font-weight:600;margin-bottom:3px">PoC Command:</div>
  <pre style="background:#0f172a;color:#a5b4fc;padding:8px 10px;border-radius:4px;font-size:11px;overflow-x:auto;margin:0;border-left:3px solid #6366f1">{poc}</pre>
</div>'''

        evidence_block = ""
        if resp_s:
            evidence_block = f'''
<div style="margin-top:6px">
  <div style="font-size:11px;color:#94a3b8;font-weight:600;margin-bottom:3px">Response Evidence:</div>
  <pre style="background:#0f172a;color:#94a3b8;padding:6px 10px;border-radius:4px;font-size:10px;overflow-x:auto;max-height:120px;margin:0">{resp_s[:500]}</pre>
</div>'''

        narr_block = ""
        if narr:
            narr_block = f'''
<div style="margin-top:10px;background:#1a0505;border-left:3px solid #dc2626;padding:10px;border-radius:0 4px 4px 0">
  <div style="font-size:11px;color:#f87171;font-weight:600;margin-bottom:6px">Attacker Exploitation Chain:</div>
  <div style="font-size:12px;color:#fca5a5;line-height:1.7">{narr}</div>
</div>'''

        return f'''
<div style="border-left:4px solid {col};background:#1e293b;border-radius:0 8px 8px 0;padding:1.2rem 1.4rem;margin-bottom:1rem">
  <div style="display:flex;gap:8px;align-items:flex-start;flex-wrap:wrap;margin-bottom:8px">
    <span style="font-weight:600;flex:1;color:#f1f5f9;font-size:14px">{f.get('name','Unknown')}</span>
    {_badge(sev, col)} {_badge(status.upper(), sc)}
    {_badge(f"CVSS {f.get('cvss_score','-')}", '#475569') if f.get('cvss_score') else ''}
    {_badge(f'CVE:{f["cve"]}', '#7c3aed') if f.get('cve') else ''}
  </div>
  <div style="font-size:11px;color:#64748b;font-family:monospace;margin-bottom:8px">
    ID: {f.get('id','-')} | Module: {f.get('module','-')} | Tool: {f.get('tool_used','-')} | {f"Port: {f['port']}/{f.get('service','?')} |" if f.get('port') else ''} {cvss_detail}
  </div>
  <p style="font-size:13px;color:#cbd5e1;margin:0 0 6px"><strong style="color:#94a3b8">Description:</strong> {f.get('description','-')}</p>
  <p style="font-size:13px;color:#cbd5e1;margin:0 0 8px"><strong style="color:#94a3b8">Recommendation:</strong> {f.get('solution','-')}</p>
  <div style="font-size:12px;background:#0f172a;border-left:3px solid #6366f1;padding:8px 10px;border-radius:0 4px 4px 0;color:#a5b4fc;margin-bottom:8px">
    <strong>Analyst Note:</strong> {f.get('analyst_note','-')}
  </div>
  {poc_block}
  {evidence_block}
  {narr_block}
  <div style="margin-top:8px;display:flex;gap:4px;flex-wrap:wrap">{compliance_tags}</div>
</div>'''

    # Build grouped findings HTML
    grouped_html = ""
    for sev in ["Critical","High","Medium","Low","Info"]:
        sev_group = [f for f in findings if f.get("severity") == sev]
        if not sev_group: continue
        col = SEV_COLORS[sev]
        grouped_html += f'''
<div style="margin-bottom:1.5rem">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:.8rem;padding-bottom:6px;border-bottom:1px solid #334155">
    <span style="width:12px;height:12px;border-radius:50%;background:{col};display:inline-block"></span>
    <span style="font-size:1rem;font-weight:600;color:{col}">{sev}</span>
    <span style="font-size:12px;color:#64748b">{len(sev_group)} finding{"s" if len(sev_group)>1 else ""}</span>
  </div>
  {"".join(_finding_block(f) for f in sev_group)}
</div>'''

    # Tool breakdown table
    tool_breakdown = summary.get("tool_breakdown",{})
    tool_rows = "".join(
        f'<tr><td style="padding:5px 10px;color:#94a3b8">{tool}</td>'
        f'<td style="padding:5px 10px;color:#e2e8f0;font-weight:500">{count}</td></tr>'
        for tool, count in tool_breakdown.items()
    )

    rating = summary.get("risk_rating","UNKNOWN")
    rc = {"CRITICAL":"#dc2626","HIGH":"#ea580c","MEDIUM":"#d97706","LOW":"#2563eb","CLEAN":"#16a34a"}.get(rating,"#6b7280")

    html = f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Report — {target}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem;line-height:1.5}}
.container{{max-width:1040px;margin:0 auto}}
.card{{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:1.5rem;margin-bottom:1.5rem}}
pre{{white-space:pre-wrap;word-break:break-all}}
@media(max-width:600px){{body{{padding:1rem}}}}
</style>
</head><body><div class="container">

<div class="card">
  <div style="display:flex;justify-content:space-between;flex-wrap:wrap;gap:1rem">
    <div>
      <h1 style="font-size:1.5rem;color:#f8fafc;font-weight:700">Security Assessment Report</h1>
      <p style="color:#64748b;font-size:12px;margin-top:4px">AI Security Testing Agent v2.0 — Authorized Testing Only</p>
    </div>
    <div style="text-align:right;font-size:12px;color:#64748b">
      <div>Generated: {gen_at}</div>
      <div>Session: {session.get("session_id","-")}</div>
      <div>Duration: {session.get("duration_seconds","-")}s</div>
    </div>
  </div>
  <div style="display:flex;gap:2rem;margin-top:1rem;flex-wrap:wrap;font-size:13px">
    <span><span style="color:#64748b">Target: </span><strong style="color:#e2e8f0">{target}</strong></span>
    <span><span style="color:#64748b">Auth: </span><span style="color:#e2e8f0">{auth}</span></span>
    <span><span style="color:#64748b">Modules: </span><span style="color:#e2e8f0">{modules}</span></span>
  </div>
</div>

<div class="card" style="text-align:center">
  <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:2px">Overall Risk Rating</div>
  <div style="font-size:3.5rem;font-weight:800;margin:10px 0;color:{rc}">{rating}</div>
  <div style="font-size:13px;color:#64748b">Score: {summary.get("overall_risk_score",0)} | Findings: {summary.get("total_findings",0)}</div>
</div>

<div style="display:grid;grid-template-columns:repeat(5,1fr);gap:.8rem;margin-bottom:1.5rem">
  {"".join(f'<div style="background:#1e293b;border:1px solid #334155;border-radius:10px;padding:1rem;text-align:center"><div style="font-size:2rem;font-weight:700;color:{SEV_COLORS[s]}">{bd.get(s,0)}</div><div style="font-size:11px;color:#64748b;margin-top:2px">{s}</div></div>' for s in ["Critical","High","Medium","Low","Info"])}
</div>

{"" if not tool_breakdown else f'<div class="card"><h3 style="color:#f1f5f9;font-size:13px;margin-bottom:8px">Tools Used</h3><table style="width:100%;font-size:13px;border-collapse:collapse">{tool_rows}</table></div>'}

<h2 style="color:#f1f5f9;font-size:1rem;font-weight:600;border-bottom:1px solid #334155;padding-bottom:8px;margin-bottom:1.2rem">Findings</h2>
{grouped_html or '<p style="color:#64748b">No findings recorded.</p>'}

<div style="text-align:center;color:#334155;font-size:11px;margin-top:2rem;padding-top:1rem;border-top:1px solid #1e293b">
  AI Security Testing Agent v2.0 | Authorized testing only | {gen_at}
</div>

</div></body></html>'''

    with open(path,"w",encoding="utf-8") as f:
        f.write(html)
    logger.info(f"[REPORT] HTML: {path}")
    return path
