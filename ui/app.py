"""
Streamlit UI — AI Security Testing Agent v1.0
Run: streamlit run ui/app.py
"""
import streamlit as st
import requests
import time
import json
from datetime import datetime

API_BASE = "http://localhost:8000"

st.set_page_config(
    page_title="AI Security Agent",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
.stApp { background-color: #0f172a; }
section[data-testid="stSidebar"] { background-color: #1e293b; }
.metric-card {
    background: #1e293b; border: 1px solid #334155; border-radius: 10px;
    padding: 1rem; text-align: center;
}
.finding-card {
    background: #1e293b; border-radius: 8px; padding: 1rem;
    margin-bottom: .6rem; border-left: 4px solid #6b7280;
}
.tag {
    display: inline-block; padding: 2px 10px; border-radius: 12px;
    font-size: 11px; font-weight: 500; margin-right: 4px;
}
</style>
""", unsafe_allow_html=True)

SEV_COLORS = {
    "Critical": "#dc2626", "High": "#ea580c",
    "Medium": "#d97706", "Low": "#2563eb", "Info": "#6b7280",
}
STATUS_ICONS = {
    "queued": "⏳", "running": "🔄", "recon": "🔍",
    "scanning": "⚡", "enrichment": "🧠",
    "awaiting_validation": "✋", "completed": "✅", "error": "❌",
}

PHASE_PROGRESS = {
    "queued": 5, "recon": 20, "scanning": 55,
    "enrichment": 85, "awaiting_validation": 100,
    "completed": 100, "error": 100,
}


# ── API helpers ───────────────────────────────────────────────────────────────
def api_get(endpoint: str, params: dict = None):
    try:
        r = requests.get(f"{API_BASE}{endpoint}", params=params, timeout=12)
        return r.json() if r.ok else None
    except Exception:
        return None


def api_post(endpoint: str, payload: dict):
    try:
        r = requests.post(f"{API_BASE}{endpoint}", json=payload, timeout=30)
        return r.json()
    except Exception as e:
        return {"error": str(e)}


def api_delete(endpoint: str):
    try:
        r = requests.delete(f"{API_BASE}{endpoint}", timeout=10)
        return r.json() if r.ok else None
    except Exception:
        return None


def check_api() -> bool:
    result = api_get("/health")
    return result is not None and result.get("status") == "healthy"


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🔐 Security Agent")
    st.caption("AI-Driven Multi-Agent Security Testing")
    st.divider()

    api_alive = check_api()
    if api_alive:
        st.success("API Online", icon="✅")
    else:
        st.error("API Offline", icon="🔴")
        st.caption("Start with: `uvicorn main:app --reload`")

    st.divider()
    page = st.radio(
        "Navigation",
        ["🎯 New Scan", "📊 Sessions", "✅ Validate Findings",
         "📄 Generate Report", "📖 API Docs"],
        label_visibility="collapsed",
    )


# ══════════════════════════════════════════════════════════════════════════════
# Page: New Scan
# ══════════════════════════════════════════════════════════════════════════════
if page == "🎯 New Scan":
    st.title("🎯 Start New Security Scan")
    st.caption("Parallel Web · Network · Cloud agents with AI-driven enrichment")

    with st.form("scan_form"):
        col1, col2 = st.columns([3, 1])
        with col1:
            target = st.text_input(
                "Target URL / IP Address",
                placeholder="https://example.com  or  192.168.1.1",
                help="Enter a full URL or IP address. The agent will auto-detect web/network/cloud type.",
            )
        with col2:
            run_cloud = st.checkbox(
                "Include Cloud Scan",
                help="Runs Prowler (AWS/GCP/Azure) checks. Uses mock data if Prowler not installed.",
            )
        description = st.text_input("Description (optional)", placeholder="Q3 Web App Assessment")
        submitted = st.form_submit_button("🚀 Launch Scan", type="primary", use_container_width=True)

    if submitted:
        if not target or not target.strip():
            st.warning("Please enter a target URL or IP address.")
        elif not api_alive:
            st.error("Cannot connect to the API. Ensure FastAPI is running.")
        else:
            result = api_post("/scan", {"target": target.strip(),
                                        "run_cloud": run_cloud,
                                        "description": description})
            if "error" in result:
                st.error(f"Failed to start scan: {result['error']}")
            else:
                session_id = result.get("session_id")
                st.success(f"Scan launched! Session ID: `{session_id}`")
                st.session_state["active_session"] = session_id

                # Live progress tracking
                st.divider()
                st.subheader("Live Scan Progress")
                progress_bar  = st.progress(0)
                status_text   = st.empty()
                phase_display = st.empty()

                for _ in range(180):  # 6 min max
                    time.sleep(2)
                    status_data = api_get(f"/session/{session_id}/status")
                    if not status_data:
                        break

                    curr    = status_data.get("status", "running")
                    prog    = PHASE_PROGRESS.get(curr, 50)
                    n_finds = status_data.get("total_findings", 0)
                    icon    = STATUS_ICONS.get(curr, "⚙️")

                    progress_bar.progress(prog)
                    status_text.markdown(
                        f"**Status:** {icon} `{curr.replace('_',' ').title()}` &nbsp;|&nbsp; "
                        f"**Findings so far:** {n_finds}"
                    )
                    phase_display.caption(
                        "Recon → [Network | Web | Cloud] (parallel) → Enrichment → Validation"
                    )

                    if curr in ("awaiting_validation", "completed", "error"):
                        break

                # Final summary
                final = api_get(f"/session/{session_id}/status")
                if final and final.get("status") != "error":
                    st.balloons()
                    st.success(f"Scan complete! Found **{final.get('total_findings', 0)}** vulnerabilities.")
                    bd = final.get("summary", {}).get("severity_breakdown", {})

                    c1, c2, c3, c4, c5 = st.columns(5)
                    for col_obj, sev in [(c1, "Critical"), (c2, "High"),
                                         (c3, "Medium"),  (c4, "Low"), (c5, "Info")]:
                        col_obj.metric(sev, bd.get(sev, 0))

                    st.info(
                        f"Risk Rating: **{final.get('summary', {}).get('risk_rating', '?')}** | "
                        f"Session: `{session_id}` | Go to **Validate Findings** to review."
                    )
                elif final and final.get("status") == "error":
                    st.error(f"Scan error: {final.get('error', 'Unknown error')}")


# ══════════════════════════════════════════════════════════════════════════════
# Page: Sessions
# ══════════════════════════════════════════════════════════════════════════════
elif page == "📊 Sessions":
    st.title("📊 Scan Sessions")

    col_refresh, col_spacer = st.columns([1, 5])
    with col_refresh:
        if st.button("🔄 Refresh"):
            st.rerun()

    data = api_get("/sessions")
    if not data:
        st.error("Cannot connect to the API.")
    elif data.get("count", 0) == 0:
        st.info("No scan sessions yet. Start a new scan.")
    else:
        st.caption(f"Total sessions: **{data['count']}**")
        st.divider()

        for s in reversed(data.get("sessions", [])):
            icon    = STATUS_ICONS.get(s.get("status", ""), "❓")
            sid     = s["session_id"]
            risk    = s.get("risk_rating", "-")
            n_finds = s.get("total_findings", 0)

            with st.expander(
                f"{icon} `[{sid}]` {s.get('target', '?')} — "
                f"{n_finds} finding{'s' if n_finds != 1 else ''} | {risk}"
            ):
                c1, c2, c3, c4 = st.columns(4)
                c1.write(f"**Status:** {s.get('status')}")
                c2.write(f"**Risk:** {risk}")
                c3.write(f"**Findings:** {n_finds}")
                c4.write(f"**Started:** {s.get('created_at', '-')[:19]}")

                if s.get("description"):
                    st.caption(f"Description: {s['description']}")

                b1, b2, b3 = st.columns(3)
                if b1.button("Load for Validation", key=f"load_{sid}"):
                    st.session_state["active_session"] = sid
                    st.success(f"Session `{sid}` loaded. Go to Validate Findings.")
                if b2.button("Quick Report (JSON)", key=f"report_{sid}"):
                    r = api_get(f"/report/{sid}", {"format": "json"})
                    if r:
                        st.code(r.get("files", []), language="text")
                if b3.button("Delete", key=f"del_{sid}"):
                    api_delete(f"/session/{sid}")
                    st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# Page: Validate Findings
# ══════════════════════════════════════════════════════════════════════════════
elif page == "✅ Validate Findings":
    st.title("✅ Human Validation")
    st.caption("Review AI-enriched findings. Approve, reject false positives, or escalate.")

    session_id = st.text_input(
        "Session ID",
        value=st.session_state.get("active_session", ""),
        placeholder="e.g. AB12CD34",
    )

    if not session_id:
        st.info("Enter a session ID above or load one from the Sessions page.")
        st.stop()

    data = api_get(f"/session/{session_id}")
    if not data:
        st.error(f"Session `{session_id}` not found.")
        st.stop()

    findings = data.get("enriched_findings", [])
    summary  = data.get("summary", {})
    bd       = summary.get("severity_breakdown", {})

    st.caption(
        f"Target: **{data.get('target')}** | "
        f"Status: **{data.get('status')}** | "
        f"Findings: **{len(findings)}** | "
        f"Risk: **{summary.get('risk_rating', '-')}**"
    )

    # Summary metrics
    c1, c2, c3, c4, c5 = st.columns(5)
    for col_obj, sev in [(c1, "Critical"), (c2, "High"), (c3, "Medium"), (c4, "Low"), (c5, "Info")]:
        col_obj.metric(sev, bd.get(sev, 0))

    st.divider()

    # Validator info + filters
    vcol1, vcol2, vcol3 = st.columns([2, 2, 1])
    with vcol1:
        validator_name = st.text_input("Your Name / Role", value="Sr. Security Consultant")
    with vcol2:
        filter_sev = st.multiselect(
            "Filter by Severity",
            ["Critical", "High", "Medium", "Low", "Info"],
            default=["Critical", "High", "Medium", "Low", "Info"],
        )
    with vcol3:
        filter_status = st.selectbox("Filter by Status", ["all", "pending", "approve", "reject", "escalate"])

    # Batch validation
    with st.expander("Batch Validate All Pending"):
        b1, b2 = st.columns(2)
        pending_ids = [f["id"] for f in findings if f.get("validation_status") == "pending"]
        if b1.button(f"✅ Approve All Pending ({len(pending_ids)})", use_container_width=True):
            result = api_post(f"/validate/{session_id}/batch",
                              {"approved_ids": pending_ids, "rejected_ids": [],
                               "validator_name": validator_name})
            st.success(f"Batch approved. Stats: {result.get('stats', {})}")
            st.rerun()
        if b2.button(f"❌ Reject All Pending ({len(pending_ids)})", use_container_width=True):
            result = api_post(f"/validate/{session_id}/batch",
                              {"approved_ids": [], "rejected_ids": pending_ids,
                               "validator_name": validator_name})
            st.warning(f"Batch rejected. Stats: {result.get('stats', {})}")
            st.rerun()

    st.divider()

    # Findings by severity
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        if sev not in filter_sev:
            continue

        sev_findings = [f for f in findings if f.get("severity") == sev]
        if filter_status != "all":
            sev_findings = [f for f in sev_findings if f.get("validation_status") == filter_status]
        if not sev_findings:
            continue

        col_color = SEV_COLORS.get(sev, "#6b7280")
        st.markdown(
            f'<div style="display:flex;align-items:center;gap:8px;margin:1rem 0 .5rem">'
            f'<span style="width:12px;height:12px;background:{col_color};border-radius:50%;display:inline-block"></span>'
            f'<strong style="color:{col_color}">{sev}</strong>'
            f'<span style="color:#64748b;font-size:13px">{len(sev_findings)} finding{"s" if len(sev_findings)>1 else ""}</span>'
            f'</div>',
            unsafe_allow_html=True,
        )

        for f in sev_findings:
            fid      = f.get("id", "")
            vstatus  = f.get("validation_status", "pending")
            status_badge = {"approve": "🟢 Approved", "reject": "🔴 Rejected (FP)",
                            "escalate": "🟣 Escalated", "pending": "⏳ Pending"}.get(vstatus, vstatus)

            with st.expander(
                f"[{fid}] {f.get('name', 'Unknown')} | CVSS {f.get('cvss_score', '-')} | {status_badge}"
            ):
                left, right = st.columns([3, 1])

                with left:
                    st.markdown(f"**Description:** {f.get('description', '-')}")
                    st.markdown(f"**Recommendation:** {f.get('solution', '-')}")
                    if f.get("cve"):
                        st.markdown(f"**CVE:** `{f['cve']}`")
                    st.info(f"**Analyst Note:** {f.get('analyst_note', '-')}")
                    if f.get("compliance"):
                        st.caption("Compliance: " + " | ".join(f["compliance"]))

                with right:
                    st.markdown(f"**Module:** {f.get('module', '-')}")
                    st.markdown(f"**CVSS Score:** {f.get('cvss_score', '-')}")
                    st.markdown(f"**Vector:** `{f.get('cvss_vector', '-')}`")
                    st.markdown(f"**Exploitability:** {f.get('exploitability', '-')}")
                    if f.get("port"):
                        st.markdown(f"**Port:** {f.get('port')}/{f.get('service', '?')}")
                    if f.get("validated_by"):
                        st.caption(f"Validated by: {f['validated_by']}")
                        if f.get("validator_notes"):
                            st.caption(f"Notes: {f['validator_notes']}")

                notes_key = f"notes_{fid}"
                notes_val = st.text_input("Validation Notes", key=notes_key, placeholder="Optional notes...")

                b1, b2, b3 = st.columns(3)
                if b1.button("✅ Approve", key=f"a_{fid}", use_container_width=True):
                    r = api_post(f"/validate/{session_id}",
                                 {"finding_id": fid, "action": "approve",
                                  "validator_name": validator_name,
                                  "notes": st.session_state.get(notes_key, "")})
                    if "error" not in r:
                        st.success("Approved!")
                        time.sleep(0.5)
                        st.rerun()

                if b2.button("🔴 Reject (FP)", key=f"r_{fid}", use_container_width=True):
                    r = api_post(f"/validate/{session_id}",
                                 {"finding_id": fid, "action": "reject",
                                  "validator_name": validator_name,
                                  "notes": st.session_state.get(notes_key, "")})
                    if "error" not in r:
                        st.warning("Marked as False Positive.")
                        time.sleep(0.5)
                        st.rerun()

                if b3.button("🟣 Escalate", key=f"e_{fid}", use_container_width=True):
                    r = api_post(f"/validate/{session_id}",
                                 {"finding_id": fid, "action": "escalate",
                                  "validator_name": validator_name,
                                  "notes": st.session_state.get(notes_key, "")})
                    if "error" not in r:
                        st.info("Escalated for further review.")
                        time.sleep(0.5)
                        st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# Page: Generate Report
# ══════════════════════════════════════════════════════════════════════════════
elif page == "📄 Generate Report":
    st.title("📄 Generate Report")

    session_id = st.text_input(
        "Session ID",
        value=st.session_state.get("active_session", ""),
        placeholder="e.g. AB12CD34",
    )

    col1, col2 = st.columns([2, 1])
    with col1:
        fmt = st.selectbox("Report Format", ["json", "html", "both"],
                           help="JSON: machine-readable. HTML: executive-ready dark-theme report.")
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        generate_btn = st.button("🗒️ Generate Report", type="primary", use_container_width=True)

    if generate_btn:
        if not session_id:
            st.warning("Enter a Session ID first.")
        else:
            with st.spinner("Generating report..."):
                result = api_get(f"/report/{session_id}", {"format": fmt})
            if result:
                st.success("Report generated!")
                for fp in result.get("files", []):
                    st.code(fp, language="text")
                    try:
                        with open(fp, encoding="utf-8") as fobj:
                            content = fobj.read()
                        if fp.endswith(".json"):
                            st.subheader("JSON Preview")
                            st.json(json.loads(content))
                        elif fp.endswith(".html"):
                            st.subheader("HTML Report Preview")
                            st.components.v1.html(content, height=700, scrolling=True)
                    except Exception as e:
                        st.warning(f"Preview error: {e}")
            else:
                st.error("Report generation failed. Is the scan complete?")


# ══════════════════════════════════════════════════════════════════════════════
# Page: API Docs
# ══════════════════════════════════════════════════════════════════════════════
elif page == "📖 API Docs":
    st.title("📖 API Reference")
    st.caption("All endpoints exposed by the FastAPI backend.")

    endpoints = [
        ("GET",    "/",                         "Health check + session count"),
        ("GET",    "/health",                   "Liveness check"),
        ("POST",   "/scan",                     "Start a new scan (async)"),
        ("GET",    "/sessions",                 "List all sessions"),
        ("GET",    "/session/{id}",             "Full session data + findings"),
        ("GET",    "/session/{id}/status",      "Live status + summary"),
        ("GET",    "/session/{id}/findings",    "Findings (filterable by severity/validated)"),
        ("DELETE", "/session/{id}",             "Delete a session"),
        ("POST",   "/validate/{id}",            "Validate a single finding"),
        ("POST",   "/validate/{id}/batch",      "Batch approve/reject findings"),
        ("GET",    "/report/{id}?format=json",  "Generate JSON report"),
        ("GET",    "/report/{id}?format=html",  "Generate HTML report"),
        ("GET",    "/report/{id}?format=both",  "Generate both formats"),
        ("GET",    "/docs",                     "Interactive Swagger UI"),
        ("GET",    "/redoc",                    "ReDoc API documentation"),
    ]

    method_colors = {"GET": "#16a34a", "POST": "#2563eb", "DELETE": "#dc2626"}

    for method, path, desc in endpoints:
        color = method_colors.get(method, "#6b7280")
        st.markdown(
            f'<div style="display:flex;align-items:center;gap:12px;padding:8px 0;'
            f'border-bottom:1px solid #1e293b">'
            f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;'
            f'font-size:11px;font-family:monospace;min-width:50px;text-align:center">{method}</span>'
            f'<code style="color:#94a3b8;font-size:13px">{path}</code>'
            f'<span style="color:#64748b;font-size:13px;flex:1">{desc}</span>'
            f'</div>',
            unsafe_allow_html=True,
        )

    st.divider()
    st.subheader("Swagger UI")
    st.markdown(f"[Open Interactive Docs →]({API_BASE}/docs)", unsafe_allow_html=False)
    st.caption("Full request/response schemas, try-it-out, and example payloads.")
