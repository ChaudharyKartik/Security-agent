"""
Streamlit UI — Security Analytics Hub v3.0
Modern, minimalist design with unique Forest Green + Gold aesthetic
NOT typical AI agent blue/purple theme
"""
import streamlit as st
import requests
import time
import json
import os

API_BASE = "http://localhost:8000"

st.set_page_config(
    page_title="Security Analytics Hub",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ────────────────────────────────────────────────────────────────────────────
# MODERN THEME: Forest Green + Gold + Clean Dark
# ────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    /* Color Palette */
    :root {
        --primary-green: #0d5d3b;
        --accent-gold: #d4a574;
        --dark-bg: #0f1419;
        --card-bg: #1a1f2e;
        --text-light: #e8e8e8;
        --text-muted: #a0a8b8;
        --border-color: #2a3342;
    }
    
    .stApp {
        background: linear-gradient(135deg, #0f1419 0%, #141a26 100%);
        color: #e8e8e8;
    }
    
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0a0d15 0%, #0f1419 100%);
        border-right: 1px solid #2a3342;
    }
    
    .stButton > button {
        width: 100%;
        padding: 11px 20px;
        border: none;
        border-radius: 8px;
        font-weight: 700;
        letter-spacing: 0.5px;
        transition: all 0.3s ease;
        background: linear-gradient(135deg, #0d5d3b 0%, #0e7a52 100%);
        color: #e8e8e8;
        box-shadow: 0 4px 12px rgba(13, 93, 59, 0.2);
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(13, 93, 59, 0.35);
        background: linear-gradient(135deg, #0e7a52 0%, #10934f 100%);
    }
    
    .stButton > button:active {
        transform: translateY(0px);
    }
    
    /* Inputs */
    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea,
    .stSelectbox > div > div > select {
        background-color: #1a1f2e !important;
        border: 1.5px solid #2a3342 !important;
        color: #e8e8e8 !important;
        border-radius: 8px !important;
        padding: 10px 14px !important;
    }
    
    .stTextInput > div > div > input:focus,
    .stTextArea > div > div > textarea:focus {
        border-color: #d4a574 !important;
        box-shadow: 0 0 0 3px rgba(212, 165, 116, 0.12) !important;
    }
    
    .stExpander {
        background: #1a1f2e !important;
        border: 1px solid #2a3342 !important;
        border-radius: 10px !important;
    }
    
    .stProgress > div > div > div > div {
        background: linear-gradient(90deg, #0d5d3b 0%, #d4a574 100%) !important;
        border-radius: 10px;
    }
    
    /* Alerts */
    .stSuccess {
        background-color: rgba(13, 93, 59, 0.15) !important;
        color: #7dd3c0 !important;
        border: 1px solid #0d5d3b !important;
        border-radius: 8px !important;
    }
    
    .stError {
        background-color: rgba(220, 38, 38, 0.15) !important;
        color: #fca5a5 !important;
        border: 1px solid #dc2626 !important;
    }
    
    .stInfo {
        background-color: rgba(13, 93, 59, 0.1) !important;
        color: #a8d5c4 !important;
        border: 1px solid #0d5d3b !important;
    }
    
    code {
        background: #0a0d15 !important;
        color: #d4a574 !important;
        padding: 2px 6px !important;
        border-radius: 4px !important;
        font-family: 'Courier New', monospace !important;
    }
    
    h1, h2, h3 {
        color: #e8e8e8 !important;
        font-weight: 700 !important;
        letter-spacing: 0.5px !important;
    }
    
    .badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-right: 6px;
    }
    
    .badge-critical { background: rgba(220, 38, 38, 0.25); color: #fca5a5; }
    .badge-high { background: rgba(234, 88, 12, 0.25); color: #fdba74; }
    .badge-medium { background: rgba(212, 165, 116, 0.25); color: #e8d4a2; }
    .badge-low { background: rgba(13, 93, 59, 0.25); color: #86efac; }
    .badge-info { background: rgba(8, 145, 178, 0.25); color: #a5f3fc; }
    
    .metric-card {
        background: linear-gradient(135deg, #1a1f2e 0%, #1f2438 100%);
        border: 1px solid #2a3342;
        border-radius: 12px;
        padding: 20px;
        text-align: center;
        transition: all 0.3s ease;
    }
    
    .metric-card:hover {
        border-color: #d4a574;
        box-shadow: 0 4px 16px rgba(212, 165, 116, 0.1);
    }
    
    ::-webkit-scrollbar {
        width: 8px;
    }
    
    ::-webkit-scrollbar-track {
        background: #0f1419;
    }
    
    ::-webkit-scrollbar-thumb {
        background: #2a3342;
        border-radius: 4px;
    }
</style>
""", unsafe_allow_html=True)

# ────────────────────────────────────────────────────────────────────────────
# HELPERS
# ────────────────────────────────────────────────────────────────────────────

def api_get(endpoint, params=None):
    try:
        r = requests.get(f"{API_BASE}{endpoint}", params=params, timeout=12)
        return r.json() if r.ok else None
    except:
        return None

def api_post(endpoint, payload):
    try:
        r = requests.post(f"{API_BASE}{endpoint}", json=payload, timeout=30)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def api_download(endpoint, params=None):
    """Return (bytes, content_type, error_msg) for binary downloads."""
    try:
        r = requests.get(f"{API_BASE}{endpoint}", params=params, timeout=60)
        if r.ok:
            return r.content, r.headers.get("content-type", "application/octet-stream"), None
        try:
            detail = r.json().get("detail", r.text[:200])
        except Exception:
            detail = r.text[:200]
        return None, None, f"HTTP {r.status_code}: {detail}"
    except Exception as e:
        return None, None, str(e)

def api_delete(endpoint) -> tuple:
    """Return (ok: bool, error_msg: str | None)."""
    try:
        r = requests.delete(f"{API_BASE}{endpoint}", timeout=10)
        if r.ok:
            return True, None
        try:
            detail = r.json().get("detail", r.text[:200])
        except Exception:
            detail = r.text[:200]
        return False, f"HTTP {r.status_code}: {detail}"
    except Exception as e:
        return False, str(e)

def check_api():
    r = api_get("/health")
    return r is not None and r.get("status") == "healthy"

def severity_badge_html(severity):
    badges = {
        "Critical": '<span class="badge badge-critical">CRITICAL</span>',
        "High": '<span class="badge badge-high">HIGH</span>',
        "Medium": '<span class="badge badge-medium">MEDIUM</span>',
        "Low": '<span class="badge badge-low">LOW</span>',
        "Info": '<span class="badge badge-info">INFO</span>'
    }
    return badges.get(severity, severity)

# ────────────────────────────────────────────────────────────────────────────
# SIDEBAR NAVIGATION
# ────────────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("""
    <div style="text-align: center; padding: 24px 0; margin-bottom: 24px; border-bottom: 1px solid #2a3342;">
        <h3 style="margin: 0 0 12px 0; font-size: 18px; font-weight: 800; color: #e8e8e8;">Security Hub</h3>
        <p style="margin: 0; font-size: 11px; color: #a0a8b8; text-transform: uppercase; letter-spacing: 1px; font-weight: 600;">Vulnerability Assessment Platform</p>
    </div>
    """, unsafe_allow_html=True)
    
    alive = check_api()
    if alive:
        st.success("Connected")
    else:
        st.error("Offline")
    
    st.divider()
    
    page = st.radio("Menu", ["Scan", "Dashboard", "Review", "Export", "Guide"], label_visibility="collapsed")
    
    st.divider()
    
    with st.expander("Settings"):
        st.selectbox("Color Theme", ["Forest Green", "Slate", "Copper"])
        st.toggle("Advanced Mode")

# ────────────────────────────────────────────────────────────────────────────
# PAGE: SCAN
# ────────────────────────────────────────────────────────────────────────────

if page == "Scan":
    st.markdown("# New Assessment")
    
    c1, c2 = st.columns([2, 1])
    with c1:
        st.markdown("### Target")
        target = st.text_input("URL or IP", placeholder="https://example.com", label_visibility="collapsed")
    with c2:
        st.markdown("### Scan Type")
        scan_type = st.selectbox("Scan Type", ["Full", "Quick", "Deep"], label_visibility="collapsed")
    
    description = st.text_area("Description", placeholder="Assessment notes...", height=60)
    
    st.divider()
    
    with st.expander("Authentication", expanded=False):
        auth_type = st.selectbox("Method", ["None", "Basic", "Form", "Token", "Cookie", "API Key"])
        
        cred = {"auth_type": auth_type.lower()}
        
        if auth_type == "Basic":
            c1, c2 = st.columns(2)
            cred["username"] = c1.text_input("Username")
            cred["password"] = c2.text_input("Password", type="password")
        elif auth_type == "Form":
            cred["login_url"] = st.text_input("Login URL")
            c1, c2 = st.columns(2)
            cred["username"] = c1.text_input("Username")
            cred["password"] = c2.text_input("Password", type="password")
        elif auth_type == "Token":
            cred["auth_token"] = st.text_input("Token", type="password")
        elif auth_type == "API Key":
            c1, c2 = st.columns(2)
            cred["api_key_name"] = c1.text_input("Key Name")
            cred["api_key_value"] = c2.text_input("Value", type="password")
    
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        pass
    
    with col2:
        include_cloud = st.checkbox("Include Cloud")
    
    with col3:
        launch = st.button("LAUNCH", type="primary", use_container_width=True)
    
    if launch:
        if not target:
            st.error("Enter target")
        elif not alive:
            st.error("API offline")
        else:
            payload = {"target": target, "run_cloud": include_cloud, "description": description, **cred}
            result = api_post("/scan", payload)
            
            if "error" in result:
                st.error(result["error"])
            else:
                st.session_state["sid"] = result["session_id"]
                st.success(f"Started: {result['session_id'][:8]}...")
                
                st.divider()
                st.markdown("### Live Progress")
                
                prog = st.progress(0)
                stat = st.empty()
                
                for _ in range(200):
                    time.sleep(2)
                    data = api_get(f"/session/{result['session_id']}/status")
                    if not data: break
                    
                    pct = {"recon": 20, "knowledge_resolution": 30, "scanning": 55, "enrichment": 75, "ai_analysis": 88, "awaiting_validation": 95, "completed": 100}.get(data.get("status"), 50)
                    prog.progress(pct / 100)
                    stat.markdown(f"**{data.get('status').upper()}** | {data.get('total_findings', 0)} findings")
                    
                    if data.get("status") in ("completed", "error"):
                        break
                
                final = api_get(f"/session/{result['session_id']}/status")
                if final and final.get("status") == "completed":
                    st.balloons()
                    st.success(f"Complete! {final.get('total_findings')} vulnerabilities found")
                    
                    bd = final.get("summary", {}).get("severity_breakdown", {})
                    c1, c2, c3, c4, c5 = st.columns(5)
                    
                    for col, sev in [(c1, "Critical"), (c2, "High"), (c3, "Medium"), (c4, "Low"), (c5, "Info")]:
                        with col:
                            st.markdown(f"""
                            <div style="background: linear-gradient(135deg, #1a1f2e 0%, #1f2438 100%); border: 1px solid #2a3342; border-radius: 10px; padding: 16px; text-align: center;">
                                <div style="font-size: 24px; font-weight: 700; color: #d4a574;">{bd.get(sev, 0)}</div>
                                <div style="font-size: 11px; color: #a0a8b8; margin-top: 8px; text-transform: uppercase; letter-spacing: 0.5px;">{sev}</div>
                            </div>
                            """, unsafe_allow_html=True)

# ────────────────────────────────────────────────────────────────────────────
# PAGE: DASHBOARD
# ────────────────────────────────────────────────────────────────────────────

elif page == "Dashboard":
    st.markdown("# Assessment Dashboard")

    # ── Toolbar ─────────────────────────────────────────────────────────────
    tb1, tb2, tb3 = st.columns([1, 1, 6])
    with tb1:
        if st.button("Refresh", use_container_width=True):
            # Clear any per-session confirm state and reload
            for k in list(st.session_state.keys()):
                if k.startswith("confirm_del_"):
                    del st.session_state[k]
            st.rerun()
    with tb2:
        if st.button("Clear All", use_container_width=True, type="secondary"):
            st.session_state["confirm_clear_all"] = True

    if st.session_state.get("confirm_clear_all"):
        st.warning("Delete ALL scan sessions permanently? This cannot be undone.")
        yes, no = st.columns(2)
        if yes.button("Yes, delete all", type="primary", key="yes_clear_all"):
            all_data = api_get("/sessions", params={"limit": 500}) or {}
            errors = []
            for s in all_data.get("sessions", []):
                ok, err = api_delete(f"/session/{s['session_id']}")
                if not ok:
                    errors.append(err)
            st.session_state.pop("confirm_clear_all", None)
            if errors:
                st.error(f"Some deletions failed: {errors}")
            else:
                st.success("All sessions deleted.")
            st.rerun()
        if no.button("Cancel", key="no_clear_all"):
            st.session_state.pop("confirm_clear_all", None)
            st.rerun()

    st.divider()

    data = api_get("/sessions")

    if not data or data.get("total", 0) == 0:
        st.info("No scans yet. Run your first assessment from the Scan tab.")
    else:
        sessions_list = data.get("sessions", [])

        # ── Summary metrics ──────────────────────────────────────────────────
        seen_targets   = {s.get("target", "?"): True for s in sessions_list}
        total_findings = sum(s.get("total_findings", 0) for s in sessions_list)
        critical_scans = sum(1 for s in sessions_list if s.get("risk_rating") == "CRITICAL")

        hc1, hc2, hc3, hc4 = st.columns(4)
        hc1.metric("Total Scans",     data.get("total", 0))
        hc2.metric("Total Findings",  total_findings)
        hc3.metric("Critical Scans",  critical_scans)
        hc4.metric("Targets Scanned", len(seen_targets))

        st.divider()
        st.markdown("### Sessions (newest first)")

        for s in sessions_list:
            risk    = s.get("risk_rating", "-")
            count   = s.get("total_findings", 0)
            status  = s.get("status", "?")
            sid     = s.get("session_id", "?")
            target  = s.get("target", "?")
            ts      = (s.get("start_time") or "")[:16].replace("T", " ")

            risk_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
                         "LOW": "🟢", "CLEAN": "✅"}.get(risk, "⚪")

            with st.expander(f"{risk_icon}  {target}  |  {count} findings  |  {risk}  |  {ts}"):
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Status",   status.replace("_", " ").title())
                c2.metric("Risk",     risk)
                c3.metric("Findings", count)
                c4.metric("Duration", f"{int(s['duration_seconds'])}s"
                          if s.get("duration_seconds") else "-")

                st.caption(f"Session ID: `{sid}`")

                # ── Delete button with inline confirmation ───────────────────
                confirm_key = f"confirm_del_{sid}"
                if not st.session_state.get(confirm_key):
                    if st.button("Delete this scan", key=f"del_{sid}",
                                 type="secondary"):
                        st.session_state[confirm_key] = True
                        st.rerun()
                else:
                    st.warning("Permanently delete this scan and all its findings?")
                    d1, d2 = st.columns(2)
                    if d1.button("Confirm delete", key=f"yes_{sid}", type="primary"):
                        ok, err = api_delete(f"/session/{sid}")
                        st.session_state.pop(confirm_key, None)
                        if ok:
                            st.success("Deleted.")
                        else:
                            st.error(f"Delete failed: {err}")
                        st.rerun()
                    if d2.button("Cancel", key=f"no_{sid}"):
                        st.session_state.pop(confirm_key, None)
                        st.rerun()

# ────────────────────────────────────────────────────────────────────────────
# PAGE: REVIEW
# ────────────────────────────────────────────────────────────────────────────

elif page == "Review":
    st.markdown("# Findings Review")

    sessions_data = api_get("/sessions")
    sessions_list = sessions_data.get("sessions", []) if sessions_data else []

    if not sessions_list:
        st.info("No scans available. Start a new assessment in the Scan tab.")
    else:
        # Newest first; show session_id + target so user knows exactly which scan
        session_options = {
            f"[{s.get('session_id')}]  {s.get('target','?')}  ({s.get('total_findings',0)} findings  ·  {s.get('risk_rating','-')})": s.get("session_id")
            for s in sessions_list
        }

        selected_display = st.selectbox("Select Scan Session", list(session_options.keys()))
        sid = session_options[selected_display]
        
        data = api_get(f"/session/{sid}")
        if not data:
            st.error("Session not found")
        else:
            findings = data.get("enriched_findings", [])
            summary = data.get("summary", {})
            bd = summary.get("severity_breakdown", {})
            
            st.markdown("### Severity Breakdown")
            c1, c2, c3, c4, c5 = st.columns(5)
            for col, sev in [(c1, "Critical"), (c2, "High"), (c3, "Medium"), (c4, "Low"), (c5, "Info")]:
                with col:
                    st.metric(sev, bd.get(sev, 0))
            
            st.divider()
            
            st.markdown("### Finding Details")
            
            if not findings:
                st.info("No findings")
            else:
                # Filter and sort
                col1, col2, col3 = st.columns(3)
                with col1:
                    filter_severity = st.multiselect(
                        "Filter Severity",
                        ["Critical", "High", "Medium", "Low", "Info"],
                        default=["Critical", "High", "Medium", "Low", "Info"],  # show ALL by default
                    )
                with col2:
                    sort_by = st.selectbox("Sort by", ["Severity", "CVSS Score", "Module"])
                with col3:
                    filter_module = st.multiselect(
                        "Filter Module",
                        ["recon", "web", "network", "cloud"],
                        default=[],
                    )
                
                st.divider()

                filtered = [f for f in findings if f.get("severity") in filter_severity]
                if filter_module:
                    filtered = [f for f in filtered if f.get("module") in filter_module]

                if sort_by == "CVSS Score":
                    filtered = sorted(filtered, key=lambda x: x.get("cvss_score") or 0, reverse=True)
                elif sort_by == "Module":
                    filtered = sorted(filtered, key=lambda x: x.get("module", ""))
                # default: Severity order
                else:
                    sev_order = {"Critical":0,"High":1,"Medium":2,"Low":3,"Info":4}
                    filtered = sorted(filtered, key=lambda x: sev_order.get(x.get("severity","Info"), 5))

                st.caption(f"Showing {len(filtered)} of {len(findings)} findings")

                for idx, f in enumerate(filtered):
                    finding_id = f.get("id", f"finding_{idx}")
                    severity = f.get("severity", "Info")
                    name = f.get("name", "Unknown")
                    cvss = f.get("cvss_score", "-")
                    
                    with st.expander(f"[{severity}] {name} (CVSS {cvss})"):
                        # Main finding info
                        col_left, col_right = st.columns([2, 1])
                        
                        with col_left:
                            st.markdown("**Description**")
                            st.write(f.get("description", "N/A"))
                            
                            st.markdown("**Recommendation**")
                            st.write(f.get("solution", "N/A"))
                            
                            # PROOF OF CONCEPT / EVIDENCE
                            evidence = f.get("evidence", {})
                            if evidence:
                                st.markdown("**Proof of Concept**")

                                # Real HTTP exchange (ZAP High/Medium findings)
                                if evidence.get("request_header") or evidence.get("request"):
                                    st.markdown("_HTTP Request_")
                                    req_block = evidence.get("request") or evidence.get("request_header", "")
                                    st.code(req_block, language="http")

                                    resp_hdr  = evidence.get("response_header", "")
                                    resp_body = evidence.get("response_snippet", "")
                                    if resp_hdr or resp_body:
                                        st.markdown("_HTTP Response_")
                                        resp_block = resp_hdr
                                        if resp_body:
                                            resp_block = resp_block.rstrip() + "\r\n\r\n" + resp_body
                                        st.code(resp_block, language="http")

                                    # Match highlight — ZAP's exact matched string in the response
                                    match_str = evidence.get("evidence", "")
                                    if match_str:
                                        st.warning(f"**Match Found in Response:** `{match_str}`")

                                    # HAR download — importable into Burp Suite / browser DevTools
                                    if evidence.get("har"):
                                        import json as _json
                                        har_bytes = _json.dumps(evidence["har"], indent=2).encode()
                                        st.download_button(
                                            label="Download HAR (Burp/DevTools import)",
                                            data=har_bytes,
                                            file_name=f"{f.get('name','finding').replace(' ','_')}.har",
                                            mime="application/json",
                                            key=f"har_{f.get('id', i)}",
                                        )

                                elif evidence.get("poc_url"):
                                    # Low/Info ZAP findings — no full exchange captured
                                    st.caption(f"URL: {evidence['poc_url']}")
                                    if evidence.get("poc_param"):
                                        st.caption(f"Parameter: {evidence['poc_param']}")
                                    if evidence.get("poc_attack"):
                                        st.caption(f"Attack: {evidence['poc_attack']}")

                                elif evidence.get("curl_poc"):
                                    # Built-in probe findings (header checks, CORS, etc.)
                                    st.code(evidence["curl_poc"], language="bash")
                                    if evidence.get("response_headers"):
                                        st.markdown("_Response Headers_")
                                        st.code(evidence["response_headers"], language="http")

                                # Reproduction steps
                                steps = f.get("reproduction_steps") or []
                                if steps:
                                    st.markdown("**Reproduction Steps**")
                                    for n, step in enumerate(steps, 1):
                                        st.markdown(f"{n}. {step}")

                                # Network-specific evidence
                                if evidence.get("nmap_cmd"):
                                    st.markdown("_Network Scan_")
                                    st.code(evidence["nmap_cmd"], language="bash")
                                    if evidence.get("banner"):
                                        st.caption(f"Banner: {evidence['banner']}")
                                    st.divider()

                                if evidence.get("affected_url"):
                                    st.info(f"Affected URL: {evidence['affected_url']}")
                            
                            # Compliance info
                            if f.get("compliance"):
                                st.markdown("**Compliance**")
                                st.write(", ".join(f["compliance"]))
                        
                        with col_right:
                            st.markdown("**Severity**")
                            st.write(severity)

                            st.markdown("**CVSS Score**")
                            st.write(cvss)

                            if f.get("cvss_vector"):
                                st.markdown("**CVSS Vector**")
                                st.code(f["cvss_vector"], language="text")

                            st.markdown("**Module**")
                            st.write(f.get("module", "-"))

                            st.markdown("**Tool**")
                            st.write(f.get("tool_used", "-"))

                            if f.get("cve"):
                                st.markdown("**CVE**")
                                st.write(f["cve"])

                            # ── AI Analysis block ────────────────────────────────
                            if f.get("llm_analysed"):
                                st.divider()
                                st.markdown("**🧠 AI Analysis**")

                                conf = f.get("confidence_score", 0)
                                conf_pct = int(conf * 100)
                                st.progress(conf, text=f"Confidence: {conf_pct}%")

                                fp_status = f.get("fp_status", "uncertain")
                                fp_colors = {
                                    "confirmed":              "🟢 Confirmed",
                                    "likely_false_positive":  "🔴 Likely False Positive",
                                    "uncertain":              "🟡 Uncertain",
                                }
                                st.caption(fp_colors.get(fp_status, fp_status))

                                if f.get("fp_reason"):
                                    st.caption(f"💬 {f['fp_reason']}")
                        
                        # Validation buttons
                        st.divider()
                        st.markdown("**Validation**")
                        
                        col_validate = st.columns(3)
                        
                        with col_validate[0]:
                            if st.button("Approve", key=f"approve_{finding_id}"):
                                api_post(f"/validate/{sid}", {
                                    "finding_id": finding_id,
                                    "action": "approve",
                                    "validator_name": "Security Analyst"
                                })
                                st.success("Approved")
                                st.rerun()
                        
                        with col_validate[1]:
                            if st.button("Reject", key=f"reject_{finding_id}"):
                                api_post(f"/validate/{sid}", {
                                    "finding_id": finding_id,
                                    "action": "reject",
                                    "validator_name": "Security Analyst"
                                })
                                st.success("Rejected")
                                st.rerun()
                        
                        with col_validate[2]:
                            if st.button("Escalate", key=f"escalate_{finding_id}"):
                                api_post(f"/validate/{sid}", {
                                    "finding_id": finding_id,
                                    "action": "escalate",
                                    "validator_name": "Security Analyst"
                                })
                                st.success("Escalated")
                                st.rerun()

# ────────────────────────────────────────────────────────────────────────────
# PAGE: EXPORT
# ────────────────────────────────────────────────────────────────────────────

elif page == "Export":
    st.markdown("# Report Export")

    # ── Session list ─────────────────────────────────────────────────────────
    sessions_data = api_get("/sessions", params={"limit": 200})
    all_sessions  = (sessions_data or {}).get("sessions", [])

    # Only sessions that have completed (or are awaiting validation)
    exportable = [
        s for s in all_sessions
        if s.get("status") in ("completed", "awaiting_validation", "error")
    ]

    if not exportable:
        st.warning("No completed scans available. Run a scan first.")
    else:
        # Build display labels for the selector
        def _session_label(s):
            ts  = (s.get("start_time") or "")[:16].replace("T", " ")
            return f"{s['target']}  |  {ts}  |  {s.get('risk_rating','-')} risk  [{s['session_id'][:8]}]"

        labels     = [_session_label(s) for s in exportable]
        chosen_idx = st.selectbox("Select Session", range(len(labels)),
                                  format_func=lambda i: labels[i])
        chosen = exportable[chosen_idx]
        sid    = chosen["session_id"]

        # ── Summary metrics ──────────────────────────────────────────────────
        st.divider()
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Target",    chosen.get("target", "-"))
        m2.metric("Status",    chosen.get("status", "-").replace("_", " ").title())
        m3.metric("Findings",  chosen.get("total_findings", 0))
        m4.metric("Risk",      chosen.get("risk_rating", "-"))
        dur = chosen.get("duration_seconds")
        m5.metric("Duration",  f"{int(dur)}s" if dur else "-")

        # ── Format download buttons ──────────────────────────────────────────
        st.divider()
        st.markdown("### Download Report")

        FORMATS = [
            ("PDF",  "pdf",  "application/pdf",       "vapt_report.pdf"),
            ("HTML", "html", "text/html",              "vapt_report.html"),
            ("CSV",  "csv",  "text/csv",               "vapt_report.csv"),
            ("JSON", "json", "application/json",       "vapt_report.json"),
        ]

        cols = st.columns(len(FORMATS))
        for col, (label, fmt, mime, _) in zip(cols, FORMATS):
            with col:
                if st.button(f"Generate {label}", key=f"gen_{fmt}_{sid}"):
                    with st.spinner(f"Generating {label} report…"):
                        data, ct, err = api_download(
                            f"/report/{sid}/download",
                            params={"format": fmt},
                        )
                    if err:
                        st.error(f"{label} failed: {err}")
                    else:
                        st.session_state[f"dl_{fmt}_{sid}"] = (data, ct)
                        st.success(f"{label} ready — click Download below")

                key = f"dl_{fmt}_{sid}"
                if key in st.session_state:
                    data, ct = st.session_state[key]
                    ext = fmt
                    st.download_button(
                        label=f"Download {label}",
                        data=data,
                        file_name=f"vapt_report_{sid[:8]}.{ext}",
                        mime=ct or mime,
                        key=f"dlbtn_{fmt}_{sid}",
                    )

# ────────────────────────────────────────────────────────────────────────────
# PAGE: GUIDE
# ────────────────────────────────────────────────────────────────────────────

elif page == "Guide":
    st.markdown("# Getting Started")
    st.markdown("""
    ## Quick Start
    
    1. **Scan** - Enter target URL
    2. **Dashboard** - View all scans
    3. **Review** - Check findings with evidence
    4. **Export** - Download report
    
    ## Features
    
    - Multi-agent scanning (Web, Network, Cloud)
    - Authentication support (Basic, Form, Token, etc.)
    - Real CVSS scoring
    - Proof of Concept evidence (curl commands, responses)
    - Human validation workflow
    
    ## Proof of Concept Evidence
    
    Each finding includes:
    - **Curl command** - Reproduce the vulnerability
    - **Request details** - HTTP method, headers, body
    - **Response evidence** - Server response that proves the issue
    - **Network data** - Nmap commands and banners
    
    ## Supported Targets
    
    - Web: https://example.com
    - IP: 192.168.1.100
    - Domain: example.com
    """)
