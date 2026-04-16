"""
Streamlit UI — AI Security Testing Agent v2.0
Features:
  - Dynamic credential input panel (auth_type drives which fields appear)
  - Tool-at-each-phase status display
  - PoC evidence viewer (curl commands, request/response)
  - Exploitation narrative per finding
  - Real CVSS 3.1 breakdown display
  - Download buttons for JSON / HTML / PDF / CSV
"""
import streamlit as st
import requests
import time
import json
import os

API_BASE = "http://localhost:8000"

st.set_page_config(page_title="AI Security Agent v2", page_icon="🔐", layout="wide")

st.markdown("""
<style>
.stApp { background-color: #0f172a; }
section[data-testid="stSidebar"] { background-color: #1e293b; }
code { background: #1e293b !important; color: #a5b4fc !important; }
</style>
""", unsafe_allow_html=True)

SEV_COLORS = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🔵","Info":"⚪"}
STATUS_ICONS = {"queued":"⏳","running":"🔄","recon":"🔍 Recon",
                "scanning":"⚡ Scanning [parallel]","enrichment":"🧠 Enriching",
                "awaiting_validation":"✋ Awaiting Validation","completed":"✅","error":"❌"}
PHASE_PROGRESS = {"queued":5,"recon":20,"scanning":55,"enrichment":85,
                  "awaiting_validation":100,"completed":100,"error":100}

TOOL_LABELS = {
    "recon":   "🔍 socket + httpx",
    "network": "🛠️ Nmap 7.x  (fallback: Mock Scanner)",
    "web":     "🌐 OWASP ZAP 2.14  (fallback: Built-in HTTP Probe)",
    "cloud":   "☁️ Prowler 3.x  (fallback: Mock Cloud Scanner)",
}

AUTH_TYPES = ["none","basic","form","token","cookie","apikey","custom_headers"]
AUTH_DESCRIPTIONS = {
    "none":           "Unauthenticated scan",
    "basic":          "HTTP Basic Auth (username + password)",
    "form":           "Form-based login (POST to login URL)",
    "token":          "Bearer / JWT token in Authorization header",
    "cookie":         "Session cookie (name + value)",
    "apikey":         "API key in header, query param, or body",
    "custom_headers": "Custom HTTP headers (any key:value pairs)",
}


# ── API helpers ───────────────────────────────────────────────────────────────

def api_get(endpoint, params=None):
    try:
        r = requests.get(f"{API_BASE}{endpoint}", params=params, timeout=12)
        return r.json() if r.ok else None
    except Exception:
        return None

def api_post(endpoint, payload):
    try:
        r = requests.post(f"{API_BASE}{endpoint}", json=payload, timeout=30)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def api_delete(endpoint):
    try:
        r = requests.delete(f"{API_BASE}{endpoint}", timeout=10)
        return r.json() if r.ok else None
    except Exception:
        return None

def download_report(session_id: str, fmt: str):
    try:
        r = requests.get(f"{API_BASE}/report/{session_id}/download",
                         params={"format": fmt}, timeout=60)
        if r.ok:
            return r.content, r.headers.get("content-type","application/octet-stream")
    except Exception:
        pass
    return None, None

def check_api():
    r = api_get("/health")
    return r is not None and r.get("status") == "healthy"


# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("## 🔐 Security Agent v2")
    st.caption("Multi-Agent · Auth-Aware · Real CVSS · PoC Evidence")
    st.divider()
    alive = check_api()
    if alive:
        st.success("API Online ✅")
    else:
        st.error("API Offline 🔴")
        st.caption("`uvicorn main:app --reload`")
    st.divider()
    page = st.radio("Navigation", [
        "🎯 New Scan",
        "📊 Sessions",
        "✅ Validate Findings",
        "📄 Reports & Download",
        "📖 API Reference",
    ], label_visibility="collapsed")


# ══════════════════════════════════════════════════════════════════════════════
# Page: New Scan
# ══════════════════════════════════════════════════════════════════════════════
if page == "🎯 New Scan":
    st.title("🎯 New Security Scan")
    st.caption("Parallel agents: Network (Nmap) · Web (ZAP) · Cloud (Prowler)")

    # ── Target + description ──────────────────────────────────────────────────
    col1, col2 = st.columns([3, 1])
    with col1:
        target = st.text_input("Target URL / IP Address",
                               placeholder="https://example.com  or  192.168.1.1")
    with col2:
        run_cloud = st.checkbox("Include Cloud Scan",
                                help="Prowler (AWS/GCP/Azure) or mock if not installed")
    description = st.text_input("Description", placeholder="Q3 Web App Assessment — optional")

    st.divider()

    # ── Tool status panel ─────────────────────────────────────────────────────
    with st.expander("🛠️ Tools Used at Each Phase", expanded=False):
        for module, label in TOOL_LABELS.items():
            st.markdown(f"**{module.capitalize()}:** {label}")
        st.caption("Real tools are auto-detected. If not installed, mock/built-in fallback activates automatically.")

    st.divider()

    # ── Credential Config Panel ───────────────────────────────────────────────
    st.subheader("🔑 Scan Credentials (Optional)")
    st.caption("Configure authentication to scan behind login. Credentials are used only for this scan session.")

    auth_type = st.selectbox(
        "Authentication Type",
        AUTH_TYPES,
        format_func=lambda x: f"{x}  —  {AUTH_DESCRIPTIONS[x]}"
    )
    st.caption(AUTH_DESCRIPTIONS[auth_type])

    # Dynamic fields based on auth_type
    cred_payload = {"auth_type": auth_type}

    if auth_type == "basic":
        c1, c2 = st.columns(2)
        cred_payload["username"] = c1.text_input("Username")
        cred_payload["password"] = c2.text_input("Password", type="password")

    elif auth_type == "form":
        cred_payload["login_url"] = st.text_input("Login URL", placeholder="https://example.com/login")
        c1, c2, c3, c4 = st.columns(4)
        cred_payload["username"]       = c1.text_input("Username")
        cred_payload["password"]       = c2.text_input("Password", type="password")
        cred_payload["username_field"] = c3.text_input("Username field", value="username")
        cred_payload["password_field"] = c4.text_input("Password field", value="password")

    elif auth_type == "token":
        cred_payload["auth_token"]   = st.text_input("Token value", type="password",
                                                       placeholder="eyJhbGciOiJIUzI1NiJ9...")
        c1, c2 = st.columns(2)
        cred_payload["token_header"] = c1.text_input("Header name", value="Authorization")
        cred_payload["token_prefix"] = c2.text_input("Prefix", value="Bearer")

    elif auth_type == "cookie":
        c1, c2 = st.columns(2)
        cred_payload["session_cookie_name"]  = c1.text_input("Cookie name", placeholder="session")
        cred_payload["session_cookie_value"] = c2.text_input("Cookie value", type="password")

    elif auth_type == "apikey":
        c1, c2, c3 = st.columns(3)
        cred_payload["api_key_name"]  = c1.text_input("Key name",  placeholder="X-API-Key")
        cred_payload["api_key_value"] = c2.text_input("Key value", type="password")
        cred_payload["api_key_in"]    = c3.selectbox("Send in", ["header","query","body"])

    elif auth_type == "custom_headers":
        raw = st.text_area("Custom headers (JSON)",
                           placeholder='{"X-Tenant": "acme", "X-Role": "admin"}',
                           height=80)
        if raw.strip():
            try:
                cred_payload["custom_headers"] = json.loads(raw)
            except json.JSONDecodeError:
                st.error("Invalid JSON for custom headers")

    # Advanced scan options
    with st.expander("⚙️ Advanced Scan Options", expanded=False):
        c1, c2 = st.columns(2)
        nmap_ports = c1.text_input("Nmap ports override",
                                   placeholder="21,22,80,443,3306 (default: auto)")
        nmap_args  = c2.text_input("Extra Nmap args",
                                   placeholder="--script=vuln (default: -sV -sC)")
        c3, c4 = st.columns(2)
        zap_base   = c3.text_input("ZAP API base", value="http://localhost:8090")
        zap_key    = c4.text_input("ZAP API key",  value="changeme")
        scan_depth = st.select_slider("Scan depth", ["quick","standard","deep"], value="standard")

        if nmap_ports: cred_payload["nmap_ports"]     = nmap_ports
        if nmap_args:  cred_payload["nmap_extra_args"] = nmap_args
        cred_payload["zap_api_base"] = zap_base
        cred_payload["zap_api_key"]  = zap_key
        cred_payload["scan_depth"]   = scan_depth

        if st.checkbox("Cloud: specify AWS profile"):
            c5, c6 = st.columns(2)
            cred_payload["aws_profile"] = c5.text_input("AWS profile", value="default")
            cred_payload["aws_region"]  = c6.text_input("AWS region",  value="us-east-1")

    st.divider()

    if st.button("🚀 Launch Scan", type="primary", use_container_width=True):
        if not target:
            st.warning("Enter a target first.")
        elif not alive:
            st.error("API offline. Start: `uvicorn main:app --reload`")
        else:
            payload = {"target": target, "run_cloud": run_cloud,
                       "description": description, **cred_payload}
            result  = api_post("/scan", payload)

            if "error" in result:
                st.error(f"Failed: {result['error']}")
            else:
                sid = result["session_id"]
                st.success(f"Scan launched! Session: `{sid}` | Auth: {result.get('auth','?')}")
                st.session_state["active_session"] = sid

                st.divider()
                st.subheader("Live Scan Progress")

                # Tool phase display
                phase_info = st.empty()
                progress   = st.progress(0)
                status_txt = st.empty()

                for _ in range(200):
                    time.sleep(2)
                    data = api_get(f"/session/{sid}/status")
                    if not data: break
                    curr    = data.get("status","running")
                    prog    = PHASE_PROGRESS.get(curr, 50)
                    n_finds = data.get("total_findings", 0)
                    icon    = STATUS_ICONS.get(curr, "⚙️")

                    progress.progress(prog)
                    status_txt.markdown(f"**{icon}** | Findings so far: **{n_finds}**")

                    # Show which tools are running
                    if "scan" in curr or curr == "recon":
                        phase_info.info(
                            "**Active agents:**\n"
                            "- 🔍 Recon: socket + httpx\n"
                            "- 🛠️ Network: Nmap\n"
                            "- 🌐 Web: OWASP ZAP / Built-in Probe\n"
                            + ("- ☁️ Cloud: Prowler / Mock\n" if run_cloud else "")
                        )

                    if curr in ("awaiting_validation","completed","error"):
                        break

                final = api_get(f"/session/{sid}/status")
                if final and final.get("status") != "error":
                    phase_info.empty()
                    st.balloons()
                    st.success(f"Scan complete! **{final.get('total_findings',0)}** vulnerabilities found.")
                    bd = final.get("summary",{}).get("severity_breakdown",{})
                    c1,c2,c3,c4,c5 = st.columns(5)
                    for col_obj, s in [(c1,"Critical"),(c2,"High"),(c3,"Medium"),(c4,"Low"),(c5,"Info")]:
                        col_obj.metric(s, bd.get(s,0))
                    st.info(f"Risk: **{final.get('summary',{}).get('risk_rating','?')}** → Go to **Validate Findings** or **Reports**")
                elif final:
                    st.error(f"Scan error: {final.get('error','Unknown')}")


# ══════════════════════════════════════════════════════════════════════════════
# Page: Sessions
# ══════════════════════════════════════════════════════════════════════════════
elif page == "📊 Sessions":
    st.title("📊 Scan Sessions")
    if st.button("🔄 Refresh"): st.rerun()

    data = api_get("/sessions")
    if not data:
        st.error("Cannot connect to API.")
    elif data.get("count",0) == 0:
        st.info("No sessions yet.")
    else:
        for s in reversed(data.get("sessions",[])):
            sid     = s["session_id"]
            n_finds = s.get("total_findings",0)
            risk    = s.get("risk_rating","-")
            icon    = STATUS_ICONS.get(s.get("status",""),"❓")
            with st.expander(f"{icon} `[{sid}]` {s.get('target','?')} — {n_finds} findings | {risk} | {s.get('auth_used','')}"):
                c1,c2,c3,c4 = st.columns(4)
                c1.write(f"**Status:** {s.get('status')}")
                c2.write(f"**Risk:** {risk}")
                c3.write(f"**Findings:** {n_finds}")
                c4.write(f"**Auth:** {s.get('auth_used','-')}")
                b1,b2,b3 = st.columns(3)
                if b1.button("Load", key=f"l_{sid}"):
                    st.session_state["active_session"] = sid
                    st.success("Loaded.")
                if b2.button("Delete", key=f"d_{sid}"):
                    api_delete(f"/session/{sid}")
                    st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# Page: Validate Findings
# ══════════════════════════════════════════════════════════════════════════════
elif page == "✅ Validate Findings":
    st.title("✅ Human Validation")

    session_id = st.text_input("Session ID", value=st.session_state.get("active_session",""))
    if not session_id:
        st.info("Enter a Session ID or load one from Sessions page.")
        st.stop()

    data = api_get(f"/session/{session_id}")
    if not data:
        st.error("Session not found.")
        st.stop()

    findings = data.get("enriched_findings",[])
    summary  = data.get("summary",{})
    bd       = summary.get("severity_breakdown",{})

    st.caption(f"Target: **{data.get('target')}** | Status: **{data.get('status')}** | "
               f"Auth: **{data.get('auth_used','?')}** | Risk: **{summary.get('risk_rating','-')}**")

    # Tool breakdown
    tool_bd = summary.get("tool_breakdown",{})
    if tool_bd:
        st.caption("Tools: " + " · ".join(f"{t}: {c} findings" for t,c in tool_bd.items()))

    c1,c2,c3,c4,c5 = st.columns(5)
    for col_obj, sev in [(c1,"Critical"),(c2,"High"),(c3,"Medium"),(c4,"Low"),(c5,"Info")]:
        col_obj.metric(sev, bd.get(sev,0))
    st.divider()

    validator_name = st.text_input("Your Name / Role", value="Sr. Security Consultant")
    filter_sev     = st.multiselect("Filter Severity",
                                    ["Critical","High","Medium","Low","Info"],
                                    default=["Critical","High","Medium","Low","Info"])
    filter_status  = st.selectbox("Filter Status",
                                   ["all","pending","approve","reject","escalate"])

    # Batch
    with st.expander("Batch Validate All Pending"):
        pending_ids = [f["id"] for f in findings if f.get("validation_status") == "pending"]
        b1, b2 = st.columns(2)
        if b1.button(f"✅ Approve All ({len(pending_ids)})", use_container_width=True):
            api_post(f"/validate/{session_id}/batch",
                     {"approved_ids":pending_ids,"rejected_ids":[],"validator_name":validator_name})
            st.rerun()
        if b2.button(f"❌ Reject All ({len(pending_ids)})", use_container_width=True):
            api_post(f"/validate/{session_id}/batch",
                     {"approved_ids":[],"rejected_ids":pending_ids,"validator_name":validator_name})
            st.rerun()

    st.divider()

    for sev in ["Critical","High","Medium","Low","Info"]:
        if sev not in filter_sev: continue
        sev_findings = [f for f in findings if f.get("severity") == sev]
        if filter_status != "all":
            sev_findings = [f for f in sev_findings if f.get("validation_status") == filter_status]
        if not sev_findings: continue

        st.markdown(f"{SEV_COLORS.get(sev,'•')} **{sev}** — {len(sev_findings)} finding(s)")

        for f in sev_findings:
            fid      = f.get("id","")
            vstatus  = f.get("validation_status","pending")
            st_badge = {"approve":"🟢 Approved","reject":"🔴 False Positive",
                        "escalate":"🟣 Escalated","pending":"⏳ Pending"}.get(vstatus,"")

            with st.expander(f"[{fid}] {f.get('name','?')} | CVSS {f.get('cvss_score','-')} | {st_badge} | 🛠️ {f.get('tool_used','-')}"):
                left, right = st.columns([3,1])

                with left:
                    st.markdown(f"**Description:** {f.get('description','-')}")
                    st.markdown(f"**Recommendation:** {f.get('solution','-')}")
                    if f.get("cve"):
                        st.code(f"CVE: {f['cve']}")
                    st.info(f"**Analyst Note:** {f.get('analyst_note','-')}")

                    # PoC Evidence — checkbox toggle (no nested expander)
                    ev = f.get("evidence",{}) or {}
                    if ev:
                        if st.checkbox("🔍 Show PoC Evidence", key=f"poc_{fid}"):
                            poc = ev.get("curl_poc","")
                            if poc:
                                st.caption("PoC Command:")
                                st.code(poc, language="bash")
                            resp = ev.get("response_snippet") or ev.get("response_headers","")
                            if resp:
                                st.caption("Response Evidence:")
                                st.code(resp[:600], language="http")
                            if ev.get("nmap_cmd"):
                                st.caption("Nmap Command:")
                                st.code(ev["nmap_cmd"], language="bash")
                            if ev.get("banner"):
                                st.caption(f"Banner: `{ev['banner']}`")
                            if ev.get("default_creds"):
                                st.caption(f"Default Credentials: `{ev['default_creds']}`")

                    # Exploitation narrative — checkbox toggle (no nested expander)
                    narr = f.get("exploitation_narrative","")
                    if narr:
                        if st.checkbox("⚠️ Show Attacker Exploitation Chain", key=f"narr_{fid}"):
                            st.markdown(
                                f'<div style="background:#1a0505;border-left:3px solid #dc2626;'
                                f'padding:10px 14px;border-radius:0 4px 4px 0;font-size:13px;'
                                f'color:#fca5a5;line-height:1.8">'
                                + narr.replace("\n","<br>")
                                        .replace("**Step","<strong>Step")
                                        .replace("**Business","<strong>Business")
                                        .replace(":**",":</strong>")
                                + "</div>",
                                unsafe_allow_html=True
                            )

                    if f.get("compliance"):
                        st.caption("Compliance: " + " | ".join(f["compliance"]))

                with right:
                    st.markdown(f"**Severity:** {sev}")
                    st.markdown(f"**CVSS Score:** {f.get('cvss_score','-')}")
                    st.markdown(f"**CVSS Vector:**")
                    st.code(f.get('cvss_vector','-'), language="text")

                    # CVSS metric breakdown
                    metrics = f.get("cvss_metrics",{})
                    if metrics:
                        st.caption("CVSS Metrics:")
                        metric_labels = {"AV":"Attack Vector","AC":"Attack Complexity",
                                         "PR":"Privileges Req.","UI":"User Interaction",
                                         "S":"Scope","C":"Confidentiality",
                                         "I":"Integrity","A":"Availability"}
                        for k, label in metric_labels.items():
                            if k in metrics:
                                st.caption(f"{label}: `{metrics[k]}`")

                    st.markdown(f"**Module:** {f.get('module','-')}")
                    st.markdown(f"**Tool:** {f.get('tool_used','-')}")
                    if f.get("port"):
                        st.markdown(f"**Port:** {f['port']}/{f.get('service','?')}")
                    if f.get("validated_by"):
                        st.caption(f"By: {f['validated_by']}")
                        if f.get("validator_notes"):
                            st.caption(f"Notes: {f['validator_notes']}")

                notes_key = f"notes_{fid}"
                notes_val = st.text_input("Notes", key=notes_key, placeholder="Optional notes...")
                b1, b2, b3 = st.columns(3)

                if b1.button("✅ Approve", key=f"a_{fid}", use_container_width=True):
                    api_post(f"/validate/{session_id}",
                             {"finding_id":fid,"action":"approve",
                              "validator_name":validator_name,
                              "notes":st.session_state.get(notes_key,"")})
                    time.sleep(0.3); st.rerun()

                if b2.button("🔴 Reject (FP)", key=f"r_{fid}", use_container_width=True):
                    api_post(f"/validate/{session_id}",
                             {"finding_id":fid,"action":"reject",
                              "validator_name":validator_name,
                              "notes":st.session_state.get(notes_key,"")})
                    time.sleep(0.3); st.rerun()

                if b3.button("🟣 Escalate", key=f"e_{fid}", use_container_width=True):
                    api_post(f"/validate/{session_id}",
                             {"finding_id":fid,"action":"escalate",
                              "validator_name":validator_name,
                              "notes":st.session_state.get(notes_key,"")})
                    time.sleep(0.3); st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# Page: Reports & Download
# ══════════════════════════════════════════════════════════════════════════════
elif page == "📄 Reports & Download":
    st.title("📄 Reports & Download")

    session_id = st.text_input("Session ID", value=st.session_state.get("active_session",""))

    st.subheader("Generate & Download")
    cols = st.columns(4)
    formats = [("JSON","json","application/json"),
               ("HTML","html","text/html"),
               ("PDF","pdf","application/pdf"),
               ("CSV","csv","text/csv")]

    for col, (label, fmt, mime) in zip(cols, formats):
        with col:
            st.markdown(f"**{label} Report**")
            if st.button(f"Generate {label}", key=f"gen_{fmt}", use_container_width=True):
                if not session_id:
                    st.warning("Enter Session ID")
                else:
                    with st.spinner(f"Generating {label}..."):
                        content, content_type = download_report(session_id, fmt)
                    if content:
                        st.download_button(
                            label=f"⬇️ Download {label}",
                            data=content,
                            file_name=f"security_report_{session_id}.{fmt}",
                            mime=mime,
                            key=f"dl_{fmt}",
                            use_container_width=True,
                        )
                        st.success(f"{label} ready!")
                    else:
                        st.error("Generation failed. Is scan complete?")

    st.divider()

    # Generate all + preview HTML
    if st.button("🗒️ Generate All Formats (JSON + HTML + PDF + CSV)", type="primary",
                 use_container_width=True):
        if not session_id:
            st.warning("Enter Session ID")
        else:
            result = api_get(f"/report/{session_id}", {"format": "all"})
            if result:
                st.success("All reports generated!")
                for fp in result.get("files",[]):
                    st.code(fp, language="text")
                    try:
                        with open(fp, encoding="utf-8") as fobj:
                            content = fobj.read()
                        if fp.endswith(".html"):
                            st.subheader("HTML Preview")
                            st.components.v1.html(content, height=700, scrolling=True)
                        elif fp.endswith(".json"):
                            st.subheader("JSON Preview")
                            st.json(json.loads(content))
                        elif fp.endswith(".csv"):
                            st.subheader("CSV Preview (first 20 rows)")
                            import csv, io
                            reader = csv.DictReader(io.StringIO(content))
                            rows = list(reader)[:20]
                            if rows:
                                st.dataframe(rows)
                    except Exception as e:
                        st.caption(f"Preview error: {e}")
            else:
                st.error("Failed. Ensure scan is complete.")


# ══════════════════════════════════════════════════════════════════════════════
# Page: API Reference
# ══════════════════════════════════════════════════════════════════════════════
elif page == "📖 API Reference":
    st.title("📖 API Reference")
    endpoints = [
        ("GET",    "/",                                   "Health + session count"),
        ("GET",    "/health",                             "Liveness check"),
        ("POST",   "/scan",                               "Start scan (with full auth config)"),
        ("GET",    "/sessions",                           "List all sessions"),
        ("GET",    "/session/{id}",                       "Full session + all findings"),
        ("GET",    "/session/{id}/status",                "Live status + summary"),
        ("GET",    "/session/{id}/findings",              "Findings (filter: severity, module, validated)"),
        ("DELETE", "/session/{id}",                       "Delete session"),
        ("POST",   "/validate/{id}",                      "Validate single finding"),
        ("POST",   "/validate/{id}/batch",                "Batch approve/reject"),
        ("GET",    "/report/{id}?format=json|html|pdf|csv|all", "Generate report"),
        ("GET",    "/report/{id}/download?format=html",   "Download report file directly"),
        ("GET",    "/docs",                               "Swagger UI — try all endpoints"),
    ]
    mc = {"GET":"#16a34a","POST":"#2563eb","DELETE":"#dc2626"}
    for method, path, desc in endpoints:
        col = mc.get(method,"#6b7280")
        st.markdown(
            f'<div style="display:flex;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid #1e293b">'
            f'<span style="background:{col};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-family:monospace;min-width:52px;text-align:center">{method}</span>'
            f'<code style="color:#94a3b8;font-size:12px;flex:1">{path}</code>'
            f'<span style="color:#64748b;font-size:13px">{desc}</span></div>',
            unsafe_allow_html=True,
        )
    st.divider()
    st.markdown(f"[Open Swagger UI →]({API_BASE}/docs)")