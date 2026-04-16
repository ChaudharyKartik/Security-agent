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

def check_api():
    r = api_get("/health")
    return r is not None and r.get("status") == "healthy"

def severity_badge_html(severity):
    badges = {
        "Critical": '<span class="badge badge-critical">🔴 CRITICAL</span>',
        "High": '<span class="badge badge-high">🟠 HIGH</span>',
        "Medium": '<span class="badge badge-medium">🟡 MEDIUM</span>',
        "Low": '<span class="badge badge-low">🔵 LOW</span>',
        "Info": '<span class="badge badge-info">⚪ INFO</span>'
    }
    return badges.get(severity, severity)

# ────────────────────────────────────────────────────────────────────────────
# SIDEBAR NAVIGATION
# ────────────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("""
    <div style="text-align: center; padding: 24px 0; margin-bottom: 24px; border-bottom: 1px solid #2a3342;">
        <h2 style="margin: 0; font-size: 28px; color: #d4a574;">🛡️</h2>
        <h3 style="margin: 12px 0 0 0; font-size: 18px; font-weight: 800; color: #e8e8e8;">Security Hub</h3>
        <p style="margin: 6px 0 0 0; font-size: 11px; color: #a0a8b8; text-transform: uppercase; letter-spacing: 1px; font-weight: 600;">Vulnerability Assessment Platform</p>
    </div>
    """, unsafe_allow_html=True)
    
    alive = check_api()
    if alive:
        st.success("✅ Connected", icon="✓")
    else:
        st.error("❌ Offline", icon="✗")
    
    st.divider()
    
    page = st.radio("Menu", ["🎯 Scan", "📊 Dashboard", "✅ Review", "📄 Export", "❓ Guide"], label_visibility="collapsed")
    
    st.divider()
    
    with st.expander("⚙️ Settings"):
        st.selectbox("Color Theme", ["Forest Green", "Slate", "Copper"])
        st.toggle("Advanced Mode")

# ────────────────────────────────────────────────────────────────────────────
# PAGE: SCAN
# ────────────────────────────────────────────────────────────────────────────

if page == "🎯 Scan":
    st.markdown("# 🎯 New Assessment")
    
    c1, c2 = st.columns([2, 1])
    with c1:
        st.markdown("### Target")
        target = st.text_input("URL or IP", placeholder="https://example.com", label_visibility="collapsed")
    with c2:
        st.markdown("### Scan Type")
        scan_type = st.selectbox("", ["Full", "Quick", "Deep"], label_visibility="collapsed")
    
    description = st.text_area("Description", placeholder="Assessment notes...", height=60)
    
    st.divider()
    
    with st.expander("🔑 Authentication", expanded=False):
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
        include_cloud = st.checkbox("☁️ Cloud Scan")
    
    with col3:
        launch = st.button("🚀 LAUNCH", type="primary", use_container_width=True)
    
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
                    
                    pct = {"recon": 20, "scanning": 50, "enrichment": 80, "awaiting_validation": 95, "completed": 100}.get(data.get("status"), 50)
                    prog.progress(pct / 100)
                    stat.markdown(f"**{data.get('status').upper()}** | {data.get('total_findings', 0)} findings")
                    
                    if data.get("status") in ("completed", "error"):
                        break
                
                final = api_get(f"/session/{result['session_id']}/status")
                if final and final.get("status") == "completed":
                    st.balloons()
                    st.success(f"✅ Complete! {final.get('total_findings')} vulnerabilities")
                    
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

elif page == "📊 Dashboard":
    st.markdown("# 📊 Assessment Dashboard")
    
    if st.button("🔄 Refresh", use_container_width=False):
        st.rerun()
    
    data = api_get("/sessions")
    
    if not data or data.get("count", 0) == 0:
        st.info("No scans yet")
    else:
        for s in reversed(data.get("sessions", [])[:10]):
            with st.expander(f"🎯 {s.get('target', '?')} | {s.get('total_findings', 0)} findings | {s.get('status')}"):
                c1, c2, c3 = st.columns(3)
                c1.metric("Status", s.get("status"))
                c2.metric("Risk", s.get("risk_rating", "-"))
                c3.metric("Findings", s.get("total_findings", 0))

# ────────────────────────────────────────────────────────────────────────────
# PAGE: REVIEW
# ────────────────────────────────────────────────────────────────────────────

elif page == "✅ Review":
    st.markdown("# ✅ Findings Review")
    
    sid = st.text_input("Session ID", value=st.session_state.get("sid", ""))
    
    if not sid:
        st.info("Enter Session ID")
    else:
        data = api_get(f"/session/{sid}")
        if not data:
            st.error("Not found")
        else:
            findings = data.get("enriched_findings", [])
            summary = data.get("summary", {})
            bd = summary.get("severity_breakdown", {})
            
            c1, c2, c3, c4, c5 = st.columns(5)
            for col, sev in [(c1, "Critical"), (c2, "High"), (c3, "Medium"), (c4, "Low"), (c5, "Info")]:
                with col:
                    st.metric(sev, bd.get(sev, 0))
            
            st.divider()
            
            for f in findings:
                severity = f.get("severity", "Info")
                with st.expander(f"{severity_badge_html(severity)} {f.get('name')} | CVSS {f.get('cvss_score')}"):
                    st.markdown(f.get("description", ""))
                    st.markdown(f"**Fix:** {f.get('solution', '')}")
                    
                    c1, c2, c3 = st.columns(3)
                    if c1.button("✅", key=f"a_{f.get('id')}"):
                        pass
                    if c2.button("❌", key=f"r_{f.get('id')}"):
                        pass
                    if c3.button("🔖", key=f"e_{f.get('id')}"):
                        pass

# ────────────────────────────────────────────────────────────────────────────
# PAGE: EXPORT
# ────────────────────────────────────────────────────────────────────────────

elif page == "📄 Export":
    st.markdown("# 📄 Report Export")
    st.info("Select a session and download report in your preferred format")

# ────────────────────────────────────────────────────────────────────────────
# PAGE: GUIDE
# ────────────────────────────────────────────────────────────────────────────

elif page == "❓ Guide":
    st.markdown("# ❓ Getting Started")
    st.markdown("""
    ## Quick Start
    
    1. **New Scan** → Enter target URL
    2. **Dashboard** → View all scans
    3. **Review** → Check findings
    4. **Export** → Download report
    
    ## Features
    
    - Multi-agent scanning (Web, Network, Cloud)
    - Authentication support (Basic, Form, Token, etc.)
    - Real CVSS scoring
    - Evidence capture & PoCs
    - Human validation workflow
    
    ## Supported Targets
    
    - Web: `https://example.com`
    - IP: `192.168.1.100`
    - Domain: `example.com`
    """)
