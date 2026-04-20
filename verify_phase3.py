"""
Phase 3 verification: tests LLM client + FP agent + full scan pipeline.
"""
import sys, time, json
sys.path.insert(0, ".")

print("=" * 60)
print("PHASE 3 VERIFICATION")
print("=" * 60)

# 1. LLM Client
print("\n[1] LLM Client")
from agents.llm_client import get_llm
llm = get_llm()
print(f"    Provider : {llm.provider}")
print(f"    Model    : {llm.model}")
print(f"    Available: {llm.is_available()}")

if not llm.is_available():
    print("    FAIL: LLM not available")
    sys.exit(1)

t = time.time()
resp = llm.chat(
    system="You are a senior penetration tester.",
    user='In one sentence: what is a missing HSTS header vulnerability?',
)
elapsed = round(time.time() - t, 1)
print(f"    Response ({elapsed}s): {resp}")

# 2. JSON mode
print("\n[2] JSON Mode")
result = llm.chat_json(
    system="You are a security analyst.",
    user='Return JSON: {"risk": "high", "exploitable": true} for an open SSH port finding.',
)
print(f"    Parsed JSON: {result}")

# 3. FP Agent with mock finding
print("\n[3] FP Agent")
from agents.fp_agent import analyse_findings

mock_finding = {
    "id": "TEST-001",
    "name": "HSTS Not Enforced",
    "severity": "Medium",
    "module": "web",
    "tool_used": "Built-in HTTP Probe",
    "url": "http://scanme.nmap.org",
    "cvss_score": 3.1,
    "description": "Response missing strict-transport-security header.",
    "solution": "Add HSTS header at web server level.",
    "confidence_score": 0.35,
    "evidence": {"response_headers": "Server: Apache, Content-Type: text/html"}
}

t = time.time()
results = analyse_findings([mock_finding])
elapsed = round(time.time() - t, 1)
r = results[0]
print(f"    LLM analysed  : {r.get('llm_analysed')}")
print(f"    FP status     : {r.get('fp_status')}")
print(f"    Confidence    : {r.get('confidence_score')}")
print(f"    FP reason     : {r.get('fp_reason')}")
print(f"    AI description: {r.get('ai_description', '')[:100]}")
print(f"    Time          : {elapsed}s")

# 4. Check DB migration
print("\n[4] DB Schema (AI columns)")
import sqlite3
conn = sqlite3.connect("vapt.db")
cols = [row[1] for row in conn.execute("PRAGMA table_info(scan_findings)")]
conn.close()
ai_cols = ["llm_analysed", "ai_confidence_score", "fp_status", "fp_reason", "ai_description", "ai_remediation", "impact"]
for col in ai_cols:
    status = "OK" if col in cols else "MISSING"
    print(f"    {col:25s} [{status}]")

print("\n" + "=" * 60)
print("PHASE 3 VERIFICATION COMPLETE")
print("=" * 60)
