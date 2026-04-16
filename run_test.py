import httpx
import json
import time

# Start fresh scan
r = httpx.post("http://localhost:8000/scan", json={
    "target": "http://testphp.vulnweb.com",
    "scan_mode": "full",
    "run_cloud": False
}, timeout=10)
data = r.json()
sid = data["session_id"]
print(f"Scan started: {sid}")

# Poll until done
terminal = {"awaiting_validation", "completed", "error"}
prev = None
for i in range(72):
    time.sleep(5)
    r2 = httpx.get(f"http://localhost:8000/session/{sid}/status", timeout=30)
    d = r2.json()
    s = d.get("status")
    findings = d.get("total_findings", 0)
    if s != prev:
        print(f"  [{i*5:3d}s] {s} | findings={findings}")
        prev = s
    if s in terminal:
        print()
        summary = d.get("summary", {})
        print(f"Risk:      {summary.get('risk_rating', '-')}")
        print(f"Findings:  {summary.get('total_findings', 0)}")
        print(f"Breakdown: {summary.get('severity_breakdown', {})}")
        print(f"Agents:    {summary.get('agents_run', [])}")
        print(f"Tools:     {summary.get('tool_breakdown', {})}")
        if d.get("error"):
            print(f"Error:     {d['error']}")
        print()
        print(f"SESSION ID: {sid}")
        break
