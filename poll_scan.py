import httpx
import time
import json

sid = "4F2FA9F9"
terminal = {"awaiting_validation", "completed", "error"}
prev_status = None

for i in range(60):
    r = httpx.get(f"http://localhost:8000/session/{sid}/status", timeout=5)
    data = r.json()
    status = data.get("status")
    findings = data.get("total_findings", 0)

    if status != prev_status:
        print(f"[{i*5:3d}s] status={status} | findings={findings}")
        prev_status = status

    if status in terminal:
        print()
        print("=== SCAN COMPLETE ===")
        print(f"Status:   {status}")
        print(f"Findings: {findings}")
        summary = data.get("summary", {})
        if summary:
            print(f"Risk Rating: {summary.get('risk_rating', '-')}")
            print(f"Breakdown:   {summary.get('severity_breakdown', {})}")
        if data.get("error"):
            print(f"Error: {data['error']}")
        break

    time.sleep(5)
else:
    print("Timed out after 5 minutes")
