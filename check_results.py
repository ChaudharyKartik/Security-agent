import httpx
import json

# Check all sessions from DB
r = httpx.get("http://localhost:8000/sessions", timeout=15)
sessions = r.json()
print(f"Total sessions in DB: {sessions['total']}")
print()

for s in sessions["sessions"][:5]:
    print(f"Session: {s['session_id']} | status={s['status']:22s} | findings={s['total_findings']} | risk={s['risk_rating']}")

# Get findings from latest completed session
completed = [s for s in sessions["sessions"] if s["total_findings"] > 0]
if completed:
    sid = completed[0]["session_id"]
    print(f"\n--- Findings for session {sid} ---")
    r2 = httpx.get(f"http://localhost:8000/session/{sid}/findings", timeout=15)
    fdata = r2.json()
    print(f"Total findings: {fdata['count']}")
    for f in fdata["findings"]:
        conf = f.get("confidence_score", "N/A")
        print(f"  [{f['severity']:8s}] conf={conf} | module={f.get('module','?'):8s} | {f['name']}")
else:
    print("\nNo sessions with findings yet - scan still running?")
    # Show latest session detail
    if sessions["sessions"]:
        sid = sessions["sessions"][0]["session_id"]
        r3 = httpx.get(f"http://localhost:8000/session/{sid}/status", timeout=15)
        print(json.dumps(r3.json(), indent=2))
