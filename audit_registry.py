import json
data = json.load(open("checklist/registry.json"))
print("Total items:", len(data))
print()
for item in data:
    iid    = item.get("id", "?")
    domain = item.get("domain", "?")
    agent  = item.get("agent", "?")
    modes  = item.get("modes", [])
    name   = item.get("canonical_name", "?")
    print(f"  {iid:8s} | domain={domain:10s} | agent={agent:15s} | modes={modes} | {name}")
