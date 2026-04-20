"""
Debug raw LLM responses
"""
import sys
import httpx
sys.path.insert(0, ".")

BASE = "http://localhost:11434"
MODEL = "gemma4:e4b"

print(f"Checking Ollama at {BASE} for model {MODEL}...")

# Check model exists
try:
    r = httpx.get(f"{BASE}/api/tags", timeout=5)
    models = [m["name"] for m in r.json().get("models", [])]
    print(f"Available models: {models}")
except Exception as e:
    print(f"Error: {e}")

print()
print("=" * 60)
print("TEST 1: Raw chat response - simple question")
print("=" * 60)

payload1 = {
    "model": MODEL,
    "stream": False,
    "options": {"temperature": 0.2, "num_predict": 60},
    "messages": [
        {"role": "system", "content": "You are a senior penetration tester."},
        {"role": "user", "content": 'In one sentence: what is a missing HSTS header vulnerability?'},
    ],
}

try:
    r = httpx.post(f"{BASE}/api/chat", json=payload1, timeout=60)
    r.raise_for_status()
    resp = r.json()
    print(f"Status: {r.status_code}")
    print(f"Full response: {resp}")
    print(f"Message content: {repr(resp.get('message', {}).get('content'))}")
except Exception as e:
    print(f"Error: {e}")

print()
print("=" * 60)
print("TEST 2: Raw chat response - JSON request")
print("=" * 60)

payload2 = {
    "model": MODEL,
    "stream": False,
    "options": {"temperature": 0.1, "num_predict": 400},
    "messages": [
        {"role": "system", "content": "You are a JSON generator. Respond ONLY with valid JSON. No markdown, no explanation."},
        {"role": "user", "content": 'Return JSON: {"status": "ok"}'},
    ],
}

try:
    r = httpx.post(f"{BASE}/api/chat", json=payload2, timeout=60)
    r.raise_for_status()
    resp = r.json()
    print(f"Status: {r.status_code}")
    print(f"Full response: {resp}")
    print(f"Message content: {repr(resp.get('message', {}).get('content'))}")
except Exception as e:
    print(f"Error: {e}")

print()
print("Done!")
