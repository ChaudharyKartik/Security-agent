"""
Simple LLM test to diagnose issues
"""
import sys
import json
sys.path.insert(0, ".")

from agents.llm_client import get_llm

print("Testing LLM Client...")
llm = get_llm()

print(f"Provider: {llm.provider}")
print(f"Model: {llm.model}")
print(f"Base URL: {llm.base}")

# Check if available
available = llm.is_available()
print(f"Available: {available}")

if not available:
    print("ERROR: LLM not available!")
    sys.exit(1)

print("\n--- Testing basic chat ---")
response = llm.chat(
    system="You are a helpful assistant.",
    user="Say hello",
    max_tokens=20
)
print(f"Response: {repr(response)}")
print(f"Response length: {len(response) if response else 0}")

print("\n--- Testing JSON chat ---")
json_response = llm.chat_json(
    system="You are a JSON generator.",
    user='Return {"status": "ok"}',
    max_tokens=30
)
print(f"JSON Response: {json_response}")
print(f"Type: {type(json_response)}")

print("\nDone!")
