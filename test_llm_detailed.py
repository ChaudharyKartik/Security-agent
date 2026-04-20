"""
Detailed LLM diagnostic
"""
import sys
sys.path.insert(0, ".")

from agents.llm_client import get_llm

llm = get_llm()

print(f"LLM Provider: {llm.provider}")
print(f"LLM Model: {llm.model}")
print(f"Available: {llm.is_available()}")
print()

# Test 1: chat() with question
print("=" * 60)
print("TEST 1: chat() - HSTS vulnerability question")
print("=" * 60)
resp = llm.chat(
    system="You are a senior penetration tester.",
    user='In one sentence: what is a missing HSTS header vulnerability?',
)
print(f"Response: {repr(resp)}")
print(f"Empty?: {not resp or resp.strip() == ''}")
print()

# Test 2: chat_json() - simple JSON
print("=" * 60)
print("TEST 2: chat_json() - Simple JSON")
print("=" * 60)
result = llm.chat_json(
    system="You are a security analyst.",
    user='Return JSON: {"risk": "high", "exploitable": true} for an open SSH port finding.',
)
print(f"Response: {result}")
print(f"Type: {type(result)}")
print()

# Test 3: chat_json() - Complex JSON for FP analysis
print("=" * 60)
print("TEST 3: chat_json() - FP Analysis JSON")
print("=" * 60)

finding_summary = """Name: HSTS Not Enforced
Severity: Medium
Module: web | Tool: Built-in HTTP Probe
Target URL: http://scanme.nmap.org
CVSS Score: 3.1
Current Description: Response missing strict-transport-security header."""

user_prompt = f"""Analyse this security finding and respond in JSON:

{finding_summary}

Return exactly this JSON structure:
{{
  "confidence_score": <float 0.0-1.0>,
  "fp_status": "<confirmed|likely_false_positive|uncertain>",
  "fp_reason": "<one sentence explaining your confidence assessment>",
  "ai_description": "<professional 1-2 sentence description of the vulnerability>",
  "ai_impact": "<1-2 sentence business/technical impact>",
  "ai_remediation": "<specific, actionable remediation steps in 1-2 sentences>"
}}"""

print("Sending JSON request to LLM...")
result = llm.chat_json(
    system="You are a senior penetration tester and security analyst with 10+ years of experience.",
    user=user_prompt,
    temperature=0.1,
)
print(f"Response: {result}")
print(f"Type: {type(result)}")

if result:
    print(f"Has confidence_score?: {'confidence_score' in result}")
    print(f"Has fp_status?: {'fp_status' in result}")
    print(f"Has ai_description?: {'ai_description' in result}")

print()
print("=" * 60)
print("DONE")
print("=" * 60)
