"""
LLM Client — multi-provider interface for FP analysis and enrichment.

Supported providers (set via LLM_PROVIDER env var):
  groq    — Groq Cloud (free, fastest)  LLM_PROVIDER=groq   + GROQ_API_KEY
  gemini  — Google Gemini (free tier)   LLM_PROVIDER=gemini + GEMINI_API_KEY
  openrouter — OpenRouter free models   LLM_PROVIDER=openrouter + OPENROUTER_API_KEY
  ollama  — Local Ollama                LLM_PROVIDER=ollama (default)
  none    — Disable LLM (heuristic only)

Quick start (Groq — recommended):
  1. Get free API key at console.groq.com
  2. Set env: LLM_PROVIDER=groq  GROQ_API_KEY=gsk_...
  3. Restart the server — done.
"""
import json
import logging
import os
import re
import time

import httpx

logger = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────────────────
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "ollama").lower()

# Groq
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL   = os.getenv("LLM_MODEL", "llama-3.3-70b-versatile")
GROQ_BASE    = "https://api.groq.com/openai/v1"

# Gemini
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL   = os.getenv("LLM_MODEL", "gemini-2.0-flash")
GEMINI_BASE    = "https://generativelanguage.googleapis.com/v1beta/models"

# OpenRouter
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL   = os.getenv("LLM_MODEL", "meta-llama/llama-3.1-8b-instruct:free")
OPENROUTER_BASE    = "https://openrouter.ai/api/v1"

# Ollama (local)
OLLAMA_BASE  = os.getenv("OLLAMA_BASE", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("LLM_MODEL", "gemma4:e4b")

LLM_TIMEOUT  = int(os.getenv("LLM_TIMEOUT", "60"))


class LLMClient:
    """
    Provider-agnostic LLM client.
    Switch providers by setting LLM_PROVIDER env var — no code changes needed.
    """

    def __init__(self):
        self.provider = LLM_PROVIDER
        self.model    = self._resolve_model()
        self._available: bool | None = None

        logger.info(f"[LLM] Provider: {self.provider} | Model: {self.model}")

    def _resolve_model(self) -> str:
        custom = os.getenv("LLM_MODEL", "")
        if custom:
            return custom
        return {
            "groq":       GROQ_MODEL,
            "gemini":     GEMINI_MODEL,
            "openrouter": OPENROUTER_MODEL,
            "ollama":     OLLAMA_MODEL,
        }.get(self.provider, "unknown")

    # ── Public API ──────────────────────────────────────────────────────────

    def is_available(self) -> bool:
        if self._available is not None:
            return self._available

        if self.provider == "none":
            self._available = False
            return False

        try:
            if self.provider == "groq":
                self._available = self._check_groq()
            elif self.provider == "gemini":
                self._available = self._check_gemini()
            elif self.provider == "openrouter":
                self._available = self._check_openrouter()
            elif self.provider == "ollama":
                self._available = self._check_ollama()
            else:
                logger.warning(f"[LLM] Unknown provider: {self.provider}")
                self._available = False
        except Exception as e:
            logger.warning(f"[LLM] Availability check failed: {e}")
            self._available = False

        return self._available

    def chat(self, system: str, user: str,
             temperature: float = 0.2,
             max_tokens: int = 512) -> str | None:
        if not self.is_available():
            return None
        try:
            if self.provider == "groq":
                return self._chat_openai_compat(
                    GROQ_BASE, GROQ_API_KEY, system, user, temperature, max_tokens)
            elif self.provider == "gemini":
                return self._chat_gemini(system, user, temperature, max_tokens)
            elif self.provider == "openrouter":
                return self._chat_openai_compat(
                    OPENROUTER_BASE, OPENROUTER_API_KEY, system, user, temperature, max_tokens,
                    extra_headers={"HTTP-Referer": "https://vapt-platform", "X-Title": "VAPT Platform"})
            elif self.provider == "ollama":
                return self._chat_ollama(system, user, temperature, max_tokens)
        except Exception as e:
            logger.error(f"[LLM] chat() failed: {e}")
        return None

    def chat_json(self, system: str, user: str,
                  temperature: float = 0.1,
                  max_tokens: int = 512) -> dict | None:
        system_json = system + "\n\nIMPORTANT: Output ONLY valid JSON. No markdown, no explanation."
        text = self.chat(system_json, user, temperature=temperature, max_tokens=max_tokens)
        if not text:
            return None
        return self._parse_json(text)

    # ── Availability checks ──────────────────────────────────────────────────

    def _check_groq(self) -> bool:
        if not GROQ_API_KEY:
            logger.warning("[LLM] GROQ_API_KEY not set. Get one free at console.groq.com")
            return False
        r = httpx.get(f"{GROQ_BASE}/models",
                      headers={"Authorization": f"Bearer {GROQ_API_KEY}"}, timeout=8)
        if r.status_code == 200:
            models = [m["id"] for m in r.json().get("data", [])]
            found = any(self.model in m for m in models)
            if not found:
                logger.warning(f"[LLM] Model '{self.model}' not in Groq. Available: {models[:5]}")
            else:
                logger.info(f"[LLM] Groq ready — model: {self.model}")
            return found
        logger.warning(f"[LLM] Groq check failed: {r.status_code}")
        return False

    def _check_gemini(self) -> bool:
        if not GEMINI_API_KEY:
            logger.warning("[LLM] GEMINI_API_KEY not set. Get one free at aistudio.google.com")
            return False
        url = f"{GEMINI_BASE}?key={GEMINI_API_KEY}"
        r = httpx.get(url, timeout=8)
        if r.status_code == 200:
            logger.info(f"[LLM] Gemini ready — model: {self.model}")
            return True
        logger.warning(f"[LLM] Gemini check failed: {r.status_code}")
        return False

    def _check_openrouter(self) -> bool:
        if not OPENROUTER_API_KEY:
            logger.warning("[LLM] OPENROUTER_API_KEY not set. Get one free at openrouter.ai")
            return False
        r = httpx.get(f"{OPENROUTER_BASE}/models",
                      headers={"Authorization": f"Bearer {OPENROUTER_API_KEY}"}, timeout=8)
        if r.status_code == 200:
            logger.info(f"[LLM] OpenRouter ready — model: {self.model}")
            return True
        logger.warning(f"[LLM] OpenRouter check failed: {r.status_code}")
        return False

    def _check_ollama(self) -> bool:
        r = httpx.get(f"{OLLAMA_BASE}/api/tags", timeout=5)
        models = [m["name"] for m in r.json().get("models", [])]
        found = OLLAMA_MODEL in models or any(
            m.startswith(OLLAMA_MODEL.split(":")[0]) for m in models)
        if not found:
            logger.warning(f"[LLM] Ollama model '{OLLAMA_MODEL}' not found. Run: ollama pull {OLLAMA_MODEL}")
        else:
            logger.info(f"[LLM] Ollama ready — model: {OLLAMA_MODEL}")
        return found

    # ── Provider implementations ─────────────────────────────────────────────

    def _chat_openai_compat(self, base: str, api_key: str,
                             system: str, user: str,
                             temperature: float, max_tokens: int,
                             extra_headers: dict = None) -> str | None:
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type":  "application/json",
        }
        if extra_headers:
            headers.update(extra_headers)

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
            "temperature": temperature,
            "max_tokens":  max_tokens,
        }

        t0 = time.time()
        r = httpx.post(f"{base}/chat/completions",
                       json=payload, headers=headers, timeout=LLM_TIMEOUT)
        r.raise_for_status()
        text = r.json()["choices"][0]["message"]["content"].strip()
        logger.debug(f"[LLM] {self.provider} {round(time.time()-t0,1)}s | {len(text.split())} tokens")
        return text or None

    def _chat_gemini(self, system: str, user: str,
                     temperature: float, max_tokens: int) -> str | None:
        url = f"{GEMINI_BASE}/{self.model}:generateContent?key={GEMINI_API_KEY}"
        payload = {
            "system_instruction": {"parts": [{"text": system}]},
            "contents": [{"parts": [{"text": user}]}],
            "generationConfig": {
                "temperature":    temperature,
                "maxOutputTokens": max_tokens,
            },
        }

        t0 = time.time()
        r = httpx.post(url, json=payload, timeout=LLM_TIMEOUT)
        r.raise_for_status()
        data = r.json()
        text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
        logger.debug(f"[LLM] gemini {round(time.time()-t0,1)}s | {len(text.split())} tokens")
        return text or None

    def _chat_ollama(self, system: str, user: str,
                     temperature: float, max_tokens: int) -> str | None:
        payload = {
            "model":  OLLAMA_MODEL,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
        }
        t0 = time.time()
        r = httpx.post(f"{OLLAMA_BASE}/api/chat", json=payload, timeout=LLM_TIMEOUT)
        r.raise_for_status()
        msg  = r.json().get("message", {})
        text = msg.get("content", "").strip()

        # Gemma extended thinking fallback
        if not text and "thinking" in msg:
            thinking = msg.get("thinking", "")
            m = re.search(r"\{.*\}", thinking, re.DOTALL)
            if m:
                try:
                    return json.dumps(json.loads(m.group()))
                except Exception:
                    pass
            text = thinking[:500]

        logger.debug(f"[LLM] ollama {round(time.time()-t0,1)}s | {len(text.split())} tokens")
        return text or None

    # ── JSON parsing ─────────────────────────────────────────────────────────

    def _parse_json(self, text: str) -> dict | None:
        text = text.strip()
        # Strip markdown fences
        if text.startswith("```"):
            lines = text.split("\n")
            text  = "\n".join(lines[1:-1]) if len(lines) > 2 else text

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            m = re.search(r"\{.*\}", text, re.DOTALL)
            if m:
                try:
                    return json.loads(m.group())
                except Exception:
                    pass
            logger.warning(f"[LLM] Could not parse JSON: {text[:200]}")
            return None


# ── Singleton ────────────────────────────────────────────────────────────────
_client: LLMClient | None = None


def get_llm() -> LLMClient:
    global _client
    if _client is None:
        _client = LLMClient()
    return _client
