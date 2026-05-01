"""
LLM Client — multi-provider interface with automatic fallback chain.

Provider priority (first available wins):
  LLM_PROVIDER env var → fallback chain: groq → gemini → openrouter → ollama

Each provider has its own circuit breaker and availability cache so a failure
on Groq automatically promotes Gemini without human intervention.

Stability features:
  - Per-provider circuit breaker: 3 failures → 5 min cooldown, then retry
  - Per-provider availability TTL: re-checks every 60 s, recovers automatically
  - Retry with exponential backoff: ConnectError, Timeout, 5xx all retried
  - 429 handling: respects Retry-After header before trying next provider
  - Robust JSON parsing: fences, language tags, prose wrappers, truncated output
  - chat_json retries once with stricter prompt on bad parse
  - Per-provider timeouts: Ollama 120 s, OpenRouter 45 s, cloud APIs 30 s
"""
import json
import logging
import os
import re
import time
from typing import Callable

import httpx
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "groq").lower()

GROQ_API_KEY       = os.getenv("GROQ_API_KEY", "")
GEMINI_API_KEY     = os.getenv("GEMINI_API_KEY", "")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OLLAMA_BASE        = os.getenv("OLLAMA_BASE", "http://localhost:11434")

GROQ_BASE       = "https://api.groq.com/openai/v1"
GEMINI_BASE     = "https://generativelanguage.googleapis.com/v1beta/models"
OPENROUTER_BASE = "https://openrouter.ai/api/v1"

# Per-provider default models — each can be overridden independently
_PROVIDER_MODELS: dict[str, str] = {
    "groq":       os.getenv("GROQ_MODEL",       "llama-3.3-70b-versatile"),
    "gemini":     os.getenv("GEMINI_MODEL",     "gemini-2.0-flash"),
    "openrouter": os.getenv("OPENROUTER_MODEL", "meta-llama/llama-3.1-8b-instruct:free"),
    "ollama":     os.getenv("OLLAMA_MODEL",     "gemma4:e4b"),
}
# LLM_MODEL overrides all providers if set (legacy behaviour preserved)
if os.getenv("LLM_MODEL"):
    for _k in _PROVIDER_MODELS:
        _PROVIDER_MODELS[_k] = os.getenv("LLM_MODEL")

# Fallback order — primary comes first via _build_chain()
_FALLBACK_CHAIN = ["groq", "gemini", "openrouter", "ollama"]

# Per-provider timeouts (seconds)
_TIMEOUTS: dict[str, int] = {
    "groq":       int(os.getenv("LLM_TIMEOUT", "30")),
    "gemini":     int(os.getenv("LLM_TIMEOUT", "30")),
    "openrouter": int(os.getenv("LLM_TIMEOUT", "45")),
    "ollama":     int(os.getenv("LLM_TIMEOUT", "120")),
}

_AVAILABILITY_TTL          = 60    # seconds before re-checking availability
_CIRCUIT_BREAKER_THRESHOLD = 3     # consecutive failures before circuit opens
_CIRCUIT_BREAKER_COOLDOWN  = 300   # seconds before circuit closes and retries
_MAX_RETRIES               = 3     # attempts per provider per call


class LLMClient:
    """
    Provider-agnostic LLM client.
    Tries LLM_PROVIDER first; on failure automatically falls back through
    groq → gemini → openrouter → ollama (skipping providers without keys).
    """

    def __init__(self):
        self.provider = LLM_PROVIDER   # primary / preferred provider
        self.model    = _PROVIDER_MODELS.get(self.provider, "unknown")

        # Per-provider state: availability cache + circuit breaker
        self._state: dict[str, dict] = {}

        logger.info(
            f"[LLM] Primary: {self.provider} ({self.model}) | "
            f"Chain: {self._build_chain()}"
        )

    # ── Public API ─────────────────────────────────────────────────────────────

    def is_available(self) -> bool:
        """True if at least one provider in the chain is reachable."""
        if self.provider == "none":
            return False
        return any(self._provider_available(p) for p in self._build_chain())

    def chat(self, system: str, user: str,
             temperature: float = 0.2,
             max_tokens: int = 512) -> str | None:
        """
        Send a chat request. Tries providers in chain order until one succeeds.
        Returns the text response, or None if all providers fail.
        """
        if self.provider == "none":
            return None

        for provider in self._build_chain():
            if not self._provider_available(provider):
                logger.debug(f"[LLM] Skipping {provider} (unavailable/circuit open)")
                continue

            result = self._try_provider(provider, system, user, temperature, max_tokens)
            if result:
                self._reset_fails(provider)
                if provider != self.provider:
                    logger.info(f"[LLM] Fallback succeeded via {provider}")
                return result

            self._record_failure(provider, "returned None after retries")

        logger.error("[LLM] All providers in chain exhausted — no response")
        return None

    def chat_json(self, system: str, user: str,
                  temperature: float = 0.1,
                  max_tokens: int = 512) -> dict | None:
        """
        Chat and parse response as JSON.
        Retries once with a stricter prompt if the first parse fails.
        """
        json_system = (
            system +
            "\n\nCRITICAL: Output ONLY valid JSON. No markdown, no code fences, no explanation."
        )

        text = self.chat(json_system, user, temperature=temperature, max_tokens=max_tokens)
        if not text:
            return None

        result = self._parse_json(text)
        if result is not None:
            return result

        # Retry once with temperature=0 and an explicit structure reminder
        logger.debug("[LLM] JSON parse failed — retrying with strict prompt")
        strict_user = (
            "Return ONLY a JSON object. No text before or after it. "
            "Start your response with { and end with }.\n\n" + user
        )
        text2 = self.chat(json_system, strict_user, temperature=0.0, max_tokens=max_tokens)
        if text2:
            result2 = self._parse_json(text2)
            if result2 is not None:
                return result2

        logger.warning("[LLM] chat_json: both attempts returned unparseable JSON")
        return None

    # ── Chain helpers ──────────────────────────────────────────────────────────

    def _build_chain(self) -> list[str]:
        """Primary provider first, then the rest of the fallback chain."""
        chain = [self.provider]
        for p in _FALLBACK_CHAIN:
            if p != self.provider:
                chain.append(p)
        return chain

    def _get_state(self, provider: str) -> dict:
        if provider not in self._state:
            self._state[provider] = {
                "available":         None,
                "available_at":      0.0,
                "consecutive_fails": 0,
                "circuit_open_until": 0.0,
            }
        return self._state[provider]

    def _provider_available(self, provider: str) -> bool:
        if provider == "none":
            return False

        st  = self._get_state(provider)
        now = time.time()

        # Circuit open
        if st["circuit_open_until"] > now:
            return False

        # Re-check if stale
        if st["available"] is None or (now - st["available_at"]) > _AVAILABILITY_TTL:
            st["available"]    = self._check_provider(provider)
            st["available_at"] = now

        return bool(st["available"])

    def _reset_fails(self, provider: str):
        st = self._get_state(provider)
        st["consecutive_fails"]  = 0
        st["circuit_open_until"] = 0.0

    def _record_failure(self, provider: str, reason: str = ""):
        st = self._get_state(provider)
        st["consecutive_fails"] += 1
        st["available"]          = None
        st["available_at"]       = 0.0

        if st["consecutive_fails"] >= _CIRCUIT_BREAKER_THRESHOLD:
            st["circuit_open_until"] = time.time() + _CIRCUIT_BREAKER_COOLDOWN
            logger.warning(
                f"[LLM] Circuit OPEN for {provider} after "
                f"{st['consecutive_fails']} failures ({reason}). "
                f"Cooldown {_CIRCUIT_BREAKER_COOLDOWN}s."
            )

    # ── Availability checks ────────────────────────────────────────────────────

    def _check_provider(self, provider: str) -> bool:
        try:
            if provider == "groq":       return self._check_groq()
            if provider == "gemini":     return self._check_gemini()
            if provider == "openrouter": return self._check_openrouter()
            if provider == "ollama":     return self._check_ollama()
            return False
        except httpx.ConnectError:
            logger.warning(f"[LLM] {provider} unreachable")
            return False
        except httpx.TimeoutException:
            logger.warning(f"[LLM] {provider} availability check timed out")
            return False
        except Exception as e:
            logger.warning(f"[LLM] {provider} availability check failed: {e}")
            return False

    def _check_groq(self) -> bool:
        if not GROQ_API_KEY:
            logger.debug("[LLM] GROQ_API_KEY not set — skipping Groq")
            return False
        r = httpx.get(f"{GROQ_BASE}/models",
                      headers={"Authorization": f"Bearer {GROQ_API_KEY}"}, timeout=8)
        if r.status_code != 200:
            logger.warning(f"[LLM] Groq check: HTTP {r.status_code}")
            return False
        models = [m["id"] for m in r.json().get("data", [])]
        model  = _PROVIDER_MODELS["groq"]
        found  = any(model in m for m in models)
        if found:
            logger.info(f"[LLM] Groq ready — {model}")
        else:
            logger.warning(f"[LLM] Groq model '{model}' not available. Found: {models[:5]}")
        return found

    def _check_gemini(self) -> bool:
        if not GEMINI_API_KEY:
            logger.debug("[LLM] GEMINI_API_KEY not set — skipping Gemini")
            return False
        r = httpx.get(f"{GEMINI_BASE}?key={GEMINI_API_KEY}", timeout=8)
        ok = r.status_code == 200
        if ok:
            logger.info(f"[LLM] Gemini ready — {_PROVIDER_MODELS['gemini']}")
        else:
            logger.warning(f"[LLM] Gemini check: HTTP {r.status_code}")
        return ok

    def _check_openrouter(self) -> bool:
        if not OPENROUTER_API_KEY:
            logger.debug("[LLM] OPENROUTER_API_KEY not set — skipping OpenRouter")
            return False
        r = httpx.get(f"{OPENROUTER_BASE}/models",
                      headers={"Authorization": f"Bearer {OPENROUTER_API_KEY}"}, timeout=8)
        ok = r.status_code == 200
        if ok:
            logger.info(f"[LLM] OpenRouter ready — {_PROVIDER_MODELS['openrouter']}")
        else:
            logger.warning(f"[LLM] OpenRouter check: HTTP {r.status_code}")
        return ok

    def _check_ollama(self) -> bool:
        try:
            r = httpx.get(f"{OLLAMA_BASE}/api/tags", timeout=5)
            r.raise_for_status()
            models = [m["name"] for m in r.json().get("models", [])]
        except Exception as e:
            logger.warning(f"[LLM] Ollama unreachable: {e}. Run: ollama serve")
            return False
        model     = _PROVIDER_MODELS["ollama"]
        base_name = model.split(":")[0]
        found     = model in models or any(m.startswith(base_name) for m in models)
        if found:
            logger.info(f"[LLM] Ollama ready — {model}")
        else:
            logger.warning(f"[LLM] Ollama model '{model}' not pulled. Run: ollama pull {model}")
        return found

    # ── Provider dispatch ──────────────────────────────────────────────────────

    def _try_provider(self, provider: str, system: str, user: str,
                      temperature: float, max_tokens: int) -> str | None:
        model = _PROVIDER_MODELS.get(provider, "unknown")
        try:
            if provider == "groq":
                return self._chat_openai_compat(
                    GROQ_BASE, GROQ_API_KEY, model,
                    system, user, temperature, max_tokens)

            if provider == "gemini":
                return self._chat_gemini(
                    model, system, user, temperature, max_tokens)

            if provider == "openrouter":
                return self._chat_openai_compat(
                    OPENROUTER_BASE, OPENROUTER_API_KEY, model,
                    system, user, temperature, max_tokens,
                    extra_headers={
                        "HTTP-Referer": "https://vapt-platform",
                        "X-Title":      "VAPT Platform",
                    })

            if provider == "ollama":
                return self._chat_ollama(
                    model, system, user, temperature, max_tokens)

        except Exception as e:
            logger.warning(f"[LLM] {provider} dispatch error: {e}")
        return None

    # ── Provider implementations ───────────────────────────────────────────────

    def _chat_openai_compat(self, base: str, api_key: str, model: str,
                             system: str, user: str,
                             temperature: float, max_tokens: int,
                             extra_headers: dict = None) -> str | None:
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        if extra_headers:
            headers.update(extra_headers)

        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
            "temperature": temperature,
            "max_tokens":  max_tokens,
        }
        # Resolve provider name from base URL for timeout lookup
        pname   = "groq" if "groq" in base else "openrouter"
        timeout = _TIMEOUTS.get(pname, 30)

        def _attempt() -> str | None:
            r = httpx.post(f"{base}/chat/completions",
                           json=payload, headers=headers, timeout=timeout)
            if r.status_code == 429:
                raise _RateLimitError(int(r.headers.get("retry-after", 5)))
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"].strip() or None

        return self._with_retry(_attempt)

    def _chat_gemini(self, model: str, system: str, user: str,
                     temperature: float, max_tokens: int) -> str | None:
        url     = f"{GEMINI_BASE}/{model}:generateContent?key={GEMINI_API_KEY}"
        payload = {
            "system_instruction": {"parts": [{"text": system}]},
            "contents":           [{"parts": [{"text": user}]}],
            "generationConfig":   {"temperature": temperature, "maxOutputTokens": max_tokens},
        }

        def _attempt() -> str | None:
            r = httpx.post(url, json=payload, timeout=_TIMEOUTS["gemini"])
            if r.status_code == 429:
                raise _RateLimitError(int(r.headers.get("retry-after", 10)))
            r.raise_for_status()
            return r.json()["candidates"][0]["content"]["parts"][0]["text"].strip() or None

        return self._with_retry(_attempt)

    def _chat_ollama(self, model: str, system: str, user: str,
                     temperature: float, max_tokens: int) -> str | None:
        payload = {
            "model":   model,
            "stream":  False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
        }

        def _attempt() -> str | None:
            r = httpx.post(f"{OLLAMA_BASE}/api/chat",
                           json=payload, timeout=_TIMEOUTS["ollama"])
            r.raise_for_status()
            msg  = r.json().get("message", {})
            text = msg.get("content", "").strip()

            # Gemma extended-thinking fallback
            if not text and msg.get("thinking"):
                thinking = msg["thinking"]
                m = re.search(r"\{.*\}", thinking, re.DOTALL)
                if m:
                    try:
                        return json.dumps(json.loads(m.group()))
                    except Exception:
                        pass
                text = thinking[:500]
            return text or None

        return self._with_retry(_attempt)

    # ── Retry logic ────────────────────────────────────────────────────────────

    def _with_retry(self, fn: Callable, max_attempts: int = _MAX_RETRIES) -> str | None:
        backoff = 2.0
        t0      = time.time()

        for attempt in range(1, max_attempts + 1):
            try:
                result = fn()
                logger.debug(f"[LLM] OK in {round(time.time()-t0,1)}s")
                return result

            except _RateLimitError as e:
                logger.warning(f"[LLM] 429 — waiting {e.retry_after}s (attempt {attempt}/{max_attempts})")
                if attempt < max_attempts:
                    time.sleep(e.retry_after)

            except httpx.TimeoutException:
                logger.warning(f"[LLM] Timeout attempt {attempt}/{max_attempts} ({round(time.time()-t0,1)}s)")
                if attempt < max_attempts:
                    time.sleep(backoff); backoff *= 2

            except httpx.ConnectError as e:
                logger.warning(f"[LLM] ConnectError attempt {attempt}/{max_attempts}: {e}")
                if attempt < max_attempts:
                    time.sleep(backoff); backoff *= 2

            except httpx.HTTPStatusError as e:
                if e.response.status_code in (500, 502, 503, 504):
                    logger.warning(f"[LLM] HTTP {e.response.status_code} attempt {attempt}/{max_attempts}")
                    if attempt < max_attempts:
                        time.sleep(backoff); backoff *= 2
                else:
                    logger.error(f"[LLM] HTTP {e.response.status_code} — not retrying")
                    break

            except Exception as e:
                logger.error(f"[LLM] Unexpected error attempt {attempt}/{max_attempts}: {e}")
                break

        return None

    # ── JSON parsing ───────────────────────────────────────────────────────────

    def _parse_json(self, text: str) -> dict | None:
        text = text.strip()

        # 1. Raw parse (fast path)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # 2. Strip markdown fences (with or without language tag)
        fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if fence:
            try:
                return json.loads(fence.group(1))
            except json.JSONDecodeError:
                pass

        # 3. Largest {...} block — handles prose before/after
        for candidate in sorted(re.findall(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)?\}", text, re.DOTALL),
                                 key=len, reverse=True):
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                continue

        # 4. Greedy first-{ to last-}
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                pass

        logger.warning(f"[LLM] Could not parse JSON: {text[:200]!r}")
        return None


# ── Rate-limit sentinel ────────────────────────────────────────────────────────

class _RateLimitError(Exception):
    def __init__(self, retry_after: int = 5):
        self.retry_after = retry_after


# ── Singleton ─────────────────────────────────────────────────────────────────
_client: LLMClient | None = None


def get_llm() -> LLMClient:
    global _client
    if _client is None:
        _client = LLMClient()
    return _client
