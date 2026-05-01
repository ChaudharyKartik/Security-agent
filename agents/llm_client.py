"""
LLM Client — multi-provider interface for FP analysis and enrichment.

Supported providers (set via LLM_PROVIDER env var):
  groq        — Groq Cloud (free, fastest)   LLM_PROVIDER=groq        + GROQ_API_KEY
  gemini      — Google Gemini (free tier)    LLM_PROVIDER=gemini      + GEMINI_API_KEY
  openrouter  — OpenRouter free models       LLM_PROVIDER=openrouter  + OPENROUTER_API_KEY
  ollama      — Local Ollama                 LLM_PROVIDER=ollama (default)
  none        — Disable LLM (heuristic only)

Stability features:
  - Availability TTL: re-checks every 60 s instead of caching forever
  - Circuit breaker: after 3 consecutive failures, pauses 5 min before retry
  - Retry with exponential backoff: connection errors, timeouts, 5xx all retried
  - 429 handling: respects Retry-After header
  - Robust JSON parsing: handles markdown fences, language tags, text surrounding JSON
  - chat_json retries once with a stricter prompt if the first parse fails
  - Per-provider timeouts: Ollama gets 120 s, cloud APIs get 30–45 s
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
GROQ_MODEL         = os.getenv("LLM_MODEL", "llama-3.3-70b-versatile")
GROQ_BASE          = "https://api.groq.com/openai/v1"

GEMINI_API_KEY     = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL       = os.getenv("LLM_MODEL", "gemini-2.0-flash")
GEMINI_BASE        = "https://generativelanguage.googleapis.com/v1beta/models"

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL   = os.getenv("LLM_MODEL", "meta-llama/llama-3.1-8b-instruct:free")
OPENROUTER_BASE    = "https://openrouter.ai/api/v1"

OLLAMA_BASE        = os.getenv("OLLAMA_BASE", "http://localhost:11434")
OLLAMA_MODEL       = os.getenv("LLM_MODEL", "gemma4:e4b")

# Per-provider timeouts (seconds) — Ollama needs more headroom for local models
_TIMEOUTS: dict[str, int] = {
    "groq":       int(os.getenv("LLM_TIMEOUT", "30")),
    "gemini":     int(os.getenv("LLM_TIMEOUT", "30")),
    "openrouter": int(os.getenv("LLM_TIMEOUT", "45")),
    "ollama":     int(os.getenv("LLM_TIMEOUT", "120")),
}

_AVAILABILITY_TTL        = 60    # re-check availability every N seconds
_CIRCUIT_BREAKER_THRESHOLD = 3   # consecutive failures before opening circuit
_CIRCUIT_BREAKER_COOLDOWN  = 300 # seconds to wait before retrying after circuit opens
_MAX_RETRIES             = 3     # max attempts for transient errors


class LLMClient:
    """
    Provider-agnostic LLM client with circuit breaker, retry, and robust JSON parsing.
    Switch providers by setting LLM_PROVIDER env var — no code changes needed.
    """

    def __init__(self):
        self.provider = LLM_PROVIDER
        self.model    = self._resolve_model()

        # Availability cache with TTL
        self._available:         bool | None = None
        self._available_at:      float       = 0.0   # epoch of last check

        # Circuit breaker state
        self._consecutive_fails: int         = 0
        self._circuit_open_until: float      = 0.0   # epoch when circuit can close

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

    # ── Public API ─────────────────────────────────────────────────────────────

    def is_available(self) -> bool:
        if self.provider == "none":
            return False

        now = time.time()

        # Circuit open — don't even try until cooldown expires
        if self._circuit_open_until > now:
            remaining = int(self._circuit_open_until - now)
            logger.debug(f"[LLM] Circuit open — {remaining}s cooldown remaining")
            return False

        # Re-check if TTL expired or never checked
        if self._available is None or (now - self._available_at) > _AVAILABILITY_TTL:
            self._available    = self._check_availability()
            self._available_at = now

        return bool(self._available)

    def chat(self, system: str, user: str,
             temperature: float = 0.2,
             max_tokens: int = 512) -> str | None:
        if not self.is_available():
            return None
        try:
            result = self._dispatch_chat(system, user, temperature, max_tokens)
            if result:
                self._consecutive_fails = 0   # reset on success
            return result
        except Exception as e:
            self._record_failure(str(e))
            return None

    def chat_json(self, system: str, user: str,
                  temperature: float = 0.1,
                  max_tokens: int = 512) -> dict | None:
        """
        Chat and parse response as JSON.
        If the first response can't be parsed, retries once with a stricter prompt.
        """
        json_system = system + "\n\nCRITICAL: Output ONLY valid JSON. No markdown, no code fences, no explanation."

        text = self.chat(json_system, user, temperature=temperature, max_tokens=max_tokens)
        if not text:
            return None

        result = self._parse_json(text)
        if result is not None:
            return result

        # First parse failed — retry once with an even stricter prompt
        logger.debug("[LLM] JSON parse failed on first attempt — retrying with strict prompt")
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

    # ── Availability checks ────────────────────────────────────────────────────

    def _check_availability(self) -> bool:
        try:
            if self.provider == "groq":
                return self._check_groq()
            elif self.provider == "gemini":
                return self._check_gemini()
            elif self.provider == "openrouter":
                return self._check_openrouter()
            elif self.provider == "ollama":
                return self._check_ollama()
            else:
                logger.warning(f"[LLM] Unknown provider: {self.provider}")
                return False
        except httpx.ConnectError:
            logger.warning(f"[LLM] {self.provider} unreachable (connection refused)")
            return False
        except httpx.TimeoutException:
            logger.warning(f"[LLM] {self.provider} availability check timed out")
            return False
        except Exception as e:
            logger.warning(f"[LLM] Availability check failed: {e}")
            return False

    def _check_groq(self) -> bool:
        if not GROQ_API_KEY:
            logger.warning("[LLM] GROQ_API_KEY not set — get a free key at console.groq.com")
            return False
        r = httpx.get(f"{GROQ_BASE}/models",
                      headers={"Authorization": f"Bearer {GROQ_API_KEY}"}, timeout=8)
        if r.status_code != 200:
            logger.warning(f"[LLM] Groq check failed: HTTP {r.status_code}")
            return False
        models = [m["id"] for m in r.json().get("data", [])]
        found = any(self.model in m for m in models)
        if not found:
            logger.warning(f"[LLM] Groq model '{self.model}' not available. Found: {models[:5]}")
        else:
            logger.info(f"[LLM] Groq ready — {self.model}")
        return found

    def _check_gemini(self) -> bool:
        if not GEMINI_API_KEY:
            logger.warning("[LLM] GEMINI_API_KEY not set — get one free at aistudio.google.com")
            return False
        r = httpx.get(f"{GEMINI_BASE}?key={GEMINI_API_KEY}", timeout=8)
        if r.status_code == 200:
            logger.info(f"[LLM] Gemini ready — {self.model}")
            return True
        logger.warning(f"[LLM] Gemini check failed: HTTP {r.status_code}")
        return False

    def _check_openrouter(self) -> bool:
        if not OPENROUTER_API_KEY:
            logger.warning("[LLM] OPENROUTER_API_KEY not set — get one free at openrouter.ai")
            return False
        r = httpx.get(f"{OPENROUTER_BASE}/models",
                      headers={"Authorization": f"Bearer {OPENROUTER_API_KEY}"}, timeout=8)
        if r.status_code == 200:
            logger.info(f"[LLM] OpenRouter ready — {self.model}")
            return True
        logger.warning(f"[LLM] OpenRouter check failed: HTTP {r.status_code}")
        return False

    def _check_ollama(self) -> bool:
        try:
            r = httpx.get(f"{OLLAMA_BASE}/api/tags", timeout=5)
            r.raise_for_status()
            models = [m["name"] for m in r.json().get("models", [])]
        except Exception as e:
            logger.warning(f"[LLM] Ollama unreachable: {e}. Run: ollama serve")
            return False

        base_name = OLLAMA_MODEL.split(":")[0]
        found = OLLAMA_MODEL in models or any(m.startswith(base_name) for m in models)
        if not found:
            logger.warning(
                f"[LLM] Ollama model '{OLLAMA_MODEL}' not pulled. "
                f"Run: ollama pull {OLLAMA_MODEL}. Available: {models[:5]}"
            )
        else:
            logger.info(f"[LLM] Ollama ready — {OLLAMA_MODEL}")
        return found

    # ── Provider dispatch ─────────────────────────────────────────────────────

    def _dispatch_chat(self, system: str, user: str,
                       temperature: float, max_tokens: int) -> str | None:
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
        return None

    # ── Provider implementations ──────────────────────────────────────────────

    def _chat_openai_compat(self, base: str, api_key: str,
                             system: str, user: str,
                             temperature: float, max_tokens: int,
                             extra_headers: dict = None) -> str | None:
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
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
        timeout = _TIMEOUTS.get(self.provider, 30)

        def _attempt() -> str | None:
            r = httpx.post(f"{base}/chat/completions",
                           json=payload, headers=headers, timeout=timeout)
            if r.status_code == 429:
                retry_after = int(r.headers.get("retry-after", 5))
                raise _RateLimitError(retry_after)
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"].strip() or None

        return self._with_retry(_attempt)

    def _chat_gemini(self, system: str, user: str,
                     temperature: float, max_tokens: int) -> str | None:
        url     = f"{GEMINI_BASE}/{self.model}:generateContent?key={GEMINI_API_KEY}"
        payload = {
            "system_instruction": {"parts": [{"text": system}]},
            "contents":           [{"parts": [{"text": user}]}],
            "generationConfig":   {"temperature": temperature, "maxOutputTokens": max_tokens},
        }
        timeout = _TIMEOUTS.get("gemini", 30)

        def _attempt() -> str | None:
            r = httpx.post(url, json=payload, timeout=timeout)
            if r.status_code == 429:
                raise _RateLimitError(int(r.headers.get("retry-after", 10)))
            r.raise_for_status()
            return r.json()["candidates"][0]["content"]["parts"][0]["text"].strip() or None

        return self._with_retry(_attempt)

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
        timeout = _TIMEOUTS.get("ollama", 120)

        def _attempt() -> str | None:
            r = httpx.post(f"{OLLAMA_BASE}/api/chat", json=payload, timeout=timeout)
            r.raise_for_status()
            msg  = r.json().get("message", {})
            text = msg.get("content", "").strip()

            # Gemma extended-thinking fallback — extract JSON from <think> block
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

    # ── Retry / circuit breaker ───────────────────────────────────────────────

    def _with_retry(self, fn: Callable, max_attempts: int = _MAX_RETRIES) -> str | None:
        """
        Call fn() up to max_attempts times.
        Retries on: ConnectError, TimeoutException, HTTP 5xx, _RateLimitError.
        Uses exponential backoff; respects Retry-After on rate limits.
        """
        backoff = 2.0
        t0      = time.time()

        for attempt in range(1, max_attempts + 1):
            try:
                result = fn()
                logger.debug(f"[LLM] {self.provider} OK in {round(time.time()-t0,1)}s")
                return result

            except _RateLimitError as e:
                wait = e.retry_after
                logger.warning(
                    f"[LLM] 429 rate-limited — waiting {wait}s (attempt {attempt}/{max_attempts})")
                if attempt < max_attempts:
                    time.sleep(wait)

            except httpx.TimeoutException:
                logger.warning(
                    f"[LLM] Timeout on attempt {attempt}/{max_attempts} "
                    f"after {round(time.time()-t0,1)}s")
                if attempt < max_attempts:
                    time.sleep(backoff)
                    backoff *= 2

            except httpx.ConnectError as e:
                logger.warning(f"[LLM] Connection error (attempt {attempt}/{max_attempts}): {e}")
                if attempt < max_attempts:
                    time.sleep(backoff)
                    backoff *= 2

            except httpx.HTTPStatusError as e:
                status = e.response.status_code
                if status in (500, 502, 503, 504):
                    logger.warning(
                        f"[LLM] HTTP {status} (attempt {attempt}/{max_attempts}) — retrying")
                    if attempt < max_attempts:
                        time.sleep(backoff)
                        backoff *= 2
                else:
                    logger.error(f"[LLM] HTTP {status} — not retrying: {e}")
                    break

            except Exception as e:
                logger.error(f"[LLM] Unexpected error (attempt {attempt}/{max_attempts}): {e}")
                break

        logger.error(f"[LLM] All {max_attempts} attempts failed")
        self._record_failure("max retries exceeded")
        return None

    def _record_failure(self, reason: str):
        self._consecutive_fails += 1
        # Force re-check of availability on next call
        self._available    = None
        self._available_at = 0.0

        if self._consecutive_fails >= _CIRCUIT_BREAKER_THRESHOLD:
            self._circuit_open_until = time.time() + _CIRCUIT_BREAKER_COOLDOWN
            logger.warning(
                f"[LLM] Circuit OPEN after {self._consecutive_fails} consecutive failures "
                f"({reason}). Will retry in {_CIRCUIT_BREAKER_COOLDOWN}s."
            )

    # ── JSON parsing ──────────────────────────────────────────────────────────

    def _parse_json(self, text: str) -> dict | None:
        """
        Robustly extract a JSON object from LLM output.
        Handles: raw JSON, markdown fences with/without language tag,
                 leading/trailing prose, truncated responses.
        """
        text = text.strip()

        # 1. Try raw parse first (fast path — model behaved)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # 2. Strip markdown code fences (```json ... ``` or ``` ... ```)
        fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if fence_match:
            try:
                return json.loads(fence_match.group(1))
            except json.JSONDecodeError:
                pass

        # 3. Extract the largest {...} block — handles prose before/after JSON
        brace_matches = re.findall(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)?\}", text, re.DOTALL)
        for candidate in sorted(brace_matches, key=len, reverse=True):
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                continue

        # 4. Greedy: find first { and last } and try the span
        start = text.find("{")
        end   = text.rfind("}")
        if start != -1 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                pass

        logger.warning(f"[LLM] Could not parse JSON from response: {text[:200]!r}")
        return None


# ── Rate-limit sentinel ───────────────────────────────────────────────────────

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
