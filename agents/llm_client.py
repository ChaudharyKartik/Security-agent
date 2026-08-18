"""
LLM Client — multi-provider, multi-key interface with automatic fallback chain.

Provider priority (first available wins):
  LLM_PROVIDER env var → fallback chain: groq → gemini → ollama

Each provider can have multiple API keys (GROQ_API_KEY_1, GROQ_API_KEY_2, ...,
falling back to a single GROQ_API_KEY if no numbered ones are set). Keys within
a provider are tried round-robin; a provider is only considered exhausted once
every one of its keys is circuit-open, rate-limit-backed-off, or at its RPM cap.

Two-tier fallback:
  Tier 1 (same provider, next key)  — cheap, same model, no compression.
  Tier 2 (provider exhausted)       — falls to the next provider in the chain.
                                       If the caller passed on_switch, it is
                                       invoked to compress `messages` in place
                                       before the next provider is tried.

Stability features:
  - Per-key rate limiter: sliding-window RPM cap prevents 429s proactively
  - Per-key circuit breaker: 3 hard failures → 5 min cooldown, then retry
  - Auth failures (401/403) open the circuit immediately — a bad key will
    never succeed on retry, so there's no reason to wait for 3 strikes
  - 429 distinction: rate-limited keys are skipped without circuit-breaking
  - Per-provider availability TTL: re-checks every 60 s, recovers automatically
  - Retry with exponential backoff: ConnectError, Timeout, 5xx all retried
  - 429 handling: respects Retry-After header before trying the next key
  - Robust JSON parsing: fences, language tags, prose wrappers, truncated output
  - chat_json retries once with stricter prompt on bad parse
  - Per-provider timeouts: Ollama 120 s, cloud APIs 30 s
"""
import collections
import json
import logging
import os
import re
import threading
import time
from typing import Callable

import httpx
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "groq").lower()

OLLAMA_BASE = os.getenv("OLLAMA_BASE", "http://localhost:11434")

GROQ_BASE   = "https://api.groq.com/openai/v1"
GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/models"


def _load_keys(prefix: str) -> list[str]:
    """
    Collect all numbered keys for a provider: PREFIX_1, PREFIX_2, ...
    Falls back to the bare PREFIX var (single-key setups) if no numbered ones exist.
    """
    keys = []
    i = 1
    while True:
        v = os.getenv(f"{prefix}_{i}")
        if not v:
            break
        keys.append(v)
        i += 1
    if not keys:
        bare = os.getenv(prefix)
        if bare:
            keys.append(bare)
    return keys


# Per-provider key pools. Ollama needs no auth — a single sentinel key keeps
# the (provider, key) bookkeeping uniform across all three providers.
_PROVIDER_KEYS: dict[str, list[str]] = {
    "groq":   _load_keys("GROQ_API_KEY"),
    "gemini": _load_keys("GEMINI_API_KEY"),
    "ollama": ["local"],
}

# Per-provider default models — each can be overridden independently
_PROVIDER_MODELS: dict[str, str] = {
    "groq":   os.getenv("GROQ_MODEL",   "openai/gpt-oss-120b"),
    "gemini": os.getenv("GEMINI_MODEL", "gemini-flash-lite-latest"),
    "ollama": os.getenv("OLLAMA_MODEL", "llama3.1:8b"),
}
# LLM_MODEL overrides all providers if set (legacy behaviour preserved)
if os.getenv("LLM_MODEL"):
    for _k in _PROVIDER_MODELS:
        _PROVIDER_MODELS[_k] = os.getenv("LLM_MODEL")

# Fallback order — primary comes first via _build_chain()
_FALLBACK_CHAIN = ["groq", "gemini", "ollama"]

# Per-provider timeouts (seconds) — each independently overridable via env var
_TIMEOUTS: dict[str, int] = {
    "groq":   int(os.getenv("GROQ_TIMEOUT",   "30")),
    "gemini": int(os.getenv("GEMINI_TIMEOUT", "30")),
    "ollama": int(os.getenv("OLLAMA_TIMEOUT", "180")),
}

_AVAILABILITY_TTL          = 60    # seconds before re-checking provider reachability
_CIRCUIT_BREAKER_THRESHOLD = 3     # consecutive failures before circuit opens
_CIRCUIT_BREAKER_COOLDOWN  = 300   # seconds before circuit closes and retries
_MAX_RETRIES               = 3     # attempts per key per call
_MAX_RETRY_WAIT            = 30    # cap on retry-after sleep — skip key if quota exhausted
_AGENT_HISTORY_KEEP        = int(os.getenv("AGENT_HISTORY", "8"))  # must match base_agent.py

# Per-provider RPM caps (requests per minute) — applied to EACH key independently.
# Set conservatively below the free-tier limit so we never hit 429 for RPM.
# Override via env vars for paid tiers (e.g. GROQ_RPM=500).
_RPM_LIMITS: dict[str, int] = {
    "groq":   int(os.getenv("GROQ_RPM",   "25")),   # free: 30 RPM per key
    "gemini": int(os.getenv("GEMINI_RPM", "12")),   # free: 15 RPM per key
    "ollama": int(os.getenv("OLLAMA_RPM", "500")),  # local — no real limit
}

# Per-provider max request size, in estimated tokens — this is a hard per-request
# ceiling (Groq's free tier caps tokens-per-minute at 8000 for some models, and
# a single large conversation can exceed that in ONE call). This is a different
# problem than RPM: no amount of key rotation fixes an oversized single request,
# since the ceiling is on the model/tier, not the key. Set conservatively below
# the real cap to leave room for the response's own max_tokens, which usually
# counts against the same budget.
_MAX_REQUEST_TOKENS: dict[str, int] = {
    "groq":   int(os.getenv("GROQ_MAX_REQUEST_TOKENS",   "6000")),
    "gemini": int(os.getenv("GEMINI_MAX_REQUEST_TOKENS", "20000")),
    "ollama": int(os.getenv("OLLAMA_MAX_REQUEST_TOKENS", "100000")),  # local — no real limit
}


def _estimate_tokens(text) -> int:
    """Cheap, dependency-free token estimate (~4 chars/token for English)."""
    return len(str(text)) // 4


class _RateLimiter:
    """
    Sliding-window rate limiter.  Thread-safe — safe for parallel agents.
    acquire() blocks the caller until a request slot is available within the window.
    has_capacity() is a non-blocking peek used by key selection.
    """

    def __init__(self, max_calls: int, window_seconds: float = 60.0):
        self.max_calls = max_calls
        self.window    = window_seconds
        self._calls    = collections.deque()
        self._lock     = threading.Lock()

    def _expire(self, now: float):
        while self._calls and now - self._calls[0] > self.window:
            self._calls.popleft()

    def has_capacity(self) -> bool:
        """Non-blocking check — is there room for one more call right now?"""
        with self._lock:
            now = time.monotonic()
            self._expire(now)
            return len(self._calls) < self.max_calls

    def acquire(self):
        while True:
            with self._lock:
                now = time.monotonic()
                self._expire(now)

                if len(self._calls) < self.max_calls:
                    self._calls.append(now)
                    return   # slot available

                # Wait until the oldest call rolls out of the window
                wait = self.window - (now - self._calls[0]) + 0.05

            time.sleep(wait)   # sleep outside the lock


class LLMClient:
    """
    Provider-agnostic, multi-key LLM client.
    Tries LLM_PROVIDER first; on failure automatically falls back through
    groq → gemini → ollama (skipping providers without keys), rotating
    through each provider's keys round-robin before moving to the next provider.
    """

    def __init__(self):
        self.provider      = LLM_PROVIDER   # primary / preferred provider
        self.model         = _PROVIDER_MODELS.get(self.provider, "unknown")
        self._provider_keys = _PROVIDER_KEYS

        # Per-(provider, key) state: circuit breaker + rate-limit backoff
        self._state: dict[tuple, dict] = {}

        # Per-(provider, key) rate limiters — shared across all threads / agents
        self._rate_limiters: dict[tuple, _RateLimiter] = {
            (provider, key): _RateLimiter(_RPM_LIMITS.get(provider, 10))
            for provider, keys in self._provider_keys.items()
            for key in keys
        }

        # Round-robin cursor per provider, protected by a lock (multiple
        # agents can request a key concurrently — web/network/cloud run
        # in parallel threads).
        self._next_key_index: dict[str, int] = {}
        self._key_index_lock = threading.Lock()

        # Per-provider reachability cache (separate from per-key state —
        # this is just "can we talk to this provider at all").
        self._reachability: dict[str, dict] = {}

        # Which (provider, key) served the most recent successful call.
        # Key is identified by its position, never the raw secret — this is
        # read by callers (e.g. BaseAgent) for logging/persistence.
        self.last_provider_key: str | None = None

        logger.info(
            f"[LLM] Primary: {self.provider} ({self.model}) | "
            f"Chain: {self._build_chain()} | "
            f"Keys: { {p: len(k) for p, k in self._provider_keys.items()} }"
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
        Send a chat request. Tries providers in chain order until one succeeds,
        rotating through each provider's keys before falling to the next provider.
        Returns the text response, or None if all providers/keys fail.
        """
        if self.provider == "none":
            return None

        for provider in self._build_chain():
            if not self._provider_available(provider):
                logger.debug(f"[LLM] Skipping {provider} (unreachable/not configured)")
                continue

            key = self.get_available_key(provider)
            if key is None:
                logger.info(f"[LLM] {provider} — every key circuit-open/rate-limited, falling back")
                continue

            pk = (provider, key)
            try:
                result = self._try_provider(provider, key, system, user, temperature, max_tokens)
            except _AuthError as e:
                self._record_failure(pk, f"auth failure (HTTP {e.status_code})", immediate=True)
                continue
            except _ProviderRateLimited:
                self._rate_limit_backoff(pk)
                continue

            if result:
                self._reset_fails(pk)
                self.last_provider_key = self._label_key(provider, key)
                if provider != self.provider:
                    logger.info(f"[LLM] Fallback succeeded via {provider}")
                return result

            self._record_failure(pk, "returned None after retries")

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

    def chat_with_tools(
        self,
        system:      str,
        messages:    list,
        tools:       list,
        temperature: float = 0.2,
        max_tokens:  int   = 1024,
        on_switch:   Callable = None,
    ) -> dict:
        """
        Multi-turn chat with tool schemas. Used by BaseAgent's ReAct loop.

        `on_switch`, if given, is called with no arguments right before falling
        back to the next provider (i.e. when the current provider's keys are
        all exhausted). It must return a synthetic summary message (same shape
        as base_agent._build_trim_summary's output); `messages` is then
        compacted in place — [messages[0], summary] + last _AGENT_HISTORY_KEEP —
        so the new provider picks up a short history instead of the full one.

        Returns one of:
          {"type": "tool_call", "tool": "name", "args": {...}, "thinking": "..."}
          {"type": "done",      "content": "..."}
          {"type": "message",   "content": "..."}
        """
        if self.provider == "none":
            return {"type": "done", "content": "LLM provider disabled"}

        for provider in self._build_chain():
            if not self._provider_available(provider):
                logger.debug(f"[LLM] Skipping {provider} (unreachable/not configured)")
                continue

            key = self.get_available_key(provider)
            if key is None:
                logger.info(f"[LLM] {provider} — every key circuit-open/rate-limited, falling back")
                if on_switch:
                    self._compress_on_switch(messages, on_switch)
                continue

            # Proactive size check — a conversation that's grown too large for
            # THIS provider's per-request token budget will 413 no matter which
            # key serves it (it's a model/tier ceiling, not a quota issue), so
            # rotating keys or waiting doesn't help. Compress before sending
            # instead of after the guaranteed failure.
            if on_switch:
                estimated = self._estimate_request_tokens(system, messages, tools)
                limit = _MAX_REQUEST_TOKENS.get(provider, 10**9)
                if estimated > limit:
                    logger.info(
                        f"[LLM] Estimated request size (~{estimated} tokens) exceeds "
                        f"{provider}'s per-request budget (~{limit}) — compressing before send"
                    )
                    self._compress_on_switch(messages, on_switch)

            pk = (provider, key)
            try:
                result = self._try_provider_tools(
                    provider, key, system, messages, tools, temperature, max_tokens
                )
            except _AuthError as e:
                self._record_failure(pk, f"auth failure (HTTP {e.status_code})", immediate=True)
                continue
            except _ProviderRateLimited:
                self._rate_limit_backoff(pk)
                continue

            if result:
                self._reset_fails(pk)
                self.last_provider_key = self._label_key(provider, key)
                if provider != self.provider:
                    logger.info(f"[LLM] Fallback tools succeeded via {provider}")
                return result

            self._record_failure(pk, "chat_with_tools returned None")

        logger.error("[LLM] chat_with_tools: all providers exhausted")
        return {"type": "done", "content": "All LLM providers failed"}

    @staticmethod
    def _compress_on_switch(messages: list, on_switch: Callable):
        """Run the caller's compression callback and splice the result into
        `messages` in place, so both this retry and the caller's own copy see it."""
        try:
            summary = on_switch()
        except Exception as e:
            logger.warning(f"[LLM] on_switch callback raised: {e}")
            return
        if not summary:
            return
        if len(messages) > _AGENT_HISTORY_KEEP + 1:
            messages[:] = [messages[0], summary] + messages[-_AGENT_HISTORY_KEEP:]
        else:
            messages[:] = [messages[0], summary] + messages[1:]

    @staticmethod
    def _estimate_request_tokens(system: str, messages: list, tools: list) -> int:
        """Cheap upper-bound estimate of the outgoing request's token size —
        system prompt + full message history + tool schemas."""
        total = _estimate_tokens(system) + _estimate_tokens(tools)
        for m in messages:
            total += _estimate_tokens(m.get("content") or "")
            if m.get("tool_calls"):
                total += _estimate_tokens(m["tool_calls"])
        return total

    # ── Key selection ──────────────────────────────────────────────────────────

    def get_available_key(self, provider: str) -> str | None:
        """
        Round-robin across this provider's keys.

        Prefers a key with immediate RPM headroom. If none have a free slot
        right now but at least one is otherwise healthy (not circuit-open,
        not rate-limit-backed-off), that key is returned anyway — the caller's
        acquire() will briefly wait for a slot, same as the old single-key
        behaviour. An RPM window being momentarily full under concurrent
        agents is normal and must NOT be treated as the provider failing.

        Returns None only when EVERY key is hard-failed (circuit-open or
        rate-limit-backed-off from a real error) — that's the actual signal
        that this provider is exhausted and the chain should fall back.
        """
        keys = self._provider_keys.get(provider, [])
        if not keys:
            return None

        with self._key_index_lock:
            start = self._next_key_index.get(provider, 0) % len(keys)
            self._next_key_index[provider] = (start + 1) % len(keys)

        now = time.time()
        healthy_but_busy = None   # first healthy key with no free slot right now

        for offset in range(len(keys)):
            idx = (start + offset) % len(keys)
            key = keys[idx]
            pk  = (provider, key)
            st  = self._get_state(pk)

            if st["circuit_open_until"] > now:
                continue
            if st["rate_limited_until"] > now:
                continue

            if self._rate_limiters[pk].has_capacity():
                return key   # best case — immediate slot, no waiting

            if healthy_but_busy is None:
                healthy_but_busy = key

        return healthy_but_busy   # None only if every key is hard-failed

    # ── Chain helpers ──────────────────────────────────────────────────────────

    def _build_chain(self) -> list[str]:
        """Primary provider first, then the rest of the fallback chain."""
        chain = [self.provider]
        for p in _FALLBACK_CHAIN:
            if p != self.provider:
                chain.append(p)
        return chain

    def _label_key(self, provider: str, key: str) -> str:
        """Human-readable, secret-free label for logging/persistence — e.g. 'groq:key_2'."""
        keys = self._provider_keys.get(provider, [])
        idx  = keys.index(key) + 1 if key in keys else "?"
        return f"{provider}:key_{idx}"

    def _get_state(self, pk: tuple) -> dict:
        if pk not in self._state:
            self._state[pk] = {
                "consecutive_fails":  0,
                "circuit_open_until": 0.0,
                "rate_limited_until": 0.0,
            }
        return self._state[pk]

    def _get_reachability(self, provider: str) -> dict:
        if provider not in self._reachability:
            self._reachability[provider] = {"reachable": None, "checked_at": 0.0}
        return self._reachability[provider]

    def _provider_available(self, provider: str) -> bool:
        """Is this provider configured and reachable? (Not key-specific —
        see get_available_key() for per-key quota/circuit state.)"""
        if provider == "none":
            return False
        if not self._provider_keys.get(provider):
            return False

        st  = self._get_reachability(provider)
        now = time.time()
        if st["reachable"] is None or (now - st["checked_at"]) > _AVAILABILITY_TTL:
            st["reachable"]  = self._check_provider(provider)
            st["checked_at"] = now

        return bool(st["reachable"])

    def _reset_fails(self, pk: tuple):
        st = self._get_state(pk)
        st["consecutive_fails"]  = 0
        st["circuit_open_until"] = 0.0
        st["rate_limited_until"] = 0.0

    def _rate_limit_backoff(self, pk: tuple, duration: int = 300):
        """Back off a quota-exhausted key for `duration` seconds (default 5 min)."""
        st = self._get_state(pk)
        st["rate_limited_until"] = time.time() + duration
        logger.warning(f"[LLM] {pk} quota exhausted — backing off for {duration}s")

    def _record_failure(self, pk: tuple, reason: str = "", immediate: bool = False):
        """
        Record a failure for one key. `immediate=True` opens the circuit right
        away (used for auth failures — a bad key will never succeed on retry,
        so there's no point waiting for the normal 3-strike threshold).
        """
        st = self._get_state(pk)
        st["consecutive_fails"] += 1

        if immediate or st["consecutive_fails"] >= _CIRCUIT_BREAKER_THRESHOLD:
            st["circuit_open_until"] = time.time() + _CIRCUIT_BREAKER_COOLDOWN
            logger.warning(
                f"[LLM] Circuit OPEN for {pk} after "
                f"{st['consecutive_fails']} failure(s) ({reason}). "
                f"Cooldown {_CIRCUIT_BREAKER_COOLDOWN}s."
            )

    # ── Availability checks ────────────────────────────────────────────────────

    def _check_provider(self, provider: str) -> bool:
        try:
            if provider == "groq":   return self._check_groq()
            if provider == "gemini": return self._check_gemini()
            if provider == "ollama": return self._check_ollama()
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
        """
        Reachable if ANY configured key works — not just the first one. A single
        bad/revoked key must never write off the whole provider when its
        siblings are fine; that previously left every other key idle for a
        full scan because this check only ever tested keys[0].
        """
        keys = self._provider_keys.get("groq", [])
        if not keys:
            logger.debug("[LLM] No Groq keys configured — skipping Groq")
            return False
        model = _PROVIDER_MODELS["groq"]
        last_status = None
        for key in keys:
            try:
                r = httpx.get(f"{GROQ_BASE}/models",
                              headers={"Authorization": f"Bearer {key}"}, timeout=8)
            except httpx.HTTPError as e:
                last_status = str(e)
                continue
            last_status = r.status_code
            if r.status_code != 200:
                continue
            models = [m["id"] for m in r.json().get("data", [])]
            if any(model in m for m in models):
                logger.info(f"[LLM] Groq ready — {model} ({len(keys)} key(s))")
                return True
        logger.warning(f"[LLM] Groq unreachable on all {len(keys)} key(s) "
                        f"(last: {last_status}) or model '{model}' unavailable")
        return False

    def _check_gemini(self) -> bool:
        """Reachable if ANY configured key works — see _check_groq() for why."""
        keys = self._provider_keys.get("gemini", [])
        if not keys:
            logger.debug("[LLM] No Gemini keys configured — skipping Gemini")
            return False
        last_status = None
        for key in keys:
            try:
                r = httpx.get(f"{GEMINI_BASE}?key={key}", timeout=8)
            except httpx.HTTPError as e:
                last_status = str(e)
                continue
            last_status = r.status_code
            if r.status_code == 200:
                logger.info(f"[LLM] Gemini ready — {_PROVIDER_MODELS['gemini']} ({len(keys)} key(s))")
                return True
        logger.warning(f"[LLM] Gemini unreachable on all {len(keys)} key(s) (last: {last_status})")
        return False

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

    def _try_provider(self, provider: str, key: str, system: str, user: str,
                      temperature: float, max_tokens: int) -> str | None:
        self._rate_limiters[(provider, key)].acquire()   # throttle to stay under RPM cap
        model = _PROVIDER_MODELS.get(provider, "unknown")
        try:
            if provider == "groq":
                return self._chat_openai_compat(
                    GROQ_BASE, key, model,
                    system, user, temperature, max_tokens)

            if provider == "gemini":
                return self._chat_gemini(
                    model, key, system, user, temperature, max_tokens)

            if provider == "ollama":
                return self._chat_ollama(
                    model, system, user, temperature, max_tokens)

        except (_ProviderRateLimited, _AuthError):
            raise   # propagate — caller decides how to record it
        except Exception as e:
            logger.warning(f"[LLM] {provider} dispatch error: {e}")
        return None

    def _try_provider_tools(
        self,
        provider:    str,
        key:         str,
        system:      str,
        messages:    list,
        tools:       list,
        temperature: float,
        max_tokens:  int,
    ) -> dict | None:
        self._rate_limiters[(provider, key)].acquire()   # throttle to stay under RPM cap
        model = _PROVIDER_MODELS.get(provider, "unknown")
        try:
            if provider == "groq":
                return self._chat_openai_compat_tools(
                    GROQ_BASE, key, model,
                    system, messages, tools, temperature, max_tokens)

            if provider == "gemini":
                return self._chat_gemini_tools(
                    model, key, system, messages, tools, temperature, max_tokens)

            if provider == "ollama":
                return self._chat_ollama_tools(
                    model, system, messages, tools, temperature, max_tokens)

        except (_ProviderRateLimited, _AuthError):
            raise   # propagate — caller decides how to record it
        except Exception as e:
            logger.warning(f"[LLM] {provider} tools dispatch error: {e}")
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
        pname   = "groq"
        timeout = _TIMEOUTS.get(pname, 30)

        def _attempt() -> str | None:
            r = httpx.post(f"{base}/chat/completions",
                           json=payload, headers=headers, timeout=timeout)
            if r.status_code == 429:
                try:
                    _ra = int(r.headers.get("retry-after", 5))
                except (ValueError, TypeError):
                    _ra = 5
                raise _RateLimitError(_ra)
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"].strip() or None

        return self._with_retry(_attempt)

    def _chat_gemini(self, model: str, api_key: str, system: str, user: str,
                     temperature: float, max_tokens: int) -> str | None:
        url     = f"{GEMINI_BASE}/{model}:generateContent?key={api_key}"
        payload = {
            "system_instruction": {"parts": [{"text": system}]},
            "contents":           [{"parts": [{"text": user}]}],
            "generationConfig":   {"temperature": temperature, "maxOutputTokens": max_tokens},
        }

        def _attempt() -> str | None:
            r = httpx.post(url, json=payload, timeout=_TIMEOUTS["gemini"])
            if r.status_code == 429:
                try:
                    _ra = int(r.headers.get("retry-after", 10))
                except (ValueError, TypeError):
                    _ra = 10
                raise _RateLimitError(_ra)
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

    # ── Tool-calling provider implementations ─────────────────────────────────

    def _chat_openai_compat_tools(
        self, base: str, api_key: str, model: str,
        system: str, messages: list, tools: list,
        temperature: float, max_tokens: int,
        extra_headers: dict = None,
    ) -> dict | None:
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        if extra_headers:
            headers.update(extra_headers)

        payload = {
            "model":       model,
            "messages":    [{"role": "system", "content": system}] + messages,
            "tools":       [{"type": "function", "function": t} for t in tools],
            "tool_choice": "auto",
            "temperature": temperature,
            "max_tokens":  max_tokens,
        }
        pname   = "groq"
        timeout = _TIMEOUTS.get(pname, 30)

        def _attempt() -> dict | None:
            r = httpx.post(f"{base}/chat/completions",
                           json=payload, headers=headers, timeout=timeout)
            if r.status_code == 429:
                try:
                    _ra = int(r.headers.get("retry-after", 5))
                except (ValueError, TypeError):
                    _ra = 5
                raise _RateLimitError(_ra)
            r.raise_for_status()
            return _parse_openai_tool_response(r.json())

        return self._with_retry(_attempt)

    def _chat_gemini_tools(
        self, model: str, api_key: str,
        system: str, messages: list, tools: list,
        temperature: float, max_tokens: int,
    ) -> dict | None:
        url = f"{GEMINI_BASE}/{model}:generateContent?key={api_key}"

        # Convert messages to Gemini role format. Historical tool-call turns are
        # flattened to plain text rather than reconstructed as structured
        # functionCall/functionResponse parts. Gemini's newer models require a
        # thoughtSignature on every functionCall part, which is opaque metadata
        # we have no way to carry through our provider-agnostic message history —
        # a turn produced by Groq or Ollama has no such signature to echo back,
        # and sending one back without it gets rejected with HTTP 400. Only
        # Gemini's own live response for the CURRENT turn needs the structured
        # format, and that's handled entirely by the API itself, not by us
        # re-encoding history. Same flattening approach _normalise_messages_for_prompt()
        # already uses for Ollama's prompt-fallback mode, for the same reason.
        contents = []
        for m in messages:
            if m["role"] == "assistant":
                if m.get("tool_calls"):
                    tc = m["tool_calls"][0]
                    fn = tc["function"]
                    text = f"[Called tool `{fn['name']}` with args: {fn.get('arguments', '{}')}]"
                    if m.get("content"):
                        text = f"{m['content']}\n{text}"
                    contents.append({"role": "model", "parts": [{"text": text}]})
                else:
                    contents.append({"role": "model", "parts": [{"text": m.get("content") or ""}]})
            elif m["role"] == "tool":
                text = f"[Tool `{m.get('name', 'tool')}` result: {m.get('content', '')}]"
                contents.append({"role": "user", "parts": [{"text": text}]})
            else:
                contents.append({"role": "user", "parts": [{"text": m.get("content") or ""}]})

        payload = {
            "system_instruction": {"parts": [{"text": system}]},
            "contents":           contents,
            "tools":              [{"function_declarations": tools}],
            "generationConfig":   {
                "temperature":    temperature,
                "maxOutputTokens": max_tokens,
            },
        }

        def _attempt() -> dict | None:
            r = httpx.post(url, json=payload, timeout=_TIMEOUTS["gemini"])
            if r.status_code == 429:
                try:
                    _ra = int(r.headers.get("retry-after", 10))
                except (ValueError, TypeError):
                    _ra = 10
                raise _RateLimitError(_ra)
            r.raise_for_status()
            return _parse_gemini_tool_response(r.json())

        return self._with_retry(_attempt)

    def _chat_ollama_tools(
        self, model: str,
        system: str, messages: list, tools: list,
        temperature: float, max_tokens: int,
    ) -> dict | None:
        # Try native tool calling via Ollama's OpenAI-compat endpoint first
        # (supported by llama3.1+, mistral-nemo, qwen2.5, etc.)
        try:
            payload = {
                "model":    model,
                "messages": [{"role": "system", "content": system}] + messages,
                "tools":    [{"type": "function", "function": t} for t in tools],
                "stream":   False,
                "options":  {"temperature": temperature, "num_predict": max_tokens},
            }

            def _native_attempt() -> dict | None:
                r = httpx.post(f"{OLLAMA_BASE}/v1/chat/completions",
                               json=payload, timeout=_TIMEOUTS["ollama"])
                r.raise_for_status()
                return _parse_openai_tool_response(r.json())

            result = self._with_retry(_native_attempt)
            if result and result.get("type") in ("tool_call", "done"):
                return result
        except Exception as e:
            logger.debug(f"[LLM] Ollama native tool calling unavailable ({e}), using prompt fallback")

        # Prompt-based fallback: inject tool schemas into system prompt
        return self._chat_prompt_tools(model, system, messages, tools, temperature, max_tokens)

    def _chat_prompt_tools(
        self, model: str,
        system: str, messages: list, tools: list,
        temperature: float, max_tokens: int,
    ) -> dict | None:
        enhanced_system = system + "\n\n" + _build_tool_prompt(tools)

        payload = {
            "model":   model,
            "stream":  False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
            "messages": [{"role": "system", "content": enhanced_system}] + _normalise_messages_for_prompt(messages),
        }

        def _attempt() -> dict | None:
            r = httpx.post(f"{OLLAMA_BASE}/api/chat",
                           json=payload, timeout=_TIMEOUTS["ollama"])
            r.raise_for_status()
            msg  = r.json().get("message", {})
            text = msg.get("content", "").strip()
            # Gemma extended-thinking fallback
            if not text and msg.get("thinking"):
                text = msg["thinking"].strip()
            if not text:
                return None
            parsed = _try_parse_tool_json(text)
            return parsed or {"type": "message", "content": text}

        return self._with_retry(_attempt)

    # ── Retry logic ────────────────────────────────────────────────────────────

    def _with_retry(self, fn: Callable, max_attempts: int = _MAX_RETRIES) -> str | None:
        """
        Retry fn up to max_attempts times with backoff.
        Raises _ProviderRateLimited if ALL failures were 429s — the caller
        must NOT circuit-break in that case; the key is fine, just busy.
        Raises _AuthError immediately on 401/403 — a bad key will never
        succeed on retry, so there's no point burning attempts on it.
        Returns None for genuine hard failures (connect error, 5xx, etc.).
        """
        backoff          = 2.0
        t0               = time.time()
        only_rate_limited = True   # flip to False on any non-429 failure

        for attempt in range(1, max_attempts + 1):
            try:
                result = fn()
                logger.debug(f"[LLM] OK in {round(time.time()-t0,1)}s")
                return result

            except _RateLimitError as e:
                if e.retry_after > _MAX_RETRY_WAIT:
                    logger.warning(
                        f"[LLM] 429 retry-after={e.retry_after}s exceeds cap "
                        f"({_MAX_RETRY_WAIT}s) — skipping key"
                    )
                    break
                logger.warning(f"[LLM] 429 — waiting {e.retry_after}s (attempt {attempt}/{max_attempts})")
                if attempt < max_attempts:
                    time.sleep(e.retry_after)

            except httpx.TimeoutException:
                only_rate_limited = False
                logger.warning(f"[LLM] Timeout attempt {attempt}/{max_attempts} ({round(time.time()-t0,1)}s)")
                if attempt < max_attempts:
                    time.sleep(backoff); backoff *= 2

            except httpx.ConnectError as e:
                only_rate_limited = False
                logger.warning(f"[LLM] ConnectError attempt {attempt}/{max_attempts}: {e}")
                if attempt < max_attempts:
                    time.sleep(backoff); backoff *= 2

            except httpx.HTTPStatusError as e:
                only_rate_limited = False
                code = e.response.status_code
                if code in (500, 502, 503, 504):
                    logger.warning(f"[LLM] HTTP {code} attempt {attempt}/{max_attempts}")
                    if attempt < max_attempts:
                        time.sleep(backoff); backoff *= 2
                elif code in (401, 403):
                    logger.error(f"[LLM] HTTP {code} — invalid/revoked key, not retrying")
                    raise _AuthError(code)
                else:
                    body = ""
                    try:
                        body = e.response.text[:300]
                    except Exception:
                        pass
                    logger.error(f"[LLM] HTTP {code} — not retrying. Body: {body}")
                    break

            except Exception as e:
                only_rate_limited = False
                logger.error(f"[LLM] Unexpected error attempt {attempt}/{max_attempts}: {e}")
                break

        if only_rate_limited:
            raise _ProviderRateLimited()
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


# ── Message format helpers ────────────────────────────────────────────────────

def _normalise_messages_for_prompt(messages: list) -> list:
    """
    Convert OpenAI tool_calls format to plain text for prompt-based tool calling.
    Used by _chat_prompt_tools where there is no native tool call API.
    """
    out = []
    for m in messages:
        if m.get("tool_calls"):
            tc = m["tool_calls"][0]
            fn = tc["function"]
            try:
                args = json.loads(fn["arguments"])
            except (json.JSONDecodeError, TypeError):
                args = {}
            out.append({
                "role":    "assistant",
                "content": json.dumps({"type": "tool_call", "tool": fn["name"], "args": args}),
            })
        elif m["role"] == "tool":
            out.append({"role": "user", "content": f"Tool result:\n{m.get('content', '')}"})
        else:
            out.append(m)
    return out


# ── Tool-response parsers (module-level, no self) ─────────────────────────────

def _parse_openai_tool_response(data: dict) -> dict:
    """Parse an OpenAI-compat chat/completions response that may contain tool_calls."""
    msg = data["choices"][0]["message"]

    if msg.get("tool_calls"):
        tc   = msg["tool_calls"][0]
        fn   = tc["function"]
        try:
            args = json.loads(fn["arguments"])
        except (json.JSONDecodeError, KeyError):
            args = {}
        return {
            "type":     "tool_call",
            "tool":     fn.get("name", ""),
            "args":     args,
            "thinking": msg.get("content") or "",
        }

    content = (msg.get("content") or "").strip()
    parsed  = _try_parse_tool_json(content)
    if parsed:
        return parsed
    return {"type": "message", "content": content}


def _parse_gemini_tool_response(data: dict) -> dict:
    """Parse a Gemini generateContent response that may contain a functionCall."""
    try:
        parts = data["candidates"][0]["content"]["parts"]
    except (KeyError, IndexError):
        return {"type": "done", "content": ""}

    for part in parts:
        if "functionCall" in part:
            fc = part["functionCall"]
            return {
                "type":     "tool_call",
                "tool":     fc.get("name", ""),
                "args":     fc.get("args", {}),
                "thinking": "",
            }

    text   = " ".join(p.get("text", "") for p in parts).strip()
    parsed = _try_parse_tool_json(text)
    if parsed:
        return parsed
    return {"type": "message", "content": text}


def _try_parse_tool_json(text: str) -> dict | None:
    """
    Extract a tool-call/done/message JSON from text.
    Used as a secondary check when the LLM embeds JSON in a text response.
    """
    if not text:
        return None

    # Fast path — clean JSON
    try:
        d = json.loads(text)
        if isinstance(d, dict) and d.get("type") in ("tool_call", "done", "message"):
            return d
    except json.JSONDecodeError:
        pass

    # Inside a markdown fence
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence:
        try:
            d = json.loads(fence.group(1))
            if isinstance(d, dict) and d.get("type") in ("tool_call", "done", "message"):
                return d
        except json.JSONDecodeError:
            pass

    # Embedded JSON block containing a "type" key
    m = re.search(r'\{[^{}]*"type"\s*:\s*"(?:tool_call|done|message)"[^{}]*\}',
                  text, re.DOTALL)
    if m:
        try:
            d = json.loads(m.group())
            if isinstance(d, dict) and d.get("type") in ("tool_call", "done", "message"):
                return d
        except json.JSONDecodeError:
            pass

    return None


def _build_tool_prompt(tools: list) -> str:
    """
    Inject tool schemas into the system prompt for providers without native
    tool calling support. The LLM is instructed to output JSON responses only.
    """
    schemas = json.dumps(tools, indent=2)
    return (
        "TOOL CALLING INSTRUCTIONS:\n"
        "You have access to the following tools. When you want to call a tool, "
        "respond with ONLY this JSON (no other text before or after it):\n"
        '{"type": "tool_call", "tool": "<tool_name>", '
        '"args": {<args as JSON object>}, "thinking": "<one sentence reason>"}\n\n'
        "When you have completed all tasks and have nothing more to investigate, "
        "respond with ONLY this JSON:\n"
        '{"type": "done", "content": "<brief summary of what was found>"}\n\n'
        "Do NOT wrap your response in markdown code fences.\n"
        "Do NOT add any text before or after the JSON.\n\n"
        f"Available tools:\n{schemas}"
    )


# ── Rate-limit / auth exceptions ────────────────────────────────────────────────

class _RateLimitError(Exception):
    """Raised inside _attempt() to signal a 429 with a retry-after value."""
    def __init__(self, retry_after: int = 5):
        self.retry_after = retry_after


class _ProviderRateLimited(Exception):
    """Raised by _with_retry when ALL retries were 429s.
    The key is working fine — callers must NOT record this as a failure
    or open the circuit breaker."""
    pass


class _AuthError(Exception):
    """Raised by _with_retry on 401/403 — the key is invalid/revoked.
    This will never succeed on retry, so callers open the circuit immediately
    instead of waiting for the normal 3-strike threshold."""
    def __init__(self, status_code: int):
        self.status_code = status_code


# ── Singleton ─────────────────────────────────────────────────────────────────
_client: LLMClient | None = None


def get_llm() -> LLMClient:
    global _client
    if _client is None:
        _client = LLMClient()
    return _client
