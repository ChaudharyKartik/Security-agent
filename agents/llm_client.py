"""
LLM Client — provider-agnostic interface for Gemma 4 (via Ollama).

Supports:
  - Ollama  (local, default)   LLM_PROVIDER=ollama
  - Fallback (heuristic only)  LLM_PROVIDER=none

Usage:
    from agents.llm_client import LLMClient
    client = LLMClient()
    response = client.chat(system="You are...", user="Analyse this finding...")
"""
import json
import logging
import os
import time

import httpx

logger = logging.getLogger(__name__)

# ── Configuration (override via environment variables) ──────────────────────
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "ollama").lower()
LLM_MODEL    = os.getenv("LLM_MODEL",    "gemma4:e4b")
OLLAMA_BASE  = os.getenv("OLLAMA_BASE",  "http://localhost:11434")

# Generous timeout for CPU inference — cold load ~14s + generation time
LLM_TIMEOUT  = int(os.getenv("LLM_TIMEOUT", "180"))


class LLMUnavailableError(Exception):
    """Raised when the LLM backend is unreachable or returns an error."""


class LLMClient:
    """
    Thin wrapper around the Ollama /api/chat endpoint.

    Automatically detects whether Ollama is running.
    Falls back gracefully (returns None) when unavailable so the rest
    of the pipeline continues without LLM enrichment.
    """

    def __init__(self):
        self.provider  = LLM_PROVIDER
        self.model     = LLM_MODEL
        self.base      = OLLAMA_BASE.rstrip("/")
        self._available: bool | None = None   # cached health check result

    # ── Public API ──────────────────────────────────────────────────────────

    def is_available(self) -> bool:
        """Check once if the LLM backend is reachable and the model is present."""
        if self._available is not None:
            return self._available

        if self.provider == "none":
            self._available = False
            return False

        try:
            r = httpx.get(f"{self.base}/api/tags", timeout=5)
            models = [m["name"] for m in r.json().get("models", [])]
            # Exact match first, then prefix match (handles tag variants)
            exact   = self.model in models
            prefix  = any(m.startswith(self.model.split(":")[0]) for m in models)
            self._available = exact or prefix
            if not self._available:
                logger.warning(
                    f"[LLM] Model '{self.model}' not found in Ollama. "
                    f"Available: {models}. Run: ollama pull {self.model}"
                )
            else:
                logger.info(f"[LLM] Ollama available — model: {self.model}")
        except Exception as e:
            logger.warning(f"[LLM] Ollama unreachable: {e}")
            self._available = False

        return self._available

    def chat(self, system: str, user: str,
             temperature: float = 0.2,
             max_tokens: int = None) -> str | None:
        """
        Send a chat message and return the text response.

        Args:
            system:      System prompt (role / instructions)
            user:        User message (the finding data / question)
            temperature: 0.0 = deterministic, higher = creative
            max_tokens:  Maximum tokens (None = unlimited)

        Returns:
            Response string, or None if LLM is unavailable.
            Note: For Gemma 4, may return thinking if content is empty.
        """
        if not self.is_available():
            return None

        options = {
            "temperature": temperature,
        }
        if max_tokens is not None:
            options["num_predict"] = max_tokens

        payload = {
            "model":  self.model,
            "stream": False,
            "options": options,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
        }

        t0 = time.time()
        try:
            r = httpx.post(
                f"{self.base}/api/chat",
                json=payload,
                timeout=LLM_TIMEOUT,
            )
            r.raise_for_status()
            resp_json = r.json()
            message = resp_json.get("message", {})
            text = message.get("content", "").strip()
            
            # Gemma 4 extended thinking: if content is empty but thinking exists, use thinking
            # This handles case where model uses tokens for reasoning before output
            if not text and "thinking" in message:
                thinking = message.get("thinking", "").strip()
                if thinking:
                    # Try to extract JSON from thinking (model may put JSON in thinking field)
                    import re
                    json_match = re.search(r"\{.*\}", thinking, re.DOTALL)
                    if json_match:
                        try:
                            extracted_json = json.loads(json_match.group())
                            logger.info("[LLM] Extracted JSON from thinking field (Gemma extended mode)")
                            return json.dumps(extracted_json)  # Return as JSON string
                        except Exception:
                            pass
                    
                    logger.warning(
                        f"[LLM] Content empty but thinking available. "
                        f"Using thinking field as fallback (Gemma extended mode)"
                    )
                    text = thinking[:500]  # Cap thinking output to 500 chars
            
            elapsed = round(time.time() - t0, 1)
            tokens  = len(text.split())
            logger.debug(f"[LLM] {elapsed}s | ~{tokens} tokens | model={self.model}")
            return text if text else None

        except httpx.TimeoutException:
            logger.error(f"[LLM] Request timed out after {LLM_TIMEOUT}s")
            return None
        except Exception as e:
            logger.error(f"[LLM] Chat request failed: {e}")
            return None

    def chat_json(self, system: str, user: str,
                  temperature: float = 0.1,
                  max_tokens: int = None) -> dict | None:
        """
        Like chat() but expects JSON back. Parses and returns a dict.
        Returns None if response is not valid JSON or LLM unavailable.
        """
        # For Gemma 4: suppress extended thinking, focus on JSON output
        system_json = (
            system + 
            "\n\nIMPORTANT: Do NOT think or reason. Output ONLY valid JSON. No markdown, no explanation, no text."
        )
        text = self.chat(system_json, user, temperature=temperature, max_tokens=max_tokens)
        if not text:
            return None

        # Strip markdown code fences if model adds them
        text = text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text  = "\n".join(lines[1:-1]) if len(lines) > 2 else text

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Try to extract JSON from within text
            import re
            m = re.search(r"\{.*\}", text, re.DOTALL)
            if m:
                try:
                    return json.loads(m.group())
                except Exception:
                    pass
            logger.warning(f"[LLM] Could not parse JSON response: {text[:200]}")
            return None


# Module-level singleton — import and use directly
_client: LLMClient | None = None


def get_llm() -> LLMClient:
    """Return the shared LLMClient singleton."""
    global _client
    if _client is None:
        _client = LLMClient()
    return _client
