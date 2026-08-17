"""
http_tool — HTTP request tool for LLM-driven agents.

Scope enforcement is Python-level: if a scope is set, the request URL must
share the same hostname (or be a subdomain of the scope target). The LLM
cannot override this guardrail via prompting.
"""
import time
import logging
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT  = 15        # seconds
_MAX_BODY_BYTES   = 50_000    # truncate large responses before returning to LLM
_ALLOWED_METHODS  = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}
_SAFE_SCHEMES     = {"http", "https"}


def http_request(
    method:       str,
    url:          str,
    headers:      dict = None,
    body:         str  = None,
    timeout:      int  = _DEFAULT_TIMEOUT,
    scope:        str  = None,
    auth_headers: dict = None,
) -> dict:
    """
    Make an HTTP request and return status, headers, and body.

    `auth_headers` is not part of the LLM-visible schema — it's injected by
    BaseAgent._execute_tool() from the agent's configured scan auth, the same
    way `scope` is. The LLM never sees or controls it; it exists purely so the
    agent's requests carry the user's configured authentication automatically.
    """
    method = method.upper()

    # Coerce headers to dict — Ollama sometimes passes a string repr
    if isinstance(headers, str):
        import ast
        try:
            headers = ast.literal_eval(headers)
        except Exception:
            headers = {}
    if not isinstance(headers, dict):
        headers = {}

    # ── Validation ─────────────────────────────────────────────────────────────
    if method not in _ALLOWED_METHODS:
        return {"error": f"Method '{method}' not allowed. Use: {_ALLOWED_METHODS}"}

    parsed = urlparse(url)
    if parsed.scheme not in _SAFE_SCHEMES:
        return {"error": f"Scheme '{parsed.scheme}' not allowed. Use http or https."}

    if not parsed.netloc:
        return {"error": f"Invalid URL — no host: {url}"}

    # ── Scope enforcement (Python guardrail — not prompt-level) ────────────────
    if scope:
        scope_host = urlparse(scope).netloc or scope
        req_host   = parsed.netloc.split(":")[0]   # strip port
        scope_host = scope_host.split(":")[0]
        # Allow exact match or subdomain
        if req_host != scope_host and not req_host.endswith("." + scope_host):
            logger.warning(f"[HTTP] Out-of-scope blocked: {url} (scope={scope})")
            return {
                "error": f"Out-of-scope: '{req_host}' is not within scope '{scope_host}'. "
                         "Only request URLs within the authorised target scope."
            }

    # ── Request ────────────────────────────────────────────────────────────────
    # Configured scan auth is applied first, then the LLM's own headers layer on
    # top — so a request is authenticated by default, but the agent can still
    # deliberately override a specific header (e.g. to test unauthenticated access).
    hdrs = {
        "User-Agent": "SecurityAgent/1.0",
        **(auth_headers or {}),
        **(headers or {}),
    }

    start = time.monotonic()
    try:
        with httpx.Client(verify=False, follow_redirects=True,
                          timeout=timeout) as client:
            resp = client.request(
                method  = method,
                url     = url,
                headers = hdrs,
                content = body.encode() if body else None,
            )
        elapsed = round((time.monotonic() - start) * 1000)

        raw_body = resp.content[:_MAX_BODY_BYTES].decode("utf-8", errors="replace")
        truncated = len(resp.content) > _MAX_BODY_BYTES

        return {
            "status_code":   resp.status_code,
            "headers":       dict(resp.headers),
            "body":          raw_body,
            "body_truncated": truncated,
            "elapsed_ms":    elapsed,
            "final_url":     str(resp.url),
            "error":         None,
        }

    except httpx.TimeoutException:
        return {"error": f"Request timed out after {timeout}s", "url": url}
    except httpx.RequestError as e:
        return {"error": f"Request failed: {e}", "url": url}
    except Exception as e:
        logger.error(f"[HTTP] Unexpected error for {url}: {e}", exc_info=True)
        return {"error": f"Unexpected error: {e}", "url": url}


http_request.__schema__ = {
    "name": "http_request",
    "description": (
        "Make an HTTP request to a URL within scope. Returns status code, "
        "response headers, and body. Use this to probe endpoints, check headers, "
        "test payloads, and observe server behaviour."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "method": {
                "type": "string",
                "enum": list(_ALLOWED_METHODS),
                "description": "HTTP method.",
            },
            "url": {
                "type": "string",
                "description": "Full URL to request (must be within scope).",
            },
            "headers": {
                "type": "object",
                "description": "Optional request headers as key-value pairs.",
            },
            "body": {
                "type": "string",
                "description": "Optional request body (for POST/PUT).",
            },
            "timeout": {
                "type": "integer",
                "description": "Request timeout in seconds (default 15).",
                "default": _DEFAULT_TIMEOUT,
            },
        },
        "required": ["method", "url"],
    },
}
