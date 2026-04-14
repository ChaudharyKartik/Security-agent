"""
Scan Configuration Model
Holds all auth credentials and scan settings supplied by the user.
Passed through the entire pipeline: Orchestrator → each Agent module.

Dynamic fields: the UI shows different inputs based on auth_type selection.
"""
from pydantic import BaseModel
from typing import Optional


class ScanConfig(BaseModel):
    """
    Unified scan config. All credential fields are optional.
    The agent modules consume only what's relevant to them.
    """

    # ── Auth type selector (drives dynamic UI fields) ──────────────────────
    auth_type: str = "none"
    # Options: none | basic | form | token | cookie | apikey | custom_headers

    # ── Basic / form auth ──────────────────────────────────────────────────
    username:       Optional[str] = None
    password:       Optional[str] = None
    login_url:      Optional[str] = None   # form POST target
    username_field: Optional[str] = "username"
    password_field: Optional[str] = "password"

    # ── Token auth ─────────────────────────────────────────────────────────
    auth_token:     Optional[str] = None   # Bearer / JWT
    token_header:   Optional[str] = "Authorization"
    token_prefix:   Optional[str] = "Bearer"

    # ── Cookie auth ────────────────────────────────────────────────────────
    session_cookie_name:  Optional[str] = None
    session_cookie_value: Optional[str] = None

    # ── API key auth ───────────────────────────────────────────────────────
    api_key_name:   Optional[str] = None   # header or param name
    api_key_value:  Optional[str] = None
    api_key_in:     Optional[str] = "header"  # header | query | body

    # ── Custom headers (any key:value pairs) ───────────────────────────────
    custom_headers: Optional[dict] = None   # e.g. {"X-Tenant": "acme"}

    # ── Nmap-specific ──────────────────────────────────────────────────────
    nmap_extra_args: Optional[str] = None   # e.g. "--script=auth"
    nmap_ports:      Optional[str] = None   # override default port list

    # ── ZAP-specific ───────────────────────────────────────────────────────
    zap_api_key:    Optional[str] = "changeme"
    zap_api_base:   Optional[str] = "http://localhost:8090"
    zap_context_name: Optional[str] = None  # named ZAP context for auth

    # ── Cloud-specific ─────────────────────────────────────────────────────
    aws_profile:    Optional[str] = None
    aws_region:     Optional[str] = "us-east-1"
    cloud_provider: Optional[str] = "aws"   # aws | azure | gcp

    # ── Scan behaviour ─────────────────────────────────────────────────────
    run_cloud:       bool = False
    scan_depth:      str  = "standard"   # quick | standard | deep
    follow_redirects: bool = True
    max_pages:       int  = 50
    timeout_seconds: int  = 300

    def build_auth_headers(self) -> dict:
        """Build HTTP headers dict from configured auth."""
        headers = dict(self.custom_headers or {})

        if self.auth_type == "token" and self.auth_token:
            headers[self.token_header] = f"{self.token_prefix} {self.auth_token}".strip()

        elif self.auth_type == "apikey" and self.api_key_value:
            if self.api_key_in == "header":
                headers[self.api_key_name or "X-API-Key"] = self.api_key_value

        elif self.auth_type == "cookie" and self.session_cookie_value:
            name  = self.session_cookie_name or "session"
            headers["Cookie"] = f"{name}={self.session_cookie_value}"

        elif self.auth_type == "basic" and self.username and self.password:
            import base64
            creds = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            headers["Authorization"] = f"Basic {creds}"

        return headers

    def build_auth_summary(self) -> str:
        """Human-readable summary for logging (no secrets)."""
        if self.auth_type == "none":
            return "Unauthenticated"
        if self.auth_type == "basic":
            return f"Basic auth — user: {self.username or '?'}"
        if self.auth_type == "token":
            return f"Token auth — header: {self.token_header}"
        if self.auth_type == "cookie":
            return f"Cookie auth — name: {self.session_cookie_name or 'session'}"
        if self.auth_type == "apikey":
            return f"API Key — in {self.api_key_in}: {self.api_key_name or 'X-API-Key'}"
        if self.auth_type == "form":
            return f"Form auth — login_url: {self.login_url or '?'}, user: {self.username or '?'}"
        if self.auth_type == "custom_headers":
            keys = list((self.custom_headers or {}).keys())
            return f"Custom headers: {keys}"
        return self.auth_type
