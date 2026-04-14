"""
Web Agent
Runs OWASP ZAP baseline scan via the ZAP Python API when available.
Falls back to an active HTTP-based probe (headers, cookies, forms,
common misconfigurations) for environments without ZAP installed.
"""
import logging
import re
import time
from datetime import datetime
from urllib.parse import urlparse, urljoin

import httpx

logger = logging.getLogger(__name__)

ZAP_API_BASE = "http://localhost:8090"
ZAP_API_KEY  = "changeme"          # match your ZAP daemon --apikey value

SECURITY_HEADERS = {
    "strict-transport-security":   ("HSTS Not Enforced",          "Medium"),
    "content-security-policy":     ("Content-Security-Policy Missing", "Medium"),
    "x-frame-options":             ("Clickjacking Protection Missing",  "Low"),
    "x-content-type-options":      ("MIME Sniffing Not Disabled",  "Low"),
    "referrer-policy":             ("Referrer Policy Missing",     "Low"),
    "permissions-policy":          ("Permissions Policy Missing",  "Low"),
    "cross-origin-opener-policy":  ("COOP Header Missing",         "Info"),
    "cross-origin-resource-policy":("CORP Header Missing",         "Info"),
}


def run_web_scan(target: str) -> dict:
    logger.info(f"[WEB] Starting web scan on: {target}")
    start = datetime.utcnow()

    url = target if target.startswith("http") else f"http://{target}"
    findings = []

    # Try ZAP first, fall back to built-in probes
    zap_result = _try_zap_scan(url)
    if zap_result:
        logger.info(f"[WEB] ZAP scan returned {len(zap_result)} alerts")
        findings.extend(zap_result)
    else:
        logger.info("[WEB] ZAP unavailable — running built-in HTTP probes")
        findings.extend(_probe_target(url))

    result = {
        "module": "web",
        "target": target,
        "scan_time": (datetime.utcnow() - start).total_seconds(),
        "findings": findings,
    }
    logger.info(f"[WEB] Done. Findings: {len(findings)}")
    return result


# ── ZAP integration ───────────────────────────────────────────────────────────

def _try_zap_scan(url: str) -> list | None:
    """
    Attempt to use a running ZAP daemon.
    Returns list of findings or None if ZAP is not available.
    """
    try:
        # Check ZAP is alive
        r = httpx.get(f"{ZAP_API_BASE}/JSON/core/view/version/",
                      params={"apikey": ZAP_API_KEY}, timeout=4)
        if r.status_code != 200:
            return None

        # Spider
        logger.info("[WEB] ZAP spider starting...")
        httpx.get(f"{ZAP_API_BASE}/JSON/spider/action/scan/",
                  params={"apikey": ZAP_API_KEY, "url": url, "maxChildren": 5}, timeout=10)
        _wait_for_zap_task("spider", url)

        # Passive + active scan
        logger.info("[WEB] ZAP active scan starting...")
        httpx.get(f"{ZAP_API_BASE}/JSON/ascan/action/scan/",
                  params={"apikey": ZAP_API_KEY, "url": url, "recurse": "true"}, timeout=10)
        _wait_for_zap_task("ascan", url)

        # Fetch alerts
        alerts_r = httpx.get(f"{ZAP_API_BASE}/JSON/core/view/alerts/",
                             params={"apikey": ZAP_API_KEY, "baseurl": url}, timeout=10)
        raw_alerts = alerts_r.json().get("alerts", [])
        return [_zap_alert_to_finding(a) for a in raw_alerts]

    except (httpx.RequestError, Exception):
        return None


def _wait_for_zap_task(task: str, url: str, timeout: int = 120):
    endpoint_map = {
        "spider": f"{ZAP_API_BASE}/JSON/spider/view/status/",
        "ascan":  f"{ZAP_API_BASE}/JSON/ascan/view/status/",
    }
    for _ in range(timeout // 3):
        try:
            r = httpx.get(endpoint_map[task],
                          params={"apikey": ZAP_API_KEY, "url": url}, timeout=5)
            progress = int(r.json().get("status", 0))
            if progress >= 100:
                return
        except Exception:
            return
        time.sleep(3)


def _zap_alert_to_finding(alert: dict) -> dict:
    risk_map = {"High": "High", "Medium": "Medium", "Low": "Low",
                "Informational": "Info", "": "Info"}
    return {
        "name":        alert.get("name", "ZAP Alert"),
        "type":        "web_vulnerability",
        "risk":        risk_map.get(alert.get("risk", ""), "Info"),
        "url":         alert.get("url", ""),
        "description": alert.get("description", ""),
        "solution":    alert.get("solution", ""),
        "confidence":  alert.get("confidence", ""),
        "cwe":         alert.get("cweid", ""),
        "wasc":        alert.get("wascid", ""),
        "evidence":    alert.get("evidence", ""),
    }


# ── Built-in HTTP probes ──────────────────────────────────────────────────────

def _probe_target(url: str) -> list:
    findings = []

    try:
        resp = httpx.get(url, timeout=10, follow_redirects=True,
                         headers={"User-Agent": "Mozilla/5.0 SecurityProbe/1.0"})
    except httpx.RequestError as e:
        logger.warning(f"[WEB] Probe failed: {e}")
        return [{"name": "Target Unreachable", "type": "web_vulnerability", "risk": "Info",
                 "description": str(e), "solution": "Verify target is online and accessible."}]

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    findings.extend(_check_security_headers(headers_lower))
    findings.extend(_check_cookies(resp.cookies, headers_lower))
    findings.extend(_check_information_disclosure(resp, headers_lower))
    findings.extend(_check_https(url, resp))
    findings.extend(_check_cors(headers_lower))
    findings.extend(_check_common_paths(url))
    findings.extend(_check_methods(url))

    return findings


def _check_security_headers(headers: dict) -> list:
    findings = []
    for header, (name, risk) in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append({
                "name": name,
                "type": "missing_security_header",
                "risk": risk,
                "url": "",
                "description": f"The HTTP response is missing the '{header}' security header.",
                "solution": f"Configure your web server to include the '{header}' header in all responses.",
            })

    # Check HSTS value if present
    hsts = headers.get("strict-transport-security", "")
    if hsts and "max-age" in hsts:
        try:
            age = int(re.search(r"max-age=(\d+)", hsts).group(1))
            if age < 31536000:
                findings.append({
                    "name": "HSTS Max-Age Too Low",
                    "type": "missing_security_header",
                    "risk": "Low",
                    "description": f"HSTS max-age is {age}s (< 1 year). Browsers may not enforce HTTPS strictly.",
                    "solution": "Set HSTS max-age to at least 31536000 (1 year). Add includeSubDomains.",
                })
        except Exception:
            pass

    # CSP quality check
    csp = headers.get("content-security-policy", "")
    if csp and ("unsafe-inline" in csp or "unsafe-eval" in csp):
        findings.append({
            "name": "Weak Content-Security-Policy (unsafe-inline/eval)",
            "type": "missing_security_header",
            "risk": "Medium",
            "description": "CSP contains 'unsafe-inline' or 'unsafe-eval', undermining XSS protection.",
            "solution": "Remove 'unsafe-inline'/'unsafe-eval'. Use nonces or hashes for inline scripts.",
        })

    return findings


def _check_cookies(cookies, headers: dict) -> list:
    findings = []
    set_cookie_raw = headers.get("set-cookie", "")

    if not set_cookie_raw and not cookies:
        return findings

    cookie_str = set_cookie_raw.lower()

    if "session" in cookie_str or "auth" in cookie_str or "token" in cookie_str:
        if "httponly" not in cookie_str:
            findings.append({
                "name": "Session Cookie Missing HttpOnly Flag",
                "type": "insecure_cookie",
                "risk": "High",
                "description": "A session/auth cookie is missing the HttpOnly flag, making it accessible to JavaScript (XSS risk).",
                "solution": "Set the HttpOnly flag on all session and authentication cookies.",
            })
        if "secure" not in cookie_str:
            findings.append({
                "name": "Session Cookie Missing Secure Flag",
                "type": "insecure_cookie",
                "risk": "Medium",
                "description": "A session/auth cookie is missing the Secure flag, allowing transmission over HTTP.",
                "solution": "Set the Secure flag on all session and authentication cookies.",
            })
        if "samesite" not in cookie_str:
            findings.append({
                "name": "Session Cookie Missing SameSite Attribute",
                "type": "insecure_cookie",
                "risk": "Medium",
                "description": "Cookie is missing SameSite attribute, potentially enabling CSRF attacks.",
                "solution": "Add SameSite=Strict or SameSite=Lax to session cookies.",
            })

    return findings


def _check_information_disclosure(resp: httpx.Response, headers: dict) -> list:
    findings = []
    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")

    if server and any(char.isdigit() for char in server):
        findings.append({
            "name": "Server Version Disclosed in Header",
            "type": "information_disclosure",
            "risk": "Low",
            "description": f"The Server header reveals version info: '{server}'. Attackers can target known CVEs.",
            "solution": "Configure your web server to suppress or genericise the Server header.",
        })

    if powered_by:
        findings.append({
            "name": "X-Powered-By Header Exposes Technology",
            "type": "information_disclosure",
            "risk": "Low",
            "description": f"X-Powered-By header reveals: '{powered_by}'. Reduces attacker effort.",
            "solution": "Remove or obscure the X-Powered-By header.",
        })

    body_lower = resp.text.lower()
    error_patterns = [
        ("SQL syntax", "SQL Error Leaking in Response", "High",
         "An SQL error message was found in the HTTP response, suggesting SQL injection vulnerability."),
        ("stack trace", "Stack Trace Leaking in Response", "Medium",
         "A stack trace is visible in the HTTP response, revealing server-side code paths."),
        ("exception in thread", "Java Exception Exposed", "Medium",
         "A Java exception trace is visible in the HTTP response."),
        ("warning: mysql", "MySQL Warning Exposed", "High",
         "MySQL warning message visible in response — possible SQL injection or misconfiguration."),
        ("fatal error", "PHP Fatal Error Exposed", "Medium",
         "A PHP fatal error is visible in the HTTP response."),
    ]
    for pattern, name, risk, desc in error_patterns:
        if pattern in body_lower:
            findings.append({
                "name": name, "type": "information_disclosure",
                "risk": risk, "url": str(resp.url),
                "description": desc,
                "solution": "Disable detailed error messages in production. Log errors server-side only.",
            })

    return findings


def _check_https(original_url: str, resp: httpx.Response) -> list:
    findings = []
    final_url = str(resp.url)

    if original_url.startswith("http://") and final_url.startswith("http://"):
        findings.append({
            "name": "No HTTPS Redirect",
            "type": "ssl_error",
            "risk": "High",
            "url": original_url,
            "description": "The application does not redirect HTTP to HTTPS, allowing unencrypted transmission.",
            "solution": "Configure a permanent 301 redirect from HTTP to HTTPS. Enable HSTS.",
        })

    return findings


def _check_cors(headers: dict) -> list:
    findings = []
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")

    if acao == "*":
        findings.append({
            "name": "CORS: Wildcard Origin Allowed",
            "type": "web_vulnerability",
            "risk": "Medium",
            "description": "Access-Control-Allow-Origin: * allows any domain to make cross-origin requests.",
            "solution": "Restrict CORS to specific trusted origins. Never combine '*' with credentials.",
        })

    if acao and acao != "*" and acac.lower() == "true" and acao in ("null", "*"):
        findings.append({
            "name": "CORS: Credentials Allowed with Wildcard Origin",
            "type": "web_vulnerability",
            "risk": "High",
            "description": "CORS allows credentials with a permissive or null origin — cross-site request forgery risk.",
            "solution": "Never set Allow-Credentials: true with a wildcard or null origin.",
        })

    return findings


def _check_common_paths(base_url: str) -> list:
    """Check for commonly exposed sensitive paths."""
    findings = []
    sensitive_paths = [
        ("/.git/HEAD",           "Git Repository Exposed",         "Critical",
         "The .git directory is publicly accessible, leaking full source code."),
        ("/.env",                ".env File Exposed",              "Critical",
         "The .env file is publicly accessible, potentially exposing secrets, API keys and DB credentials."),
        ("/wp-login.php",        "WordPress Login Panel Exposed",  "Medium",
         "WordPress admin login is publicly accessible. Susceptible to brute force."),
        ("/phpmyadmin/",         "phpMyAdmin Panel Exposed",       "High",
         "phpMyAdmin is publicly accessible. Direct database access risk."),
        ("/admin/",              "Admin Panel Exposed",            "Medium",
         "An admin panel is accessible from the internet."),
        ("/server-status",       "Apache server-status Exposed",   "Medium",
         "Apache server-status page leaks request details and server info."),
        ("/actuator/env",        "Spring Boot Actuator Exposed",   "High",
         "Spring Boot Actuator /env endpoint leaks environment variables and secrets."),
        ("/api/swagger.json",    "Swagger/OpenAPI Spec Exposed",   "Low",
         "API schema is publicly accessible, revealing all endpoints and parameters."),
        ("/robots.txt",          "robots.txt Contains Sensitive Paths","Info",
         "robots.txt may reveal hidden paths. Review for sensitive entries."),
        ("/.well-known/security.txt","Security.txt Missing",       "Info",
         "No security.txt file found. Consider adding one for responsible disclosure."),
    ]

    for path, name, risk, desc in sensitive_paths:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            r = httpx.get(url, timeout=5, follow_redirects=False,
                          headers={"User-Agent": "Mozilla/5.0 SecurityProbe/1.0"})
            if r.status_code in (200, 206):
                findings.append({
                    "name": name,
                    "type": "information_disclosure",
                    "risk": risk,
                    "url": url,
                    "description": desc,
                    "solution": "Restrict access to this path via server configuration or .htaccess.",
                })
        except httpx.RequestError:
            pass

    return findings


def _check_methods(url: str) -> list:
    findings = []
    dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]
    try:
        r = httpx.options(url, timeout=5)
        allowed = r.headers.get("allow", "").upper()
        for method in dangerous_methods:
            if method in allowed:
                risk = "High" if method in ("PUT", "DELETE", "TRACE") else "Low"
                findings.append({
                    "name": f"Dangerous HTTP Method Enabled: {method}",
                    "type": "web_vulnerability",
                    "risk": risk,
                    "url": url,
                    "description": f"HTTP {method} method is enabled. This can allow unauthorized file manipulation or traffic interception.",
                    "solution": f"Disable the {method} method unless explicitly required. Configure via server Allow/Limit directives.",
                })
    except httpx.RequestError:
        pass

    # TRACE-specific check
    try:
        r = httpx.request("TRACE", url, timeout=5)
        if r.status_code == 200 and "TRACE" in r.text:
            findings.append({
                "name": "HTTP TRACE Method Enabled (XST Risk)",
                "type": "web_vulnerability",
                "risk": "Medium",
                "url": url,
                "description": "TRACE method is enabled and reflecting back headers — Cross-Site Tracing (XST) attack possible.",
                "solution": "Disable TRACE method in web server configuration.",
            })
    except httpx.RequestError:
        pass

    return findings
