"""
Web Agent — ZAP API + built-in HTTP probes.
Auth credentials from ScanConfig are injected into all requests.
Every finding captures request/response pairs and curl PoC commands.
Tool label: OWASP ZAP 2.14 (real) | Built-in HTTP Probe (fallback)
"""
import logging
import re
import time
from datetime import datetime
from urllib.parse import urlparse, urljoin

import httpx

logger = logging.getLogger(__name__)

TOOL_ZAP      = "OWASP ZAP 2.14"
TOOL_PROBE    = "Built-in HTTP Probe"

SECURITY_HEADERS = {
    "strict-transport-security":    ("HSTS Not Enforced",             "Medium"),
    "content-security-policy":      ("Content-Security-Policy Missing","Medium"),
    "x-frame-options":              ("Clickjacking Protection Missing","Low"),
    "x-content-type-options":       ("MIME Sniffing Not Disabled",    "Low"),
    "referrer-policy":              ("Referrer Policy Missing",       "Low"),
    "permissions-policy":           ("Permissions Policy Missing",    "Low"),
    "cross-origin-opener-policy":   ("COOP Header Missing",           "Info"),
    "cross-origin-resource-policy": ("CORP Header Missing",           "Info"),
}


def run_web_scan(target: str, config=None) -> dict:
    logger.info(f"[WEB] Starting web scan: {target}")
    start    = datetime.utcnow()
    url      = target if target.startswith("http") else f"http://{target}"
    auth_hdrs = config.build_auth_headers() if config else {}
    zap_base  = (config.zap_api_base if config else None) or "http://localhost:8090"
    zap_key   = (config.zap_api_key  if config else None) or "changeme"

    zap_result = _try_zap_scan(url, zap_base, zap_key, config)
    if zap_result is not None:
        findings   = zap_result
        tool_used  = TOOL_ZAP
    else:
        logger.info("[WEB] ZAP unavailable — running built-in HTTP probes")
        findings  = _probe_target(url, auth_hdrs, config)
        tool_used = TOOL_PROBE

    return {
        "module":    "web",
        "target":    target,
        "tool_used": tool_used,
        "scan_time": (datetime.utcnow() - start).total_seconds(),
        "findings":  findings,
        "auth_used": config.build_auth_summary() if config else "Unauthenticated",
    }


# ── ZAP ───────────────────────────────────────────────────────────────────────

def _try_zap_scan(url: str, base: str, key: str, config) -> list | None:
    try:
        r = httpx.get(f"{base}/JSON/core/view/version/", params={"apikey": key}, timeout=4)
        if r.status_code != 200:
            return None

        # Set up context + auth if credentials provided
        if config and config.auth_type != "none":
            _configure_zap_auth(base, key, url, config)

        httpx.get(f"{base}/JSON/spider/action/scan/",
                  params={"apikey": key, "url": url, "maxChildren": 10}, timeout=10)
        _zap_wait("spider", base, key, url)

        httpx.get(f"{base}/JSON/ascan/action/scan/",
                  params={"apikey": key, "url": url, "recurse": "true"}, timeout=10)
        _zap_wait("ascan", base, key, url)

        alerts_r = httpx.get(f"{base}/JSON/core/view/alerts/",
                             params={"apikey": key, "baseurl": url}, timeout=10)
        return [_zap_to_finding(a) for a in alerts_r.json().get("alerts", [])]
    except Exception:
        return None


def _configure_zap_auth(base: str, key: str, url: str, config):
    """Push auth config into ZAP context."""
    try:
        parsed = urlparse(url)
        ctx_r  = httpx.get(f"{base}/JSON/context/action/newContext/",
                           params={"apikey": key, "contextName": "authed"}, timeout=5)
        ctx_id = ctx_r.json().get("contextId", "1")

        if config.auth_type == "form" and config.login_url:
            httpx.get(f"{base}/JSON/authentication/action/setAuthenticationMethod/",
                      params={"apikey": key, "contextId": ctx_id,
                              "authMethodName": "formBasedAuthentication",
                              "authMethodConfigParams":
                                  f"loginUrl={config.login_url}&"
                                  f"loginRequestData={config.username_field}%3D{config.username}%26"
                                  f"{config.password_field}%3D{config.password}"}, timeout=5)
        elif config.auth_type == "http_basic" and config.username:
            httpx.get(f"{base}/JSON/authentication/action/setAuthenticationMethod/",
                      params={"apikey": key, "contextId": ctx_id,
                              "authMethodName": "httpAuthentication",
                              "authMethodConfigParams":
                                  f"hostname={parsed.hostname}&realm="}, timeout=5)
    except Exception as e:
        logger.warning(f"[WEB] ZAP auth config failed: {e}")


def _zap_wait(task: str, base: str, key: str, url: str, timeout: int = 180):
    ep = {"spider": f"{base}/JSON/spider/view/status/",
          "ascan":  f"{base}/JSON/ascan/view/status/"}
    for _ in range(timeout // 3):
        try:
            r = httpx.get(ep[task], params={"apikey": key, "url": url}, timeout=5)
            if int(r.json().get("status", 0)) >= 100:
                return
        except Exception:
            return
        time.sleep(3)


def _zap_to_finding(alert: dict) -> dict:
    risk_map = {"High":"High","Medium":"Medium","Low":"Low","Informational":"Info","":"Info"}
    url  = alert.get("url","")
    host = urlparse(url).netloc or url
    return {
        "name":       alert.get("name","ZAP Alert"),
        "type":       "web_vulnerability",
        "risk":       risk_map.get(alert.get("risk",""),"Info"),
        "url":        url,
        "description":alert.get("description",""),
        "solution":   alert.get("solution",""),
        "confidence": alert.get("confidence",""),
        "cwe":        alert.get("cweid",""),
        "evidence": {
            "type":         "zap_alert",
            "evidence":     alert.get("evidence",""),
            "attack":       alert.get("attack",""),
            "param":        alert.get("param",""),
            "curl_poc":     f'curl -sk "{url}"',
            "request":      alert.get("messageId",""),
            "solution":     alert.get("solution",""),
        },
    }


# ── Built-in probes ───────────────────────────────────────────────────────────

def _probe_target(url: str, auth_hdrs: dict, config) -> list:
    findings = []
    base_hdrs = {"User-Agent": "Mozilla/5.0 SecurityProbe/1.0"}
    base_hdrs.update(auth_hdrs)

    try:
        resp = httpx.get(url, timeout=10, follow_redirects=True, headers=base_hdrs)
    except httpx.RequestError as e:
        return [{"name":"Target Unreachable","type":"web_vulnerability","risk":"Info",
                 "description":str(e),"solution":"Verify target is online.",
                 "evidence":{"curl_poc":f'curl -sk "{url}"',"type":"unreachable"}}]

    hdrs   = {k.lower(): v for k, v in resp.headers.items()}
    req_str = _build_curl(url, base_hdrs)

    findings.extend(_check_security_headers(hdrs, url, req_str, resp))
    findings.extend(_check_cookies(resp, hdrs, url, req_str))
    findings.extend(_check_info_disclosure(resp, hdrs, url, req_str))
    findings.extend(_check_https(url, resp, req_str))
    findings.extend(_check_cors(hdrs, url, req_str, resp))
    findings.extend(_check_sensitive_paths(url, base_hdrs))
    findings.extend(_check_methods(url, base_hdrs))
    if config and config.auth_type != "none":
        findings.extend(_check_auth_bypass(url, base_hdrs, resp))
    return findings


def _build_curl(url: str, headers: dict, method: str = "GET", data: str = "") -> str:
    flags = " ".join(f'-H "{k}: {v}"' for k, v in headers.items()
                     if k.lower() not in ("user-agent",))
    method_flag = f"-X {method}" if method != "GET" else ""
    data_flag   = f"-d '{data}'"  if data else ""
    return f'curl -sk -i {method_flag} {data_flag} {flags} "{url}"'.strip()


def _resp_snippet(resp: httpx.Response, length: int = 300) -> str:
    """Return status line + headers + first N chars of body."""
    header_block = "\n".join(f"{k}: {v}" for k, v in list(resp.headers.items())[:12])
    body_snip    = resp.text[:length].replace("\n","\\n")
    return f"HTTP/{resp.http_version} {resp.status_code}\n{header_block}\n\n{body_snip}"


def _check_security_headers(headers: dict, url: str, req_str: str, resp) -> list:
    findings = []
    for header, (name, risk) in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append({
                "name":        name,
                "type":        "missing_security_header",
                "risk":        risk,
                "url":         url,
                "description": f"Response missing '{header}' security header.",
                "solution":    f"Add '{header}' to all HTTP responses at web server level.",
                "evidence": {
                    "type":             "missing_header",
                    "curl_poc":         req_str,
                    "response_headers": "\n".join(f"{k}: {v}" for k, v in resp.headers.items()),
                    "missing_header":   header,
                },
            })

    hsts = headers.get("strict-transport-security","")
    if hsts:
        m = re.search(r"max-age=(\d+)", hsts)
        if m and int(m.group(1)) < 31536000:
            findings.append({
                "name": "HSTS Max-Age Too Low", "type": "missing_security_header",
                "risk": "Low", "url": url,
                "description": f"HSTS max-age={m.group(1)}s < 1 year.",
                "solution": "Set HSTS max-age ≥ 31536000.",
                "evidence": {"type":"weak_header","curl_poc":req_str,
                             "actual_value": hsts},
            })

    csp = headers.get("content-security-policy","")
    if csp and ("unsafe-inline" in csp or "unsafe-eval" in csp):
        findings.append({
            "name": "Weak CSP (unsafe-inline/eval)", "type": "missing_security_header",
            "risk": "Medium", "url": url,
            "description": "CSP contains 'unsafe-inline'/'unsafe-eval' — XSS protection undermined.",
            "solution": "Remove unsafe-inline/eval. Use nonces or hashes.",
            "evidence": {"type":"weak_csp","curl_poc":req_str,"actual_value":csp},
        })
    return findings


def _check_cookies(resp, headers: dict, url: str, req_str: str) -> list:
    findings = []
    raw = headers.get("set-cookie","").lower()
    if not raw:
        return findings

    sensitive = any(k in raw for k in ("session","auth","token","jwt","sid","csrf"))
    if not sensitive:
        return findings

    checks = [
        ("httponly" not in raw,  "Session Cookie Missing HttpOnly Flag", "High",
         "Session cookie accessible via JavaScript — XSS can steal it.",
         "Set HttpOnly flag on all session cookies."),
        ("secure"   not in raw,  "Session Cookie Missing Secure Flag",   "Medium",
         "Cookie transmitted over plain HTTP — interception risk.",
         "Set Secure flag on all session cookies."),
        ("samesite" not in raw,  "Session Cookie Missing SameSite",      "Medium",
         "No SameSite attribute — CSRF attacks possible.",
         "Add SameSite=Strict or Lax to session cookies."),
    ]
    for condition, name, risk, desc, sol in checks:
        if condition:
            findings.append({
                "name": name, "type": "insecure_cookie", "risk": risk, "url": url,
                "description": desc, "solution": sol,
                "evidence": {
                    "type":       "insecure_cookie",
                    "curl_poc":   req_str,
                    "set_cookie": headers.get("set-cookie","")[:300],
                },
            })
    return findings


def _check_info_disclosure(resp, headers: dict, url: str, req_str: str) -> list:
    findings = []
    server     = headers.get("server","")
    powered_by = headers.get("x-powered-by","")

    if server and any(c.isdigit() for c in server):
        findings.append({
            "name": "Server Version Disclosed", "type": "information_disclosure",
            "risk": "Low", "url": url,
            "description": f"Server header reveals version: '{server}'.",
            "solution": "Suppress or genericise the Server header.",
            "evidence": {"type":"info_disclosure","curl_poc":req_str,"actual_value":server},
        })

    if powered_by:
        findings.append({
            "name": "X-Powered-By Header Exposed", "type": "information_disclosure",
            "risk": "Low", "url": url,
            "description": f"X-Powered-By: '{powered_by}' reveals technology stack.",
            "solution": "Remove X-Powered-By header.",
            "evidence": {"type":"info_disclosure","curl_poc":req_str,"actual_value":powered_by},
        })

    body = resp.text.lower()
    patterns = [
        ("sql syntax",         "SQL Error in Response",   "High",  "SQL error leaks db structure — possible SQLi."),
        ("stack trace",        "Stack Trace Exposed",     "Medium","Server-side code paths revealed."),
        ("warning: mysql",     "MySQL Warning Exposed",   "High",  "MySQL warning in response."),
        ("fatal error",        "PHP Fatal Error Exposed", "Medium","PHP fatal error in response."),
        ("traceback (most",    "Python Traceback Exposed","Medium","Python traceback in response."),
        ("undefined index",    "PHP Notice Exposed",      "Low",   "PHP notice reveals variable names."),
    ]
    for pattern, name, risk, desc in patterns:
        if pattern in body:
            findings.append({
                "name": name, "type": "information_disclosure", "risk": risk, "url": url,
                "description": desc,
                "solution": "Disable detailed errors in production. Log server-side only.",
                "evidence": {
                    "type":         "error_disclosure",
                    "curl_poc":     req_str,
                    "response_body": resp.text[:400],
                },
            })
    return findings


def _check_https(original_url: str, resp, req_str: str) -> list:
    if original_url.startswith("http://") and str(resp.url).startswith("http://"):
        return [{
            "name": "No HTTPS Redirect", "type": "ssl_error", "risk": "High",
            "url": original_url,
            "description": "App doesn't redirect HTTP→HTTPS — unencrypted traffic.",
            "solution": "Add 301 redirect HTTP→HTTPS. Enable HSTS.",
            "evidence": {
                "type":    "no_https",
                "curl_poc": req_str,
                "response_snippet": f"HTTP {resp.status_code} (no redirect to HTTPS)",
            },
        }]
    return []


def _check_cors(headers: dict, url: str, req_str: str, resp) -> list:
    findings = []
    acao = headers.get("access-control-allow-origin","")
    acac = headers.get("access-control-allow-credentials","")

    if acao == "*":
        findings.append({
            "name": "CORS Wildcard Origin", "type": "web_vulnerability",
            "risk": "Medium", "url": url,
            "description": "ACAO: * allows any domain to make cross-origin requests.",
            "solution": "Restrict CORS to specific trusted origins.",
            "evidence": {
                "type":    "cors_wildcard",
                "curl_poc": f'curl -sk -H "Origin: https://evil.com" "{url}" -I',
                "response_snippet": f"Access-Control-Allow-Origin: {acao}",
            },
        })

    if acao and acac.lower() == "true" and acao in ("null","*"):
        findings.append({
            "name": "CORS: Credentials with Permissive Origin", "type": "web_vulnerability",
            "risk": "High", "url": url,
            "description": "Allow-Credentials: true with null/wildcard origin — CSRF risk.",
            "solution": "Never set Allow-Credentials:true with wildcard or null origin.",
            "evidence": {
                "type":    "cors_creds",
                "curl_poc": f'curl -sk -H "Origin: null" "{url}" -I',
                "response_snippet": f"ACAO: {acao}\nACAC: {acac}",
            },
        })
    return findings


def _check_sensitive_paths(base_url: str, headers: dict) -> list:
    findings = []
    paths = [
        ("/.git/HEAD",         "Git Repository Exposed",       "Critical",
         ".git dir publicly accessible — full source code leakable."),
        ("/.env",              ".env File Exposed",             "Critical",
         ".env file publicly accessible — secrets, API keys, DB creds exposed."),
        ("/wp-login.php",      "WordPress Login Panel Exposed", "Medium",
         "WordPress admin login publicly accessible — brute force risk."),
        ("/phpmyadmin/",       "phpMyAdmin Panel Exposed",      "High",
         "phpMyAdmin accessible from internet — direct database access."),
        ("/admin/",            "Admin Panel Exposed",           "Medium",
         "Admin panel accessible from internet."),
        ("/server-status",     "Apache server-status Exposed",  "Medium",
         "Apache server-status leaks request details."),
        ("/actuator/env",      "Spring Boot Actuator Exposed",  "High",
         "Spring Actuator /env endpoint leaks env vars and secrets."),
        ("/.aws/credentials",  "AWS Credentials File Exposed",  "Critical",
         "AWS credentials file publicly accessible — full AWS account compromise."),
        ("/api/swagger.json",  "Swagger Spec Exposed",          "Low",
         "API schema exposed — all endpoints and parameters revealed."),
        ("/backup.zip",        "Backup Archive Exposed",        "High",
         "Backup archive publicly accessible — source code / DB dump risk."),
    ]
    for path, name, risk, desc in paths:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            r = httpx.get(url, timeout=5, follow_redirects=False, headers=headers)
            if r.status_code in (200, 206):
                findings.append({
                    "name": name, "type": "information_disclosure", "risk": risk, "url": url,
                    "description": desc,
                    "solution": f"Restrict access to {path} via server config / firewall.",
                    "evidence": {
                        "type":             "sensitive_path",
                        "curl_poc":         f'curl -sk -i "{url}"',
                        "status_code":      r.status_code,
                        "response_snippet": r.text[:300],
                    },
                })
        except httpx.RequestError:
            pass
    return findings


def _check_methods(url: str, headers: dict) -> list:
    findings = []
    try:
        r = httpx.options(url, timeout=5, headers=headers)
        allowed = r.headers.get("allow","").upper()
        for method in ["PUT","DELETE","TRACE","CONNECT"]:
            if method in allowed:
                risk = "High" if method in ("PUT","DELETE","TRACE") else "Low"
                findings.append({
                    "name": f"Dangerous HTTP Method: {method}", "type": "web_vulnerability",
                    "risk": risk, "url": url,
                    "description": f"HTTP {method} is enabled — file manipulation or traffic interception risk.",
                    "solution": f"Disable {method} unless explicitly required.",
                    "evidence": {
                        "type":    "dangerous_method",
                        "curl_poc": f'curl -sk -X OPTIONS "{url}" -I',
                        "allow_header": allowed,
                    },
                })
    except httpx.RequestError:
        pass
    return findings


def _check_auth_bypass(url: str, auth_hdrs: dict, authed_resp) -> list:
    """
    Try the same request WITHOUT auth headers.
    If the unauthed response looks as rich as the authed one, flag auth bypass.
    """
    findings = []
    try:
        unauthed_resp = httpx.get(url, timeout=8, follow_redirects=True,
                                  headers={"User-Agent": "Mozilla/5.0 SecurityProbe/1.0"})
        authed_len   = len(authed_resp.text)
        unauthed_len = len(unauthed_resp.text)

        if (unauthed_resp.status_code == authed_resp.status_code and
                abs(authed_len - unauthed_len) < 200 and
                unauthed_resp.status_code not in (401, 403, 302)):
            findings.append({
                "name": "Potential Authentication Bypass", "type": "auth_misconfiguration",
                "risk": "High", "url": url,
                "description": (
                    "Unauthenticated request returned the same response as authenticated request. "
                    "Authentication may not be enforced on this endpoint."
                ),
                "solution": "Verify all endpoints require valid authentication. Implement proper authz middleware.",
                "evidence": {
                    "type":            "auth_bypass",
                    "curl_poc":        f'curl -sk -i "{url}"  # no auth headers',
                    "authed_status":   authed_resp.status_code,
                    "unauthed_status": unauthed_resp.status_code,
                    "authed_length":   authed_len,
                    "unauthed_length": unauthed_len,
                },
            })
    except httpx.RequestError:
        pass
    return findings
