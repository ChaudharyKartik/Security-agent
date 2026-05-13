"""
modules/probes.py — WSTG-aligned HTTP probes

Each probe function maps to one or more WSTG checklist IDs via @register.
Signature: probe_NAME(url, hdrs, config=None) -> list[dict]

Use run_probes() to dispatch — it runs all applicable probes concurrently.
"""
import concurrent.futures
import logging
import math
import re
import time
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse

import httpx

logger = logging.getLogger(__name__)

# ── Registry ───────────────────────────────────────────────────────────────────

PROBE_REGISTRY: dict = {}   # wstg_id -> probe_fn


def register(*wstg_ids):
    """Decorator: register a probe for one or more WSTG IDs."""
    def decorator(fn):
        for wid in wstg_ids:
            PROBE_REGISTRY[wid] = fn
        return fn
    return decorator


def run_probes(url: str, hdrs: dict, config=None, checklist_ids: list = None) -> list:
    """
    Run all applicable probes concurrently.
    checklist_ids: if provided, only probes registered for those IDs are run.
                   if None, all registered probes run (full scan).
    """
    if checklist_ids is not None:
        probe_fns = {PROBE_REGISTRY[wid] for wid in checklist_ids if wid in PROBE_REGISTRY}
    else:
        probe_fns = set(PROBE_REGISTRY.values())

    if not probe_fns:
        return []

    findings: list = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(probe_fns), 20)) as ex:
        futures = {ex.submit(fn, url, hdrs, config): fn.__name__ for fn in probe_fns}
        for fut, name in futures.items():
            try:
                result = fut.result(timeout=35)
                if result:
                    findings.extend(result)
            except Exception as e:
                logger.debug(f"[PROBE] {name}: {e}")
    return findings


# ── Shared helpers ─────────────────────────────────────────────────────────────

SECURITY_HEADERS = {
    "strict-transport-security":    ("HSTS Not Enforced",              "Medium"),
    "content-security-policy":      ("Content-Security-Policy Missing", "Medium"),
    "x-frame-options":              ("Clickjacking Protection Missing", "Low"),
    "x-content-type-options":       ("MIME Sniffing Not Disabled",     "Low"),
    "referrer-policy":              ("Referrer Policy Missing",        "Low"),
    "permissions-policy":           ("Permissions Policy Missing",     "Low"),
    "cross-origin-opener-policy":   ("COOP Header Missing",            "Info"),
    "cross-origin-resource-policy": ("CORP Header Missing",            "Info"),
}


SQL_ERRORS = re.compile(
    r"(sql syntax|mysql_fetch|ORA-\d{5}|pg_query|sqlite_|"
    r"unclosed quotation|quoted string not properly|"
    r"syntax error.*sql|microsoft.*odbc|jet database engine|"
    r"warning.*mysql|division by zero|supplied argument is not)",
    re.I,
)

SESSION_NAMES = re.compile(
    r"(sess|session|token|auth|jwt|sid|jsessionid|phpsessid|asp\.net_sessionid|connect\.sid)",
    re.I,
)


def _fetch(url: str, hdrs: dict, method: str = "GET",
           follow_redirects: bool = True, timeout: int = 8, **kwargs) -> httpx.Response | None:
    try:
        fn = getattr(httpx, method.lower())
        return fn(url, headers=hdrs, timeout=timeout,
                  follow_redirects=follow_redirects, **kwargs)
    except httpx.RequestError:
        return None


def _curl(url: str, hdrs: dict, method: str = "GET", data: str = "") -> str:
    flags = " ".join(f'-H "{k}: {v}"' for k, v in hdrs.items()
                     if k.lower() != "user-agent")
    mflag = f"-X {method} " if method != "GET" else ""
    dflag = f"-d '{data}' " if data else ""
    return f"curl -sk -i {mflag}{dflag}{flags} \"{url}\"".strip()


# ── INFO — Information Gathering ───────────────────────────────────────────────

@register("WSTG-INFO-02", "WSTG-INFO-08", "WSTG-INFO-09")
def probe_server_fingerprint(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-INFO-02: Fingerprint web server via response headers.
    WSTG-INFO-08: Fingerprint web framework (X-Powered-By, cookies, body tells).
    WSTG-INFO-09: Fingerprint web application (CMS, platform).
    """
    resp = _fetch(url, hdrs)
    if resp is None:
        return []

    findings = []
    rh = {k.lower(): v for k, v in resp.headers.items()}
    req_str = _curl(url, hdrs)

    server = rh.get("server", "")
    if server and any(c.isdigit() for c in server):
        findings.append({
            "name": "Server Version Disclosed", "type": "information_disclosure",
            "risk": "Low", "url": url,
            "description": f"Server header reveals software version: '{server}'.",
            "solution": "Suppress or genericise the Server header.",
            "evidence": {"type": "server_version", "curl_poc": req_str,
                         "actual_value": server},
        })

    powered_by = rh.get("x-powered-by", "")
    if powered_by:
        findings.append({
            "name": "X-Powered-By Header Exposed", "type": "information_disclosure",
            "risk": "Low", "url": url,
            "description": f"X-Powered-By: '{powered_by}' reveals technology stack.",
            "solution": "Remove X-Powered-By from all HTTP responses.",
            "evidence": {"type": "powered_by", "curl_poc": req_str,
                         "actual_value": powered_by},
        })

    body_lower = resp.text.lower()
    all_headers_str = str(resp.headers).lower()
    framework_tells = [
        ("laravel_session",    "Laravel (PHP)"),
        ("csrftoken",          "Django (Python)"),
        ("_rails",             "Ruby on Rails"),
        ("phpsessid",          "PHP"),
        ("asp.net_sessionid",  "ASP.NET"),
        ("jsessionid",         "Java Servlet Container"),
        ("wp-content",         "WordPress"),
        ("joomla",             "Joomla"),
        ("drupal.settings",    "Drupal"),
    ]
    for indicator, framework in framework_tells:
        if indicator in body_lower or indicator in all_headers_str:
            findings.append({
                "name": f"Framework Identified: {framework}",
                "type": "information_disclosure", "risk": "Info", "url": url,
                "description": (
                    f"Application identified as {framework} via response indicators. "
                    "Attackers can target known CVEs for this platform."
                ),
                "solution": "Remove or obfuscate technology-identifying markers from responses.",
                "evidence": {"type": "framework_fingerprint", "curl_poc": req_str,
                             "indicator": indicator},
            })
            break  # one framework per scan

    return findings


@register("WSTG-INFO-03")
def probe_webserver_metafiles(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-INFO-03: Review webserver metafiles (robots.txt, sitemap.xml,
    crossdomain.xml) for information leakage.
    """
    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"
    findings = []

    sensitive_kw = {
        "admin", "config", "backup", "private", "secret", "internal",
        "credential", "password", "token", "database", "db",
        "debug", "dev", "staging", "test", "console", "dashboard",
    }

    # robots.txt
    robots_url = base + "/robots.txt"
    r = _fetch(robots_url, hdrs)
    if r and r.status_code == 200 and "html" not in r.headers.get("content-type", ""):
        disallowed = []
        for line in r.text.splitlines():
            s = line.strip()
            if s.lower().startswith("disallow:"):
                path = s.split(":", 1)[1].strip()
                if path and path not in ("/", "*"):
                    disallowed.append(path)
        sensitive = [p for p in disallowed if any(k in p.lower() for k in sensitive_kw)]
        if sensitive:
            findings.append({
                "name": "Sensitive Paths in robots.txt",
                "type": "information_disclosure", "risk": "Low", "url": robots_url,
                "description": (
                    f"robots.txt Disallow directives expose: {', '.join(sensitive[:5])}. "
                    "Attackers routinely read robots.txt to enumerate hidden routes."
                ),
                "solution": "Remove sensitive path hints. Enforce access controls server-side.",
                "evidence": {
                    "type": "robots_disclosure",
                    "curl_poc": f'curl -sk "{robots_url}"',
                    "sensitive_paths": sensitive[:10],
                    "response_snippet": r.text[:400],
                },
            })

    return findings


@register("WSTG-INFO-05")
def probe_html_comments(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-INFO-05: Review HTML source for developer comments containing
    credentials, API keys, version info, or internal paths.
    """
    resp = _fetch(url, hdrs)
    if resp is None:
        return []
    ct = resp.headers.get("content-type", "")
    if "html" not in ct:
        return []

    findings = []
    comments  = re.findall(r"<!--(.*?)-->", resp.text, re.DOTALL)
    sensitive_patterns = [
        (r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+",          "Password in HTML Comment",          "High"),
        (r"(?i)(api[_-]?key|apikey|secret|token)\s*[=:]\s*\S+", "Credential in HTML Comment",     "High"),
        (r"(?i)(todo|fixme|hack|xxx|bug|temp)\b",             "Developer Note in HTML Comment",    "Info"),
        (r"(?i)(internal|staging|dev|test)\.([\w-]+\.)+\w+", "Internal Hostname in HTML Comment", "Low"),
        (r"(?i)(db|database|host)\s*[=:]\s*\S+",             "Infrastructure Hint in HTML Comment","Low"),
    ]

    seen: set = set()
    for comment in comments:
        c = comment.strip()
        if len(c) < 4:
            continue
        for pattern, name, risk in sensitive_patterns:
            if name not in seen and re.search(pattern, c):
                seen.add(name)
                findings.append({
                    "name": name, "type": "information_disclosure",
                    "risk": risk, "url": url,
                    "description": "HTML comment contains potentially sensitive information.",
                    "solution": "Remove all sensitive data from HTML comments before deployment.",
                    "evidence": {
                        "type": "html_comment", "curl_poc": _curl(url, hdrs),
                        "comment": c[:200],
                    },
                })
    return findings


@register("WSTG-INFO-06")
def probe_entry_points(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-INFO-06: Identify application entry points.
    Parses HTML for forms, input fields, hidden params, file uploads,
    same-domain links, and data-* API attributes.
    """
    resp = _fetch(url, hdrs)
    if resp is None:
        return []
    if "html" not in resp.headers.get("content-type", ""):
        return []

    findings = []
    body     = resp.text
    parsed   = urlparse(url)

    # ── Forms ────────────────────────────────────────────────────────────────
    form_pattern = re.compile(
        r"<form([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL
    )
    input_pattern = re.compile(
        r"<input([^>]*)>", re.IGNORECASE
    )
    attr = lambda tag, name: (re.search(rf'{name}=["\']([^"\']*)["\']', tag, re.I) or
                              re.search(rf'{name}=(\S+)', tag, re.I))

    forms_found   = []
    has_upload    = False
    http_post_urls = []

    for form_match in form_pattern.finditer(body):
        form_attrs  = form_match.group(1)
        form_body   = form_match.group(2)

        action_m = attr(form_attrs, "action")
        method_m = attr(form_attrs, "method")
        action   = action_m.group(1) if action_m else url
        method   = method_m.group(1).upper() if method_m else "GET"

        # Resolve relative action URL
        full_action = urljoin(url, action) if action else url

        inputs = []
        for inp in input_pattern.finditer(form_body):
            inp_tag  = inp.group(1)
            itype_m  = attr(inp_tag, "type")
            itype    = itype_m.group(1) if itype_m else "text"
            iname    = attr(inp_tag, "name")
            inp_name = iname.group(1) if iname else "(unnamed)"
            inputs.append({"name": inp_name, "type": itype.lower()})
            if itype.lower() == "file":
                has_upload = True

        # Flag form posting to plain HTTP
        if method == "POST" and full_action.startswith("http://"):
            http_post_urls.append(full_action)

        forms_found.append({
            "action": full_action,
            "method": method,
            "inputs": inputs,
        })

    if forms_found:
        field_summary = []
        for f in forms_found:
            names = [i["name"] for i in f["inputs"]]
            field_summary.append(f"{f['method']} {f['action']} [{', '.join(names[:6])}]")

        findings.append({
            "name": "Application Entry Points Identified",
            "type": "information_disclosure", "risk": "Info", "url": url,
            "description": (
                f"{len(forms_found)} form(s) discovered. "
                "Entry points reveal the application's attack surface."
            ),
            "solution": "Ensure all entry points enforce input validation, authentication, and CSRF protection.",
            "evidence": {
                "type":    "entry_points",
                "curl_poc": _curl(url, hdrs),
                "forms":   field_summary[:10],
                "form_count": len(forms_found),
            },
        })

    if has_upload:
        findings.append({
            "name": "File Upload Entry Point Detected",
            "type": "web_vulnerability", "risk": "Medium", "url": url,
            "description": (
                "A file upload input was found. "
                "Upload endpoints are high-risk — file type validation and server-side execution controls are critical."
            ),
            "solution": (
                "Validate file type by content (magic bytes), not extension. "
                "Store uploads outside the web root. Never execute uploaded files."
            ),
            "evidence": {
                "type":    "file_upload",
                "curl_poc": _curl(url, hdrs),
                "forms":   [f["action"] for f in forms_found
                            if any(i["type"] == "file" for i in f["inputs"])],
            },
        })

    for post_url in http_post_urls:
        findings.append({
            "name": "Form POSTs to Plain HTTP",
            "type": "web_vulnerability", "risk": "High", "url": url,
            "description": (
                f"A form submits data via POST to a plain HTTP URL: {post_url}. "
                "Credentials or sensitive data will be transmitted unencrypted."
            ),
            "solution": "Change form action URLs to HTTPS. Enforce HTTPS site-wide.",
            "evidence": {
                "type":    "http_post",
                "curl_poc": _curl(url, hdrs),
                "action_url": post_url,
            },
        })

    # ── Same-domain links ─────────────────────────────────────────────────────
    link_pattern = re.compile(r'<a[^>]+href=["\']([^"\'#][^"\']*)["\']', re.I)
    links = set()
    for m in link_pattern.finditer(body):
        href = m.group(1).strip()
        full = urljoin(url, href)
        if urlparse(full).netloc == parsed.netloc:
            links.add(full)

    # Highlight interesting paths in same-domain links
    interesting_kw = ("login", "signin", "admin", "upload", "api", "search",
                      "register", "signup", "password", "reset", "oauth", "callback")
    interesting_links = [l for l in links if any(k in l.lower() for k in interesting_kw)]

    if interesting_links:
        findings.append({
            "name": "Interesting Application Paths Discovered",
            "type": "information_disclosure", "risk": "Info", "url": url,
            "description": (
                f"{len(interesting_links)} path(s) with security-relevant names found in page links: "
                f"{', '.join(interesting_links[:5])}."
            ),
            "solution": "Verify these endpoints enforce proper authentication and authorization.",
            "evidence": {
                "type":  "interesting_links",
                "curl_poc": _curl(url, hdrs),
                "paths": interesting_links[:15],
            },
        })

    # ── Hidden fields ─────────────────────────────────────────────────────────
    hidden = re.findall(
        r'<input[^>]+type=["\']hidden["\'][^>]+name=["\']([^"\']+)["\']',
        body, re.I
    )
    sensitive_hidden_kw = ("token", "key", "secret", "password", "pass", "auth",
                           "session", "id", "user", "role", "price", "amount")
    sensitive_hidden = [h for h in hidden if any(k in h.lower() for k in sensitive_hidden_kw)]

    if sensitive_hidden:
        findings.append({
            "name": "Sensitive Hidden Form Fields Detected",
            "type": "web_vulnerability", "risk": "Low", "url": url,
            "description": (
                f"Hidden fields with security-relevant names found: {', '.join(sensitive_hidden[:5])}. "
                "Client-controlled hidden fields can be tampered with to bypass server-side logic."
            ),
            "solution": "Never trust hidden field values server-side. Re-derive or sign sensitive values server-side.",
            "evidence": {
                "type":    "hidden_fields",
                "curl_poc": _curl(url, hdrs),
                "fields":  sensitive_hidden[:10],
            },
        })

    return findings


@register("WSTG-INFO-07")
def probe_execution_paths(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-INFO-07: Map execution paths through the application.
    Fetches the root page, extracts all referenced URLs, follows same-domain
    page links one level deep, and reports a structured path inventory.
    Flags parameterized paths, deeply nested routes, and tech-stack tells.
    """
    resp = _fetch(url, hdrs)
    if resp is None:
        return []
    if "html" not in resp.headers.get("content-type", ""):
        return []

    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    def _extract_urls(html: str, base: str) -> set:
        """Pull all URLs from href, action, src, and data-url attributes."""
        raw = set()
        for pattern in [
            r'href=["\']([^"\'#>]+)["\']',
            r'action=["\']([^"\'#>]+)["\']',
            r'src=["\']([^"\'#>]+)["\']',
            r'data-url=["\']([^"\'#>]+)["\']',
            r'data-href=["\']([^"\'#>]+)["\']',
        ]:
            for m in re.finditer(pattern, html, re.I):
                raw.add(m.group(1).strip())
        resolved = set()
        for href in raw:
            if href.startswith(("mailto:", "tel:", "javascript:", "#")):
                continue
            full = urljoin(base, href)
            if urlparse(full).netloc == parsed.netloc:
                resolved.add(full)
        return resolved

    def _categorise(link: str) -> str:
        p    = urlparse(link)
        path = p.path.lower()
        ext  = path.rsplit(".", 1)[-1] if "." in path.split("/")[-1] else ""
        if ext in ("js", "mjs"):          return "script"
        if ext in ("css",):               return "stylesheet"
        if ext in ("png","jpg","jpeg","gif","svg","ico","webp"): return "media"
        if ext in ("pdf","doc","docx","xls","xlsx","zip"):       return "document"
        if "/api/" in path or path.startswith("/api"):           return "api"
        return "page"

    # Level 0 — extract from landing page
    level0_urls = _extract_urls(resp.text, url)

    page_urls = {u for u in level0_urls if _categorise(u) == "page"}
    # Cap crawl to avoid runaway scan — follow at most 15 same-domain pages
    to_crawl  = list(page_urls)[:15]

    # Level 1 — fetch linked pages concurrently, collect their paths too
    level1_urls: set = set()

    def _fetch_links(link_url):
        r = _fetch(link_url, hdrs, timeout=6)
        if r is not None and "html" in r.headers.get("content-type", ""):
            return _extract_urls(r.text, link_url)
        return set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        for result in ex.map(_fetch_links, to_crawl):
            level1_urls.update(result)

    all_urls = level0_urls | level1_urls

    # Build path inventory
    by_category: dict = {}
    parameterized: list = []
    deep_paths:    list = []

    for link in all_urls:
        cat = _categorise(link)
        by_category.setdefault(cat, set()).add(link)

        p = urlparse(link)
        if p.query:
            parameterized.append(link)
        if p.path.count("/") > 4:
            deep_paths.append(link)

    findings = []

    # Main path map finding
    summary = {cat: len(urls) for cat, urls in by_category.items()}
    all_pages = sorted(by_category.get("page", set()))
    all_apis  = sorted(by_category.get("api",  set()))

    if all_urls:
        findings.append({
        "name": "Application Path Map",
        "type": "information_disclosure", "risk": "Info", "url": url,
        "description": (
            f"Crawled {len(all_urls)} URLs across root + {len(to_crawl)} linked page(s). "
            f"Breakdown: {', '.join(f'{v} {k}(s)' for k, v in summary.items())}."
        ),
        "solution": "Ensure all discovered paths enforce authentication and authorisation. Remove debug/test routes from production.",
        "evidence": {
            "type":       "path_map",
            "curl_poc":   _curl(url, hdrs),
            "pages":      all_pages[:20],
            "api_paths":  all_apis[:20],
            "total_urls": len(all_urls),
            "breakdown":  summary,
        },
    })

    # Parameterized paths — potential injection surface
    if parameterized:
        findings.append({
            "name": "Parameterized URLs Discovered",
            "type": "information_disclosure", "risk": "Info", "url": url,
            "description": (
                f"{len(parameterized)} URL(s) with query parameters found. "
                "Each parameter is a potential injection or tampering point."
            ),
            "solution": "Validate and sanitize all query parameters server-side. Apply input allowlists.",
            "evidence": {
                "type":   "parameterized_paths",
                "curl_poc": _curl(url, hdrs),
                "paths":  parameterized[:15],
            },
        })

    # Deeply nested paths — may indicate hidden functionality
    if deep_paths:
        findings.append({
            "name": "Deeply Nested Paths Discovered",
            "type": "information_disclosure", "risk": "Info", "url": url,
            "description": (
                f"{len(deep_paths)} path(s) nested more than 4 levels deep. "
                "Deep paths often indicate admin panels, internal tools, or legacy endpoints."
            ),
            "solution": "Review deeply nested paths for proper access control and removal of unused routes.",
            "evidence": {
                "type":  "deep_paths",
                "curl_poc": _curl(url, hdrs),
                "paths": deep_paths[:10],
            },
        })

    # API paths deserve their own callout
    if all_apis:
        findings.append({
            "name": "API Endpoints Discovered",
            "type": "information_disclosure", "risk": "Info", "url": url,
            "description": (
                f"{len(all_apis)} API path(s) identified. "
                "API endpoints may lack the same access controls applied to the web UI."
            ),
            "solution": "Ensure API endpoints enforce authentication, rate limiting, and input validation.",
            "evidence": {
                "type":      "api_paths",
                "curl_poc":  _curl(url, hdrs),
                "endpoints": all_apis[:15],
            },
        })

    return findings


@register("WSTG-INFO-10")
def probe_application_architecture(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-INFO-10: Map application architecture.
    Detects CDN, WAF, load balancer, reverse proxy, and app server
    components from response headers. Two requests are made:
      1. Normal request — baseline header analysis
      2. Invalid Host header — may trigger WAF block page revealing vendor
    """
    resp = _fetch(url, hdrs)
    if resp is None:
        return []

    rh = {k.lower(): v for k, v in resp.headers.items()}

    # Second request with junk Host to provoke WAF signature
    waf_resp = _fetch(url, {**hdrs, "Host": "waf-probe.invalid.local"},
                      follow_redirects=False, timeout=6)

    waf_hdrs = ({k.lower(): v for k, v in waf_resp.headers.items()}
                if waf_resp else {})
    waf_body  = (waf_resp.text.lower() if waf_resp else "")

    findings  = []
    detected: dict = {}   # layer -> product

    # ── CDN detection ─────────────────────────────────────────────────────────
    cdn_signatures = [
        ("cf-ray",                    "Cloudflare CDN"),
        ("x-amz-cf-id",               "AWS CloudFront"),
        ("x-azure-ref",               "Azure CDN"),
        ("x-fastly-request-id",       "Fastly CDN"),
        ("x-served-by",               "Fastly CDN"),
        ("x-cache",                   "Caching Layer"),
        ("x-varnish",                 "Varnish Cache"),
        ("x-cache-hits",              "CDN Cache"),
        ("via",                       "Proxy / CDN"),
        ("x-cdn",                     "CDN"),
        ("x-akamai-transformed",      "Akamai CDN"),
        ("x-sucuri-cache",            "Sucuri CDN / WAF"),
    ]
    for header, product in cdn_signatures:
        if header in rh:
            detected["CDN / Cache"] = product
            break

    # ── WAF detection ─────────────────────────────────────────────────────────
    waf_signatures = [
        # Header-based
        ("x-sucuri-id",               "Sucuri WAF"),
        ("x-iinfo",                   "Imperva / Incapsula WAF"),
        ("x-fw-hash",                 "Fortinet WAF"),
        ("x-waf-event-info",          "Barracuda WAF"),
        ("x-protected-by",            "WAF (generic)"),
        ("x-dotdefender-denied",      "dotDefender WAF"),
        ("x-aemsecurityfilter",       "Adobe AEM WAF"),
    ]
    for header, product in waf_signatures:
        if header in rh or header in waf_hdrs:
            detected["WAF"] = product
            break

    # Body-based WAF detection on the bad-Host response
    waf_body_tells = [
        ("cloudflare",         "Cloudflare WAF"),
        ("incapsula",          "Imperva Incapsula WAF"),
        ("sucuri",             "Sucuri WAF"),
        ("akamai",             "Akamai WAF"),
        ("mod_security",       "ModSecurity WAF"),
        ("request blocked",    "WAF (generic block page)"),
        ("access denied",      "WAF / Access Control"),
        ("403 forbidden",      "WAF / Access Control"),
    ]
    if "WAF" not in detected:
        for tell, product in waf_body_tells:
            if tell in waf_body:
                detected["WAF"] = product
                break

    # ── Load balancer / reverse proxy ─────────────────────────────────────────
    lb_signatures = [
        ("x-envoy-upstream-service-time", "Envoy Proxy (service mesh)"),
        ("x-kong-upstream-latency",       "Kong API Gateway"),
        ("x-nginx-cache",                 "Nginx Proxy"),
        ("x-request-id",                  "Load Balancer / API Gateway"),
        ("x-correlation-id",              "Load Balancer / API Gateway"),
        ("x-forwarded-server",            "Reverse Proxy"),
        ("x-lb-identifier",               "Load Balancer"),
        ("server-timing",                 "Reverse Proxy / CDN"),
    ]
    for header, product in lb_signatures:
        if header in rh:
            detected.setdefault("Load Balancer / Proxy", product)
            break

    # ── App server detection ───────────────────────────────────────────────────
    server = rh.get("server", "")
    app_server_tells = [
        ("nginx",      "Nginx"),
        ("apache",     "Apache"),
        ("iis",        "Microsoft IIS"),
        ("cloudflare", "Cloudflare"),
        ("gunicorn",   "Gunicorn (Python)"),
        ("uvicorn",    "Uvicorn (Python)"),
        ("jetty",      "Jetty (Java)"),
        ("tomcat",     "Apache Tomcat"),
        ("lighttpd",   "Lighttpd"),
        ("openresty",  "OpenResty (Nginx + Lua)"),
        ("caddy",      "Caddy"),
    ]
    for tell, product in app_server_tells:
        if tell in server.lower():
            detected["App Server"] = product
            break

    # ── Language / framework detection ────────────────────────────────────────
    powered_by = rh.get("x-powered-by", "")
    lang_tells = [
        ("php",        "PHP"),
        ("asp.net",    "ASP.NET"),
        ("express",    "Node.js / Express"),
        ("next.js",    "Next.js"),
        ("django",     "Django (Python)"),
        ("ruby",       "Ruby on Rails"),
        ("laravel",    "Laravel (PHP)"),
    ]
    for tell, product in lang_tells:
        if tell in powered_by.lower() or tell in server.lower():
            detected["Framework"] = product
            break

    # ── Report ────────────────────────────────────────────────────────────────
    if detected:
        arch_summary = " → ".join(
            f"{layer}: {product}"
            for layer, product in detected.items()
        )
        findings.append({
            "name": "Application Architecture Mapped",
            "type": "information_disclosure", "risk": "Info", "url": url,
            "description": (
                f"Infrastructure components identified from response headers: {arch_summary}. "
                "This information helps attackers target known CVEs for each component."
            ),
            "solution": "Remove or genericise identifying headers. Keep all components patched.",
            "evidence": {
                "type":         "architecture_map",
                "curl_poc":     _curl(url, hdrs),
                "components":   detected,
                "raw_headers":  {k: v for k, v in rh.items()
                                 if any(k in s[0] for s in
                                        cdn_signatures + waf_signatures +
                                        lb_signatures)},
            },
        })

    # Separate finding if WAF detected — security teams want to know
    if "WAF" in detected:
        findings.append({
            "name": f"WAF Detected: {detected['WAF']}",
            "type": "information_disclosure", "risk": "Info", "url": url,
            "description": (
                f"A Web Application Firewall ({detected['WAF']}) was identified. "
                "WAF presence is noted — bypass techniques may still be applicable."
            ),
            "solution": "Keep WAF rules updated. WAF is a defence-in-depth layer, not a substitute for secure code.",
            "evidence": {
                "type":     "waf_detected",
                "curl_poc": _curl(url, hdrs),
                "product":  detected["WAF"],
            },
        })

    # No infrastructure headers at all — plain direct-to-app deployment
    if not detected:
        findings.append({
            "name": "No Infrastructure Layer Detected",
            "type": "information_disclosure", "risk": "Info", "url": url,
            "description": (
                "No CDN, WAF, or reverse proxy headers were found. "
                "The application may be exposed directly to the internet without a protective layer."
            ),
            "solution": "Consider placing the application behind a CDN or WAF for DDoS and attack mitigation.",
            "evidence": {
                "type":     "no_infra_layer",
                "curl_poc": _curl(url, hdrs),
            },
        })

    return findings


# ── CONF — Configuration Management ───────────────────────────────────────────

@register("WSTG-CONF-03")
def probe_file_extensions(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-CONF-03: Test for backup/temp copies of web files
    (.bak, .old, .orig, .swp, ~).
    """
    parsed    = urlparse(url)
    base_root = f"{parsed.scheme}://{parsed.netloc}"
    base_path = parsed.path.rstrip("/") or "/index"

    exts        = [".bak", ".old", ".orig", ".copy", ".tmp", ".swp", "~", ".save"]
    base_files  = ["index", "config", "database", "settings", "app", "web", "admin"]

    targets = [f"{base_root}{base_path}{ext}" for ext in exts]
    for fname in base_files:
        for ext in [".bak", ".old", ".orig"]:
            targets.append(f"{base_root}/{fname}{ext}")

    def _check(target_url):
        r = _fetch(target_url, hdrs, follow_redirects=False)
        if r is not None and r.status_code == 200 and len(r.content) > 0:
                return {
                    "name": "Backup/Temp File Exposed",
                    "type": "information_disclosure", "risk": "High", "url": target_url,
                    "description": (
                        f"Backup or temp file accessible: {target_url}. "
                        "May contain source code, credentials, or configuration."
                    ),
                    "solution": "Remove all .bak/.old/.orig files from the web root. Automate cleanup in CI/CD.",
                    "evidence": {
                        "type": "backup_file",
                        "curl_poc": f'curl -sk -i "{target_url}"',
                        "status_code": r.status_code,
                        "response_snippet": r.text[:200],
                    },
                }
        return None

    findings = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        for result in ex.map(_check, targets):
            if result:
                findings.append(result)
    return findings


@register("WSTG-CONF-04", "WSTG-CONF-05")
def probe_sensitive_paths(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-CONF-04: Backup and unreferenced files for sensitive information.
    WSTG-CONF-05: Enumerate infrastructure and admin interfaces.
    """
    paths = [
        # Source / secrets
        ("/.git/HEAD",        "Git Repository Exposed",           "Critical",
         ".git dir publicly accessible — full source code leakable."),
        ("/.git/config",      "Git Config Exposed",               "High",
         ".git/config exposes repository URLs and may contain credentials."),
        ("/.env",             ".env File Exposed",                "Critical",
         ".env file publicly accessible — API keys, DB credentials exposed."),
        ("/.htpasswd",        "Apache .htpasswd Exposed",         "Critical",
         ".htpasswd accessible — hashed credentials exposed."),
        ("/.htaccess",        "Apache .htaccess Exposed",         "Medium",
         ".htaccess accessible — server config and auth rules visible."),
        ("/.aws/credentials", "AWS Credentials Exposed",          "Critical",
         "AWS credentials file accessible — full account compromise possible."),
        # Config files
        ("/web.config",       "IIS web.config Exposed",           "High",
         "web.config accessible — connection strings and secrets exposed."),
        ("/config.php",       "PHP Config Exposed",               "High",
         "PHP config accessible — database credentials may be exposed."),
        ("/appsettings.json", ".NET appsettings.json Exposed",    "High",
         "appsettings.json accessible — connection strings exposed."),
        ("/config.json",      "Config JSON Exposed",              "High",
         "config.json accessible — application configuration exposed."),
        # Admin panels
        ("/phpmyadmin/",      "phpMyAdmin Exposed",               "High",
         "phpMyAdmin accessible — direct database access possible."),
        ("/admin/",           "Admin Panel Exposed",              "Medium",
         "Admin panel accessible from the internet."),
        ("/wp-login.php",     "WordPress Login Exposed",          "Medium",
         "WordPress admin login accessible — brute force risk."),
        ("/wp-admin/",        "WordPress Admin Exposed",          "Medium",
         "/wp-admin/ accessible — enumeration and brute force risk."),
        ("/console",          "Debug Console Exposed",            "High",
         "Debug console accessible — possible remote code execution."),
        # Diagnostics
        ("/server-status",    "Apache server-status Exposed",     "Medium",
         "server-status leaks active requests and client IPs."),
        ("/phpinfo.php",      "PHP Info Page Exposed",            "High",
         "phpinfo() exposes PHP config, env vars, and server paths."),
        ("/info.php",         "PHP Info Page Exposed",            "High",
         "PHP info page exposes server and PHP configuration."),
        # Spring actuator
        ("/actuator/env",     "Spring Actuator /env Exposed",     "High",
         "/actuator/env leaks environment variables and secrets."),
        ("/actuator/beans",   "Spring Actuator /beans Exposed",   "High",
         "/actuator/beans exposes bean structure and dependencies."),
        ("/actuator/metrics", "Spring Actuator /metrics Exposed", "Medium",
         "/actuator/metrics exposes performance counters."),
        # API docs
        ("/api/swagger.json", "Swagger JSON Exposed",             "Low",
         "Swagger spec exposed — all endpoints and params enumerable."),
        ("/swagger-ui.html",  "Swagger UI Exposed",               "Low",
         "Swagger UI accessible — interactive API exploration."),
        ("/api-docs",         "API Docs Exposed",                 "Low",
         "API docs endpoint accessible."),
        # Backups / debug
        ("/backup.zip",       "Backup Archive Exposed",           "High",
         "Backup archive accessible — source code / DB dump risk."),
        ("/debug",            "Debug Endpoint Exposed",           "Medium",
         "Debug endpoint accessible — may expose internals."),
        ("/.DS_Store",        ".DS_Store File Exposed",           "Low",
         ".DS_Store exposes macOS directory structure."),
    ]

    def _check(pt):
        path, name, risk, desc = pt
        target = urljoin(url.rstrip("/") + "/", path.lstrip("/"))
        r = _fetch(target, hdrs, follow_redirects=False)
        if r is None:
            return None
        if r.status_code in (200, 206):
            return {
                "name": name, "type": "information_disclosure",
                "risk": risk, "url": target,
                "description": desc,
                "solution": f"Restrict access to {path} via server config or firewall.",
                "evidence": {
                    "type": "sensitive_path",
                    "curl_poc": f'curl -sk -i "{target}"',
                    "status_code": r.status_code,
                    "response_snippet": r.text[:300],
                },
            }
        if r.status_code in (401, 403):
            return {
                "name": f"{name} (Path Exists — Access Restricted)",
                "type": "information_disclosure", "risk": "Low", "url": target,
                "description": f"{desc} Path confirmed to exist (HTTP {r.status_code}).",
                "solution": f"Confirm {path} is properly protected and bypass is not possible.",
                "evidence": {
                    "type": "sensitive_path_restricted",
                    "curl_poc": f'curl -sk -i "{target}"',
                    "status_code": r.status_code,
                },
            }
        return None

    # Directory listing — run alongside path checks
    def _dir_check(dir_path):
        parsed = urlparse(url)
        dir_url = f"{parsed.scheme}://{parsed.netloc}{dir_path}"
        r = _fetch(dir_url, hdrs, follow_redirects=False)
        if r is not None and r.status_code == 200:
            body_l = r.text.lower()
            if "index of" in body_l or "directory listing" in body_l:
                return {
                    "name": "Directory Listing Enabled",
                    "type": "information_disclosure", "risk": "Medium", "url": dir_url,
                    "description": (
                        f"Directory listing enabled at {dir_path} — "
                        "file structure and sensitive documents enumerable."
                    ),
                    "solution": "Disable directory listing (Options -Indexes / autoindex off).",
                    "evidence": {
                        "type": "directory_listing",
                        "curl_poc": f'curl -sk -i "{dir_url}"',
                        "response_snippet": r.text[:300],
                    },
                }
        return None

    dir_paths = ["/uploads/", "/images/", "/files/", "/static/",
                 "/assets/", "/backup/", "/data/", "/docs/"]

    findings = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        path_futs = [ex.submit(_check, pt) for pt in paths]
        dir_futs  = [ex.submit(_dir_check, dp) for dp in dir_paths]
        for fut in path_futs + dir_futs:
            result = fut.result()
            if result:
                findings.append(result)
    return findings


@register("WSTG-CONF-06", "WSTG-INPV-03")
def probe_http_methods(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-CONF-06 / WSTG-INPV-03: Test for dangerous enabled HTTP methods.
    """
    findings = []
    r = _fetch(url, hdrs, method="OPTIONS", follow_redirects=False, timeout=5)
    if r is None:
        return findings
    allowed = r.headers.get("allow", "").upper()
    for method in ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"]:
        if method in allowed:
            risk = "High" if method in ("PUT", "DELETE", "PATCH", "TRACE") else "Low"
            findings.append({
                "name": f"Dangerous HTTP Method: {method}",
                "type": "web_vulnerability", "risk": risk, "url": url,
                "description": f"HTTP {method} enabled — file manipulation or interception risk.",
                "solution": f"Disable {method} unless explicitly required.",
                "evidence": {
                    "type": "dangerous_method",
                    "curl_poc": f'curl -sk -X OPTIONS "{url}" -I',
                    "allow_header": allowed,
                },
            })
    return findings


@register("WSTG-CONF-07", "WSTG-CLNT-09")
def probe_security_headers(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-CONF-07: Test HTTP Strict Transport Security.
    WSTG-CLNT-09: Test for Clickjacking (X-Frame-Options / CSP frame-ancestors).
    Also checks all other security response headers.
    """
    resp = _fetch(url, hdrs)
    if resp is None:
        return []

    findings = []
    rh      = {k.lower(): v for k, v in resp.headers.items()}
    req_str = _curl(url, hdrs)

    for header, (name, risk) in SECURITY_HEADERS.items():
        if header not in rh:
            findings.append({
                "name": name, "type": "missing_security_header",
                "risk": risk, "url": url,
                "description": f"Response is missing the '{header}' security header.",
                "solution": f"Add '{header}' to all HTTP responses at the web server level.",
                "evidence": {
                    "type": "missing_header", "curl_poc": req_str,
                    "response_headers": "\n".join(f"{k}: {v}" for k, v in resp.headers.items()),
                    "missing_header": header,
                },
            })

    hsts = rh.get("strict-transport-security", "")
    if hsts:
        m = re.search(r"max-age=(\d+)", hsts)
        if m and int(m.group(1)) < 31536000:
            findings.append({
                "name": "HSTS Max-Age Too Low", "type": "missing_security_header",
                "risk": "Low", "url": url,
                "description": f"HSTS max-age={m.group(1)}s is below the recommended 1 year.",
                "solution": "Set Strict-Transport-Security: max-age=31536000; includeSubDomains.",
                "evidence": {"type": "weak_hsts", "curl_poc": req_str,
                             "actual_value": hsts},
            })

    csp = rh.get("content-security-policy", "")
    if csp:
        if "unsafe-inline" in csp or "unsafe-eval" in csp:
            findings.append({
                "name": "Weak CSP (unsafe-inline / unsafe-eval)",
                "type": "missing_security_header", "risk": "Medium", "url": url,
                "description": "CSP contains 'unsafe-inline' or 'unsafe-eval' — XSS protection undermined.",
                "solution": "Remove unsafe-inline/eval. Use nonces or hashes for inline scripts.",
                "evidence": {"type": "weak_csp", "curl_poc": req_str,
                             "actual_value": csp},
            })
        # Wildcard source in script-src or default-src allows any origin to inject scripts
        if re.search(r"(?:script-src|default-src)[^;]*\s\*", csp):
            findings.append({
                "name": "Weak CSP (Wildcard Script Source)",
                "type": "missing_security_header", "risk": "High", "url": url,
                "description": "CSP script-src or default-src allows '*' — any external origin can load scripts.",
                "solution": "Replace '*' with explicit trusted origins in script-src.",
                "evidence": {"type": "weak_csp_wildcard", "curl_poc": req_str,
                             "actual_value": csp},
            })
        # data: URI in script-src allows inline script execution via data URIs
        if re.search(r"(?:script-src|default-src)[^;]*\bdata:", csp):
            findings.append({
                "name": "Weak CSP (data: URI in Script Source)",
                "type": "missing_security_header", "risk": "Medium", "url": url,
                "description": "CSP script-src or default-src allows 'data:' — permits script execution via data URIs.",
                "solution": "Remove 'data:' from script-src. Use nonces or hashes instead.",
                "evidence": {"type": "weak_csp_data_uri", "curl_poc": req_str,
                             "actual_value": csp},
            })

    return findings


@register("WSTG-CONF-08")
def probe_crossdomain_policy(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-CONF-08: Test RIA cross-domain policy.
    Fetches crossdomain.xml and clientaccesspolicy.xml, parses the policy,
    and flags overly permissive access rules (wildcard domains, all headers,
    allow-http-request-headers-from *, etc.).
    """
    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"
    findings = []

    # ── crossdomain.xml (Flash / PDF) ─────────────────────────────────────────
    cdx_url = base + "/crossdomain.xml"
    r = _fetch(cdx_url, hdrs)
    if r and r.status_code == 200 and len(r.text.strip()) > 0:
        body = r.text
        body_lower = body.lower()

        # Wildcard domain — any origin can read responses
        if re.search(r'domain\s*=\s*["\']?\*', body, re.I) or 'domain="*"' in body_lower:
            findings.append({
                "name": "crossdomain.xml: Wildcard Domain Allowed",
                "type": "web_vulnerability", "risk": "High", "url": cdx_url,
                "description": (
                    "crossdomain.xml grants access to all domains (domain=\"*\"). "
                    "Any Flash or PDF document on any origin can make authenticated "
                    "cross-domain requests and read responses — equivalent to CORS wildcard."
                ),
                "solution": "Restrict allow-access-from to specific trusted domains. Never use domain=\"*\".",
                "evidence": {
                    "type":             "crossdomain_wildcard",
                    "curl_poc":         f'curl -sk "{cdx_url}"',
                    "response_snippet": body[:400],
                },
            })

        # Wildcard headers
        if 'headers="*"' in body_lower or "headers='*'" in body:
            findings.append({
                "name": "crossdomain.xml: All Request Headers Allowed",
                "type": "web_vulnerability", "risk": "Medium", "url": cdx_url,
                "description": (
                    "crossdomain.xml permits all request headers (headers=\"*\"). "
                    "Cross-domain clients can send arbitrary headers including auth tokens."
                ),
                "solution": "Restrict permitted headers to the minimum required set.",
                "evidence": {
                    "type":             "crossdomain_headers_wildcard",
                    "curl_poc":         f'curl -sk "{cdx_url}"',
                    "response_snippet": body[:400],
                },
            })

        # allow-http-request-headers-from with wildcard
        if re.search(r'allow-http-request-headers-from[^>]+domain=["\*]', body, re.I):
            findings.append({
                "name": "crossdomain.xml: HTTP Request Headers from Any Domain",
                "type": "web_vulnerability", "risk": "Medium", "url": cdx_url,
                "description": (
                    "allow-http-request-headers-from with domain=\"*\" permits any domain "
                    "to inject arbitrary HTTP headers into cross-domain requests."
                ),
                "solution": "Restrict allow-http-request-headers-from to specific trusted domains.",
                "evidence": {
                    "type":             "crossdomain_headers_any",
                    "curl_poc":         f'curl -sk "{cdx_url}"',
                    "response_snippet": body[:400],
                },
            })

        # Policy exists but no wildcard — still worth reporting as info
        if not findings:
            # Count how many domains are allowed
            domains = re.findall(r'domain=["\']([^"\']+)["\']', body, re.I)
            findings.append({
                "name": "crossdomain.xml Present",
                "type": "information_disclosure", "risk": "Low", "url": cdx_url,
                "description": (
                    f"crossdomain.xml exists and permits access from: {', '.join(domains[:5]) or '(unknown)'}. "
                    "Verify each allowed domain is intentional and still trusted."
                ),
                "solution": "Review allowed domains regularly. Remove stale or overly broad entries.",
                "evidence": {
                    "type":             "crossdomain_present",
                    "curl_poc":         f'curl -sk "{cdx_url}"',
                    "allowed_domains":  domains[:10],
                    "response_snippet": body[:400],
                },
            })

    # ── clientaccesspolicy.xml (Silverlight) ──────────────────────────────────
    cap_url = base + "/clientaccesspolicy.xml"
    r = _fetch(cap_url, hdrs)
    if r and r.status_code == 200 and len(r.text.strip()) > 0:
        body = r.text
        body_lower = body.lower()

        # Wildcard URI — any origin
        if '<domain uri="*"' in body_lower or "<domain uri='*'" in body_lower:
            findings.append({
                "name": "clientaccesspolicy.xml: Wildcard Origin Allowed",
                "type": "web_vulnerability", "risk": "High", "url": cap_url,
                "description": (
                    "clientaccesspolicy.xml permits Silverlight access from all origins (uri=\"*\"). "
                    "Any Silverlight application can make authenticated cross-domain requests."
                ),
                "solution": "Restrict domain uri to specific trusted origins.",
                "evidence": {
                    "type":             "cap_wildcard",
                    "curl_poc":         f'curl -sk "{cap_url}"',
                    "response_snippet": body[:400],
                },
            })
        else:
            findings.append({
                "name": "clientaccesspolicy.xml Present",
                "type": "information_disclosure", "risk": "Low", "url": cap_url,
                "description": (
                    "clientaccesspolicy.xml (Silverlight cross-domain policy) exists. "
                    "Silverlight is end-of-life but the file may still affect some clients."
                ),
                "solution": "Remove clientaccesspolicy.xml if Silverlight is no longer in use.",
                "evidence": {
                    "type":             "cap_present",
                    "curl_poc":         f'curl -sk "{cap_url}"',
                    "response_snippet": body[:400],
                },
            })

    return findings


@register("WSTG-CONF-10")
def probe_subdomain_takeover(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-CONF-10: Test for subdomain takeover.
    Resolves the target hostname's CNAME chain, matches against known cloud
    service fingerprints, and checks for unclaimed-resource indicators in the
    HTTP response body.
    """
    findings = []
    try:
        import socket

        parsed   = urlparse(url)
        hostname = parsed.hostname or ""
        if not hostname:
            return []

        # ── resolve CNAME chain ───────────────────────────────────────────────
        cname_target = None
        try:
            import dns.resolver  # dnspython
            answers = dns.resolver.resolve(hostname, "CNAME")
            cname_target = str(answers[0].target).rstrip(".")
        except Exception:
            # Fallback: getaddrinfo won't give us the CNAME but at least we
            # can detect if the hostname resolves to a cloud IP range heuristic.
            # Leave cname_target as None — we'll still do the HTTP body check.
            pass

        # ── cloud service fingerprints ────────────────────────────────────────
        # Each entry: (cname_pattern, unclaimed_body_strings, service_name)
        FINGERPRINTS = [
            ("github.io",                ["There isn't a GitHub Pages site here"],          "GitHub Pages"),
            ("githubusercontent.com",     ["There isn't a GitHub Pages site here"],          "GitHub Pages"),
            ("herokuapp.com",            ["No such app", "there is no app"],                "Heroku"),
            ("s3.amazonaws.com",         ["NoSuchBucket", "The specified bucket"],          "AWS S3"),
            ("s3-website",               ["NoSuchBucket", "The specified bucket"],          "AWS S3"),
            ("cloudfront.net",           ["ERROR: The request could not be satisfied"],     "AWS CloudFront"),
            ("azurewebsites.net",        ["404 Web Site not found", "does not exist"],      "Azure Web Apps"),
            ("azureedge.net",            ["404 Web Site not found"],                        "Azure CDN"),
            ("blob.core.windows.net",    ["BlobNotFound", "ResourceNotFound"],              "Azure Blob"),
            ("netlify.com",              ["Not Found - Request ID"],                        "Netlify"),
            ("netlify.app",              ["Not Found - Request ID"],                        "Netlify"),
            ("readthedocs.io",           ["unknown to Read the Docs"],                      "Read the Docs"),
            ("zendesk.com",              ["Help Center Closed"],                            "Zendesk"),
            ("myshopify.com",            ["Sorry, this shop is currently unavailable"],     "Shopify"),
            ("surge.sh",                 ["project not found"],                             "Surge.sh"),
            ("bitbucket.io",             ["Repository not found"],                          "Bitbucket Pages"),
            ("ghost.io",                 ["The thing you were looking for is no longer here"], "Ghost"),
            ("fastly.net",               ["Fastly error: unknown domain"],                  "Fastly"),
            ("pantheonsite.io",          ["The gods are wise", "404 error unknown site"],   "Pantheon"),
            ("cargo.site",               ["404 Not Found"],                                 "Cargo"),
            ("webflow.io",               ["Page Not Found", "The page you are looking"],   "Webflow"),
        ]

        matched_service = None
        unclaimed_indicators = []

        if cname_target:
            for cname_pat, body_strings, service in FINGERPRINTS:
                if cname_pat in cname_target:
                    matched_service     = service
                    unclaimed_indicators = body_strings
                    break

        # ── HTTP body check ───────────────────────────────────────────────────
        if matched_service:
            # Fetch the CNAME destination directly
            cname_url = f"{parsed.scheme}://{cname_target}{parsed.path or '/'}"
            r = _fetch(cname_url, hdrs)
            body_text = (r.text if r else "").lower()

            is_unclaimed = any(ind.lower() in body_text for ind in unclaimed_indicators)

            if is_unclaimed:
                findings.append({
                    "name": f"Subdomain Takeover: {matched_service}",
                    "type": "web_vulnerability", "risk": "High", "url": url,
                    "description": (
                        f"The hostname '{hostname}' has a CNAME pointing to '{cname_target}' "
                        f"({matched_service}), but the upstream resource appears unclaimed. "
                        "An attacker can register this resource and serve arbitrary content "
                        "under the victim's domain."
                    ),
                    "solution": (
                        f"Remove the dangling CNAME record for '{hostname}' immediately, "
                        f"or reclaim the {matched_service} resource it points to."
                    ),
                    "evidence": {
                        "type":             "subdomain_takeover",
                        "curl_poc":         f'curl -sk -H "Host: {hostname}" "{cname_url}"',
                        "cname_target":     cname_target,
                        "service":          matched_service,
                        "response_snippet": (r.text[:400] if r else ""),
                    },
                })
            else:
                findings.append({
                    "name": f"CNAME Points to {matched_service}",
                    "type": "information_disclosure", "risk": "Low", "url": url,
                    "description": (
                        f"'{hostname}' has a CNAME to '{cname_target}' ({matched_service}). "
                        "The resource currently appears claimed, but should be monitored — "
                        "if the upstream service is decommissioned without removing this DNS "
                        "record, the subdomain becomes vulnerable to takeover."
                    ),
                    "solution": (
                        "Ensure the CNAME target remains actively maintained. "
                        "Remove the DNS record when the service is decommissioned."
                    ),
                    "evidence": {
                        "type":         "cname_to_cloud",
                        "curl_poc":     f'curl -sk "{url}"',
                        "cname_target": cname_target,
                        "service":      matched_service,
                    },
                })

    except Exception as exc:
        logger.debug(f"[PROBE] probe_subdomain_takeover: {exc}")

    return findings


# ── IDNT — Identity Management Testing ────────────────────────────────────────

@register("WSTG-IDNT-04")
def probe_account_enumeration(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-IDNT-04: Test for account enumeration via login, registration,
    and password-reset endpoints. Compares status codes, body content,
    and response timing between valid-looking and invalid usernames.
    """
    parsed  = urlparse(url)
    base    = f"{parsed.scheme}://{parsed.netloc}"
    findings = []

    VALID_USER   = "admin@example.com"
    INVALID_USER = "zz_no_such_user_xyzzy_99@invalid-domain-xyzzy.tld"
    FAKE_PASS    = "P@ssw0rd_probe_1!"

    # ── candidate endpoints ───────────────────────────────────────────────────
    LOGIN_PATHS = [
        "/login", "/signin", "/sign-in", "/auth/login", "/user/login",
        "/api/login", "/api/auth/login", "/api/v1/auth/login",
        "/account/login", "/admin/login", "/wp-login.php",
    ]
    REGISTER_PATHS = [
        "/register", "/signup", "/sign-up", "/auth/register",
        "/user/register", "/api/register", "/api/auth/register",
        "/account/register", "/create-account",
    ]
    RESET_PATHS = [
        "/forgot-password", "/forgot_password", "/password/reset",
        "/reset-password", "/auth/forgot", "/api/auth/forgot",
        "/account/forgot-password", "/user/forgot-password",
    ]

    json_ct  = {"Content-Type": "application/json"}
    combined = {**hdrs, **json_ct}

    def _timed_post(endpoint, payload_valid, payload_invalid):
        """POST with valid then invalid user; return (valid_r, invalid_r, timing_diff_ms)."""
        try:
            t0 = time.monotonic()
            rv = httpx.post(endpoint, json=payload_valid,
                            headers=combined, timeout=10, follow_redirects=True)
            t1 = time.monotonic()
            ri = httpx.post(endpoint, json=payload_invalid,
                            headers=combined, timeout=10, follow_redirects=True)
            t2 = time.monotonic()
            return rv, ri, round(((t1 - t0) - (t2 - t1)) * 1000)
        except Exception:
            return None, None, 0

    def _check_enum(endpoint, rv, ri, timing_diff_ms, endpoint_type):
        local_findings = []
        if rv is None or ri is None:
            return local_findings

        status_diff = rv.status_code != ri.status_code
        body_diff   = abs(len(rv.text) - len(ri.text)) > 50

        # Keyword indicators in response bodies
        valid_keywords   = ["incorrect password", "wrong password", "invalid password",
                            "email already", "account exists", "password reset sent"]
        invalid_keywords = ["user not found", "no account", "email not found",
                            "account not found", "does not exist", "not registered"]

        vb = rv.text.lower()
        ib = ri.text.lower()
        keyword_leak = (
            any(k in vb for k in valid_keywords) or
            any(k in ib for k in invalid_keywords)
        )

        timing_leak = abs(timing_diff_ms) > 300  # >300ms gap → timing oracle

        if status_diff or body_diff or keyword_leak:
            local_findings.append({
                "name": f"Account Enumeration via {endpoint_type}",
                "type": "information_disclosure", "risk": "Medium", "url": endpoint,
                "description": (
                    f"The {endpoint_type} endpoint returns distinguishable responses for "
                    "valid vs invalid usernames, allowing an attacker to enumerate valid accounts."
                ),
                "solution": (
                    "Return identical responses (status code, body, timing) for valid and "
                    "invalid usernames. Use generic messages like 'If that email is registered, "
                    "you will receive an email.'"
                ),
                "evidence": {
                    "type":              "account_enumeration",
                    "curl_poc":          f'curl -sk -X POST "{endpoint}" -H "Content-Type: application/json" -d \'{{"email":"{VALID_USER}","password":"{FAKE_PASS}"}}\'',
                    "valid_status":      rv.status_code,
                    "invalid_status":    ri.status_code,
                    "valid_body_len":    len(rv.text),
                    "invalid_body_len":  len(ri.text),
                    "keyword_leak":      keyword_leak,
                },
            })

        if timing_leak:
            local_findings.append({
                "name": f"Account Enumeration via Timing Oracle ({endpoint_type})",
                "type": "information_disclosure", "risk": "Low", "url": endpoint,
                "description": (
                    f"Response time differs by {abs(timing_diff_ms)}ms between valid and invalid "
                    f"usernames on {endpoint_type} — may allow timing-based account enumeration."
                ),
                "solution": "Ensure consistent processing time for all username inputs (constant-time comparison, uniform delays).",
                "evidence": {
                    "type":         "timing_oracle",
                    "curl_poc":     f'curl -sk -w "%{{time_total}}" -X POST "{endpoint}" -H "Content-Type: application/json" -d \'{{"email":"{VALID_USER}","password":"{FAKE_PASS}"}}\'',
                    "timing_diff_ms": timing_diff_ms,
                },
            })

        return local_findings

    # ── login endpoints ───────────────────────────────────────────────────────
    for path in LOGIN_PATHS:
        endpoint = base + path
        rv, ri, tdiff = _timed_post(
            endpoint,
            {"email": VALID_USER,   "username": VALID_USER,   "password": FAKE_PASS},
            {"email": INVALID_USER, "username": INVALID_USER, "password": FAKE_PASS},
        )
        if rv and rv.status_code not in (404, 405, 403):
            findings.extend(_check_enum(endpoint, rv, ri, tdiff, "Login"))
            break  # stop at first responding login endpoint

    # ── registration endpoints ────────────────────────────────────────────────
    for path in REGISTER_PATHS:
        endpoint = base + path
        rv, ri, tdiff = _timed_post(
            endpoint,
            {"email": VALID_USER,   "username": VALID_USER,   "password": FAKE_PASS},
            {"email": INVALID_USER, "username": INVALID_USER, "password": FAKE_PASS},
        )
        if rv and rv.status_code not in (404, 405, 403):
            findings.extend(_check_enum(endpoint, rv, ri, tdiff, "Registration"))
            break

    # ── password-reset endpoints ──────────────────────────────────────────────
    for path in RESET_PATHS:
        endpoint = base + path
        rv, ri, tdiff = _timed_post(
            endpoint,
            {"email": VALID_USER},
            {"email": INVALID_USER},
        )
        if rv and rv.status_code not in (404, 405, 403):
            findings.extend(_check_enum(endpoint, rv, ri, tdiff, "Password Reset"))
            break

    return findings


# ── ATHN — Authentication Testing ─────────────────────────────────────────────

@register("WSTG-ATHN-01", "WSTG-CRYP-03")
def probe_https_redirect(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-ATHN-01: Credentials transported over an encrypted channel.
    WSTG-CRYP-03: Sensitive information sent via unencrypted channel.
    """
    if not url.startswith("http://"):
        return []
    r = _fetch(url, hdrs, follow_redirects=False)
    if r is not None:
        location = r.headers.get("location", "").lower()
        if r.status_code not in (301, 302, 303, 307, 308) or "https" not in location:
            return [{
                "name": "No HTTPS Redirect",
                "type": "ssl_error", "risk": "High", "url": url,
                "description": (
                    "The application does not redirect HTTP to HTTPS. "
                    "Credentials and session tokens may be transmitted in cleartext."
                ),
                "solution": "Add a 301 redirect from HTTP to HTTPS. Enable HSTS.",
                "evidence": {
                    "type": "no_https", "curl_poc": _curl(url, hdrs),
                    "response_snippet": f"HTTP {r.status_code} — no HTTPS redirect",
                },
            }]
    return []


@register("WSTG-ATHN-04")
def probe_auth_bypass(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-ATHN-04: Test for bypassing authentication by comparing
    authenticated vs unauthenticated responses.
    """
    has_auth = any(k.lower() in ("authorization", "cookie", "x-api-key") for k in hdrs)
    if not has_auth:
        return []
    authed   = _fetch(url, hdrs)
    unauthed = _fetch(url, {"User-Agent": "Mozilla/5.0 SecurityProbe/1.0"})
    if authed is None or unauthed is None:
        return []
    if (unauthed.status_code == authed.status_code and
            abs(len(authed.text) - len(unauthed.text)) < 200 and
            unauthed.status_code not in (401, 403, 302)):
        return [{
            "name": "Potential Authentication Bypass",
            "type": "auth_misconfiguration", "risk": "High", "url": url,
            "description": (
                "Unauthenticated request returned the same response as the authenticated one. "
                "Authentication enforcement may be missing."
            ),
            "solution": "Verify all endpoints enforce authentication. Implement global authz middleware.",
            "evidence": {
                "type": "auth_bypass",
                "curl_poc": f'curl -sk -i "{url}"  # without auth headers',
                "authed_status": authed.status_code,
                "unauthed_status": unauthed.status_code,
                "authed_length": len(authed.text),
                "unauthed_length": len(unauthed.text),
            },
        }]
    return []


@register("WSTG-ATHN-06")
def probe_browser_cache(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-ATHN-06: Test browser cache weakness on pages with sensitive content.
    """
    resp = _fetch(url, hdrs)
    if resp is None:
        return []

    body_lower = resp.text.lower()
    is_sensitive = (
        any(k in body_lower for k in ("password", "login", "logout", "account", "sign in")) or
        any(k.lower() in ("authorization", "cookie") for k in hdrs)
    )
    if not is_sensitive:
        return []

    cc = resp.headers.get("cache-control", "").lower()
    if "no-store" not in cc:
        return [{
            "name": "Sensitive Page Cacheable",
            "type": "web_vulnerability", "risk": "Low", "url": url,
            "description": (
                "Sensitive page does not set Cache-Control: no-store. "
                "Cache-Control: private restricts proxy caching but the browser still "
                "stores the response locally — credentials or session data may be "
                "recovered from browser cache on shared devices."
            ),
            "solution": "Set Cache-Control: no-store, no-cache, must-revalidate on all authenticated pages.",
            "evidence": {
                "type": "browser_cache", "curl_poc": _curl(url, hdrs),
                "cache_control": cc or "(not set)",
            },
        }]
    return []


@register("WSTG-ATHN-02")
def probe_default_credentials(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-ATHN-02: Test for default credentials on discovered login endpoints.
    """
    parsed   = urlparse(url)
    base     = f"{parsed.scheme}://{parsed.netloc}"
    findings = []

    LOGIN_PATHS = [
        "/login", "/signin", "/admin/login", "/admin", "/wp-login.php",
        "/api/login", "/api/auth/login", "/api/v1/auth/login",
        "/auth/login", "/user/login", "/account/login",
    ]
    DEFAULT_CREDS = [
        ("admin",     "admin"),
        ("admin",     "password"),
        ("admin",     "admin123"),
        ("admin",     "1234"),
        ("admin",     "123456"),
        ("root",      "root"),
        ("root",      "toor"),
        ("root",      "password"),
        ("test",      "test"),
        ("guest",     "guest"),
        ("user",      "user"),
        ("admin",     ""),
        ("administrator", "administrator"),
        ("administrator", "password"),
    ]
    combined = {**hdrs, "Content-Type": "application/json"}

    SUCCESS_INDICATORS   = ["dashboard", "welcome", "logout", "profile",
                            "token", "access_token", "session"]
    FAILURE_INDICATORS   = ["invalid", "incorrect", "failed", "unauthorized",
                            "wrong", "denied", "error"]

    def _looks_successful(r) -> bool:
        if r is None:
            return False
        if r.status_code in (200, 201):
            body = r.text.lower()
            has_success = any(k in body for k in SUCCESS_INDICATORS)
            has_failure = any(k in body for k in FAILURE_INDICATORS)
            return has_success and not has_failure
        return False

    for path in LOGIN_PATHS:
        endpoint = base + path
        # Probe with first cred to check if endpoint exists
        probe = _fetch(endpoint, combined, method="POST",
                       json={"username": "admin", "password": "____probe____"})
        if probe is None or probe.status_code in (404, 405):
            continue

        for username, password in DEFAULT_CREDS:
            r = _fetch(endpoint, combined, method="POST",
                       json={"username": username, "password": password,
                             "email": f"{username}@example.com"})
            if r is None:
                continue

            if _looks_successful(r):
                findings.append({
                    "name": "Default Credentials Accepted",
                    "type": "auth_misconfiguration", "risk": "Critical", "url": endpoint,
                    "description": (
                        f"The login endpoint accepted default credentials "
                        f"'{username}' / '{password}'. An attacker can gain immediate "
                        "access without any brute-force effort."
                    ),
                    "solution": "Change all default credentials immediately. Enforce strong password policy on first login.",
                    "evidence": {
                        "type":       "default_credentials",
                        "curl_poc":   (
                            f'curl -sk -X POST "{endpoint}" '
                            f'-H "Content-Type: application/json" '
                            f'-d \'{{"username":"{username}","password":"{password}"}}\''
                        ),
                        "username":   username,
                        "password":   password,
                        "status":     r.status_code,
                        "response_snippet": r.text[:300],
                    },
                })
                break  # one confirmed hit per endpoint is enough
        if findings:
            break  # stop after first confirmed vulnerable endpoint

    return findings


@register("WSTG-ATHN-05")
def probe_remember_password(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-ATHN-05: Test browser caching of credentials — checks for missing
    autocomplete="off" on password fields and login forms.
    """
    import html.parser

    class _FormParser(html.parser.HTMLParser):
        def __init__(self):
            super().__init__()
            self.password_inputs = []  # (autocomplete_attr,)
            self.forms_with_pass = []  # (form_autocomplete,)
            self._cur_form_ac = None

        def handle_starttag(self, tag, attrs):
            a = dict(attrs)
            if tag == "form":
                self._cur_form_ac = a.get("autocomplete", "").lower()
            if tag == "input" and a.get("type", "").lower() == "password":
                self.password_inputs.append(a.get("autocomplete", "").lower())
                self.forms_with_pass.append(self._cur_form_ac or "")

        def handle_endtag(self, tag):
            if tag == "form":
                self._cur_form_ac = None

    findings = []
    LOGIN_PATHS = ["/login", "/signin", "/admin/login", "/wp-login.php",
                   "/auth/login", "/account/login", "/user/login"]

    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    checked = set()
    targets = [url] + [base + p for p in LOGIN_PATHS]

    for target in targets:
        if target in checked:
            continue
        checked.add(target)
        r = _fetch(target, hdrs)
        if not r or r.status_code != 200:
            continue
        ct = r.headers.get("content-type", "")
        if "html" not in ct:
            continue

        parser = _FormParser()
        try:
            parser.feed(r.text)
        except Exception:
            continue

        for i, (pw_ac, form_ac) in enumerate(
                zip(parser.password_inputs, parser.forms_with_pass)):
            # Safe values: "off", "new-password", "current-password" (correct for existing-password fields)
            safe = pw_ac in ("off", "new-password", "current-password") or form_ac == "off"
            if not safe:
                findings.append({
                    "name": "Password Field Missing autocomplete=off",
                    "type": "web_vulnerability", "risk": "Low", "url": target,
                    "description": (
                        "A password input field does not set autocomplete=\"off\" or "
                        "autocomplete=\"new-password\". Browsers may cache credentials, "
                        "exposing them to other users on shared devices."
                    ),
                    "solution": (
                        'Add autocomplete="off" to the <form> or '
                        'autocomplete="current-password"/"new-password" to each password <input>.'
                    ),
                    "evidence": {
                        "type":          "autocomplete_missing",
                        "curl_poc":      _curl(target, hdrs),
                        "field_index":   i,
                        "field_autocomplete": pw_ac or "(not set)",
                        "form_autocomplete":  form_ac or "(not set)",
                    },
                })
        if findings:
            break  # one finding is enough to flag the issue

    return findings


@register("WSTG-ATHN-09")
def probe_password_reset_weakness(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-ATHN-09: Test password reset mechanism for weaknesses —
    token in response body, no rate limiting, and weak/short tokens.
    """
    parsed   = urlparse(url)
    base     = f"{parsed.scheme}://{parsed.netloc}"
    findings = []
    combined = {**hdrs, "Content-Type": "application/json"}

    RESET_PATHS = [
        "/forgot-password", "/forgot_password", "/password/reset",
        "/reset-password", "/auth/forgot", "/api/auth/forgot",
        "/api/v1/auth/forgot", "/account/forgot-password",
        "/user/forgot-password", "/password/forgot",
    ]

    FAKE_EMAIL = "probe_user_xyzzy_99@probe-domain-xyzzy.invalid"

    for path in RESET_PATHS:
        endpoint = base + path

        r = _fetch(endpoint, combined, method="POST",
                   json={"email": FAKE_EMAIL}, timeout=10)
        if r is None or r.status_code in (404, 405):
            continue

        body = r.text

        # ── token leaked in response body ─────────────────────────────────────
        token_patterns = [
            r'["\']?token["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{8,})["\']',
            r'["\']?reset_token["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{8,})["\']',
            r'["\']?code["\']?\s*[:=]\s*["\']([A-Za-z0-9]{6,})["\']',
        ]
        for pat in token_patterns:
            m = re.search(pat, body, re.I)
            if m:
                token_val = m.group(1)
                findings.append({
                    "name": "Password Reset Token Exposed in Response",
                    "type": "information_disclosure", "risk": "High", "url": endpoint,
                    "description": (
                        "The password reset endpoint returns the reset token directly "
                        "in the HTTP response body. An attacker who intercepts the "
                        "response can immediately reset any account."
                    ),
                    "solution": "Send reset tokens only via out-of-band channel (email). Never return them in the API response.",
                    "evidence": {
                        "type":             "token_in_response",
                        "curl_poc":         f'curl -sk -X POST "{endpoint}" -H "Content-Type: application/json" -d \'{{"email":"victim@example.com"}}\'',
                        "token_snippet":    token_val[:20] + "…",
                        "response_snippet": body[:300],
                    },
                })
                break

        # ── rate limiting check — send 5 rapid requests ───────────────────────
        statuses = [r.status_code]
        for _ in range(4):
            rr = _fetch(endpoint, combined, method="POST",
                        json={"email": FAKE_EMAIL}, timeout=10)
            if rr is not None:
                statuses.append(rr.status_code)

        all_ok = all(s not in (429, 423, 503) for s in statuses)

        if all_ok and len(statuses) >= 3:
            findings.append({
                "name": "No Rate Limiting on Password Reset",
                "type": "web_vulnerability", "risk": "Medium", "url": endpoint,
                "description": (
                    "The password reset endpoint accepted 5 rapid requests without "
                    "rate limiting or lockout. Attackers can flood reset emails or "
                    "brute-force short reset tokens."
                ),
                "solution": "Apply rate limiting (e.g. 3 requests per 15 minutes per IP/email) on password reset.",
                "evidence": {
                    "type":     "no_rate_limit",
                    "curl_poc": f'for i in $(seq 1 5); do curl -sk -X POST "{endpoint}" -H "Content-Type: application/json" -d \'{{"email":"victim@example.com"}}\'; done',
                    "statuses": statuses,
                },
            })

        if findings:
            break  # stop after first actionable endpoint

    return findings


# ── ATHZ — Authorization Testing ──────────────────────────────────────────────

@register("WSTG-ATHZ-01")
def probe_directory_traversal(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-ATHZ-01: Test directory traversal / path traversal.
    Appends traversal sequences to the URL path and common query parameters,
    then checks responses for filesystem file signatures.
    """
    parsed  = urlparse(url)
    base    = f"{parsed.scheme}://{parsed.netloc}"
    findings = []

    TRAVERSAL_SEQS = [
        # Standard sequences
        "../etc/passwd",
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        # URL-encoded slashes
        "..%2fetc%2fpasswd",
        "..%2F..%2Fetc%2Fpasswd",
        "%2e%2e%2fetc%2fpasswd",
        # Double URL-encoded (WAF bypass)
        "%252e%252e%252fetc%252fpasswd",
        "%252e%252e/%252e%252e/etc/passwd",
        # Null byte termination (bypass extension checks)
        "../etc/passwd%00",
        "../etc/passwd%00.jpg",
        # Windows
        "..\\..\\windows\\win.ini",
        "..%5c..%5cwindows%5cwin.ini",
        "%252e%252e%255cwindows%255cwin.ini",
    ]

    UNIX_SIG    = re.compile(r"root:[x*]?:\d+:\d+:")
    WIN_SIG     = re.compile(r"\[fonts\]", re.I)

    def _is_vuln(text: str) -> bool:
        return bool(UNIX_SIG.search(text) or WIN_SIG.search(text))

    def _finding(hit_url, seq, snippet):
        return {
            "name": "Directory Traversal",
            "type": "web_vulnerability", "risk": "High", "url": hit_url,
            "description": (
                f"Path traversal sequence '{seq}' returned filesystem content. "
                "An attacker can read arbitrary files from the server."
            ),
            "solution": (
                "Validate and canonicalize all file path inputs. "
                "Use allowlists for permitted files. Never concatenate user input into file paths."
            ),
            "evidence": {
                "type":             "directory_traversal",
                "curl_poc":         f'curl -sk "{hit_url}"',
                "traversal_seq":    seq,
                "response_snippet": snippet[:300],
            },
        }

    # ── 1. path-based traversal (append to URL path) ──────────────────────────
    for seq in TRAVERSAL_SEQS:
        target = base + "/" + seq
        r = _fetch(target, hdrs)
        if r and r.status_code == 200 and _is_vuln(r.text):
            findings.append(_finding(target, seq, r.text))
            break  # one path-based hit is sufficient; continue to param probing

    # ── 2. common query-parameter traversal ───────────────────────────────────
    PARAM_NAMES = ["file", "path", "page", "template", "doc", "filename",
                   "include", "load", "read", "view", "dir", "folder"]
    _path = parsed.path or "/"
    for param in PARAM_NAMES:
        for seq in TRAVERSAL_SEQS[:4]:  # top 4 are enough per param
            target = f"{parsed.scheme}://{parsed.netloc}{_path}?{param}={seq}"
            r = _fetch(target, hdrs)
            if r and r.status_code == 200 and _is_vuln(r.text):
                findings.append(_finding(target, seq, r.text))
                break  # one hit per param is enough; continue to next param

    return findings


@register("WSTG-ATHZ-04")
def probe_idor(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-ATHZ-04: Test for Insecure Direct Object References.
    Looks for numeric / UUID IDs in the URL path or query string,
    then probes adjacent IDs to check if access control is enforced.
    """
    parsed   = urlparse(url)
    findings = []

    # ── extract IDs from path segments ───────────────────────────────────────
    NUM_RE  = re.compile(r"^(\d+)$")
    UUID_RE = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
    )

    path_parts = [p for p in parsed.path.split("/") if p]
    candidate_indices = [i for i, p in enumerate(path_parts)
                         if NUM_RE.match(p) or UUID_RE.match(p)]

    def _swap_path_id(parts, idx, new_val):
        new_parts = parts[:]
        new_parts[idx] = str(new_val)
        return "/" + "/".join(new_parts)

    def _adjacent_nums(val):
        n = int(val)
        return [max(1, n - 1), n + 1, 1, 2, 9999]

    original_r = _fetch(url, hdrs)
    if original_r is None:
        return []
    orig_status = original_r.status_code
    orig_len    = len(original_r.text)

    # ── path ID probing ───────────────────────────────────────────────────────
    for idx in candidate_indices:
        part = path_parts[idx]
        if NUM_RE.match(part):
            probes = _adjacent_nums(part)
        else:
            # UUID: substitute a zeroed UUID
            probes = ["00000000-0000-0000-0000-000000000001"]

        for probe_val in probes:
            if str(probe_val) == part:
                continue
            new_path = _swap_path_id(path_parts, idx, probe_val)
            probe_url = urlunparse((
                parsed.scheme, parsed.netloc, new_path,
                parsed.params, parsed.query, ""
            ))
            r = _fetch(probe_url, hdrs)
            if r is None:
                continue
            # Treat as IDOR if adjacent ID returns 200 with similar body size
            if (r.status_code == 200 and orig_status == 200 and
                    abs(len(r.text) - orig_len) < orig_len * 0.5 and
                    orig_len > 50):
                findings.append({
                    "name": "Potential IDOR — Adjacent Object Accessible",
                    "type": "web_vulnerability", "risk": "High", "url": probe_url,
                    "description": (
                        f"Substituting the object ID '{part}' with '{probe_val}' "
                        "returned a 200 response with similar content. "
                        "Access control may not be enforced on this resource."
                    ),
                    "solution": (
                        "Verify ownership/permission for every object access. "
                        "Use indirect references or UUIDs, and enforce server-side authz checks."
                    ),
                    "evidence": {
                        "type":             "idor",
                        "curl_poc":         f'curl -sk "{probe_url}"',
                        "original_id":      part,
                        "probed_id":        str(probe_val),
                        "original_url":     url,
                        "original_status":  orig_status,
                        "probed_status":    r.status_code,
                        "original_length":  orig_len,
                        "probed_length":    len(r.text),
                    },
                })
                break  # one hit per path segment; continue to next segment

    # ── query-param ID probing ────────────────────────────────────────────────
    qs = parse_qs(parsed.query, keep_blank_values=True)
    for param, vals in qs.items():
        val = vals[0] if vals else ""
        if not NUM_RE.match(val):
            continue
        for probe_val in _adjacent_nums(val):
            if str(probe_val) == val:
                continue
            new_qs = {**qs, param: [str(probe_val)]}
            probe_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(new_qs, doseq=True), ""
            ))
            r = _fetch(probe_url, hdrs)
            if r is None:
                continue
            if (r.status_code == 200 and orig_status == 200 and
                    abs(len(r.text) - orig_len) < orig_len * 0.5 and
                    orig_len > 50):
                findings.append({
                    "name": "Potential IDOR — Query Parameter Object Accessible",
                    "type": "web_vulnerability", "risk": "High", "url": probe_url,
                    "description": (
                        f"Changing query parameter '{param}' from '{val}' to '{probe_val}' "
                        "returned a 200 response with similar content size. "
                        "Access control may not be enforced."
                    ),
                    "solution": (
                        "Enforce server-side authorization on all object lookups. "
                        "Validate that the requesting user owns or has access to the object."
                    ),
                    "evidence": {
                        "type":            "idor",
                        "curl_poc":        f'curl -sk "{probe_url}"',
                        "param":           param,
                        "original_val":    val,
                        "probed_val":      str(probe_val),
                        "original_status": orig_status,
                        "probed_status":   r.status_code,
                        "original_length": orig_len,
                        "probed_length":   len(r.text),
                    },
                })
                break  # one hit per query param; continue to next param

    return findings


# ── SESS — Session Management ──────────────────────────────────────────────────

@register("WSTG-SESS-01")
def probe_session_management_schema(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-SESS-01: Test session management schema.
    Makes two unauthenticated requests, captures any issued session tokens,
    and checks for weak entropy (short length, numeric-only, sequential patterns).
    """
    findings = []

    def _extract_tokens(response) -> list:
        """Return all candidate session token values from Set-Cookie headers."""
        tokens = []
        for hdr, val in response.headers.items():
            if hdr.lower() != "set-cookie":
                continue
            # parse cookie name=value
            m = re.match(r"([^=]+)=([^;]+)", val.strip())
            if not m:
                continue
            name, value = m.group(1).strip(), m.group(2).strip()
            if SESSION_NAMES.search(name):
                tokens.append((name, value))
        return tokens

    def _entropy_bits(token: str) -> float:
        """Estimate bits of entropy: len * log2(charset_size)."""
        if re.fullmatch(r"[0-9]+", token):
            charset = 10
        elif re.fullmatch(r"[0-9a-f]+", token, re.I):
            charset = 16
        elif re.fullmatch(r"[0-9a-zA-Z]+", token):
            charset = 62
        else:
            charset = 90
        return len(token) * math.log2(charset)

    # Collect two independent tokens
    r1 = _fetch(url, hdrs)
    r2 = _fetch(url, hdrs)
    if not r1 or not r2:
        return []

    tokens1 = _extract_tokens(r1)
    tokens2 = _extract_tokens(r2)

    if not tokens1:
        return []

    for (name, val1), (_, val2) in zip(tokens1, tokens2):
        bits = _entropy_bits(val1)

        # ── weak entropy: < 128 bits ──────────────────────────────────────────
        if bits < 128:
            findings.append({
                "name": "Weak Session Token Entropy",
                "type": "web_vulnerability", "risk": "High", "url": url,
                "description": (
                    f"Session token '{name}' has an estimated {bits:.0f} bits of entropy "
                    f"(value: '{val1[:30]}…'). OWASP requires at least 128 bits. "
                    "Low-entropy tokens are vulnerable to brute-force."
                ),
                "solution": "Use a CSPRNG to generate session tokens with at least 128 bits of entropy (e.g. 32 hex chars).",
                "evidence": {
                    "type":          "weak_entropy",
                    "curl_poc":      _curl(url, hdrs),
                    "cookie_name":   name,
                    "token_sample":  val1[:40],
                    "entropy_bits":  round(bits, 1),
                },
            })

        # ── numeric-only token ────────────────────────────────────────────────
        if re.fullmatch(r"[0-9]+", val1):
            findings.append({
                "name": "Numeric-Only Session Token",
                "type": "web_vulnerability", "risk": "High", "url": url,
                "description": (
                    f"Session token '{name}' is numeric-only ('{val1[:20]}…'). "
                    "Numeric tokens have very low entropy and are trivially enumerable."
                ),
                "solution": "Replace numeric session IDs with CSPRNG-generated alphanumeric tokens.",
                "evidence": {
                    "type":         "numeric_token",
                    "curl_poc":     _curl(url, hdrs),
                    "cookie_name":  name,
                    "token_sample": val1[:40],
                },
            })

        # ── sequential tokens: differ by ≤ 5 between requests ─────────────────
        if (re.fullmatch(r"[0-9]+", val1) and re.fullmatch(r"[0-9]+", val2)):
            try:
                diff = abs(int(val1) - int(val2))
                if 0 < diff <= 5:
                    findings.append({
                        "name": "Sequential Session Tokens Detected",
                        "type": "web_vulnerability", "risk": "Critical", "url": url,
                        "description": (
                            f"Two consecutive session tokens differ by only {diff}. "
                            "Tokens appear sequential and are trivially predictable — "
                            "an attacker can enumerate all valid sessions."
                        ),
                        "solution": "Use a CSPRNG; never derive session IDs from counters or timestamps.",
                        "evidence": {
                            "type":        "sequential_tokens",
                            "curl_poc":    _curl(url, hdrs),
                            "cookie_name": name,
                            "token_1":     val1,
                            "token_2":     val2,
                            "difference":  diff,
                        },
                    })
            except ValueError:
                pass

        # ── timestamp-embedded token (unix epoch in first 10 digits) ──────────
        if len(val1) >= 10 and re.match(r"1[5-9]\d{8}", val1):
            findings.append({
                "name": "Timestamp-Based Session Token",
                "type": "web_vulnerability", "risk": "Medium", "url": url,
                "description": (
                    f"Session token '{name}' appears to embed a Unix timestamp "
                    f"('{val1[:10]}…'). Timestamp-seeded tokens drastically reduce "
                    "the brute-force search space."
                ),
                "solution": "Do not seed session token generation with timestamps. Use a CSPRNG exclusively.",
                "evidence": {
                    "type":         "timestamp_token",
                    "curl_poc":     _curl(url, hdrs),
                    "cookie_name":  name,
                    "token_sample": val1[:40],
                },
            })

        if findings:
            break  # one finding set per token type is enough

    return findings


@register("WSTG-SESS-02")
def probe_cookie_attributes(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-SESS-02: Test session cookie security attributes
    (HttpOnly, Secure, SameSite).
    """
    resp = _fetch(url, hdrs)
    if resp is None:
        return []

    findings = []
    sensitive_kw = ("session", "auth", "token", "jwt", "sid", "csrf")
    all_cookies  = [v for k, v in resp.headers.items() if k.lower() == "set-cookie"]
    req_str      = _curl(url, hdrs)

    for cookie_str in all_cookies:
        cl = cookie_str.lower()
        if not any(k in cl for k in sensitive_kw):
            continue

        has_httponly = "httponly" in cl
        has_secure   = bool(re.search(r"(;|\s)secure(\s*;|$)", cl))
        has_samesite = "samesite" in cl
        samesite_m   = re.search(r"samesite\s*=\s*(\w+)", cl)
        samesite_val = samesite_m.group(1) if samesite_m else ""

        checks = [
            (not has_httponly, "Session Cookie Missing HttpOnly Flag", "High",
             "Cookie accessible via JavaScript — XSS can steal it.",
             "Set HttpOnly on all session cookies."),
            (not has_secure,   "Session Cookie Missing Secure Flag",   "Medium",
             "Cookie may be sent over plain HTTP — interception risk.",
             "Set Secure on all session cookies."),
            (not has_samesite, "Session Cookie Missing SameSite",      "Medium",
             "No SameSite attribute — CSRF attacks possible.",
             "Add SameSite=Strict or Lax to all session cookies."),
            (samesite_val == "none" and not has_secure,
             "Session Cookie SameSite=None Without Secure Flag", "High",
             "SameSite=None requires the Secure flag — without it, the cookie is sent "
             "over plain HTTP and cross-site, defeating the SameSite protection entirely.",
             "Always pair SameSite=None with the Secure flag."),
        ]
        for condition, name, risk, desc, sol in checks:
            if condition:
                findings.append({
                    "name": name, "type": "insecure_cookie",
                    "risk": risk, "url": url,
                    "description": desc, "solution": sol,
                    "evidence": {
                        "type": "insecure_cookie", "curl_poc": req_str,
                        "set_cookie": cookie_str[:300],
                    },
                })
    return findings


@register("WSTG-SESS-03", "WSTG-SESS-04")
def probe_session_in_url(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-SESS-03: Session fixation — detect session IDs in the URL.
    WSTG-SESS-04: Exposed session variables in query string.
    """
    session_params = {
        "sessionid", "session_id", "sessid", "sid", "jsessionid",
        "phpsessid", "asp.net_sessionid", "token", "auth_token",
    }
    parsed = urlparse(url)
    qs     = {k.lower(): v for k, v in parse_qs(parsed.query).items()}

    findings = []
    for param in session_params & qs.keys():
        findings.append({
            "name": "Session Token in URL",
            "type": "web_vulnerability", "risk": "High", "url": url,
            "description": (
                f"Session identifier '{param}' is in the URL query string. "
                "It appears in server logs, browser history, and Referer headers."
            ),
            "solution": "Store session tokens exclusively in HttpOnly, Secure cookies. Never in URLs.",
            "evidence": {
                "type": "session_in_url", "curl_poc": _curl(url, hdrs),
                "param": param,
            },
        })
    return findings


@register("WSTG-SESS-05")
def probe_csrf_protection(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-SESS-05: Check for CSRF protection via tokens in POST forms.
    """
    resp = _fetch(url, hdrs)
    if resp is None:
        return []
    if "html" not in resp.headers.get("content-type", ""):
        return []

    forms = re.findall(
        r"<form[^>]*method=[\"']?post[\"']?[^>]*>(.*?)</form>",
        resp.text, re.IGNORECASE | re.DOTALL
    )
    for form in forms:
        has_csrf = bool(re.search(
            r'name=["\'](_?csrf[_-]?token|_?token|csrf|authenticity_token|_wpnonce)["\']',
            form, re.IGNORECASE
        ))
        if not has_csrf:
            return [{
                "name": "CSRF Token Missing in POST Form",
                "type": "web_vulnerability", "risk": "High", "url": url,
                "description": (
                    "A POST form was found without a CSRF token. "
                    "Attackers can forge cross-site requests that execute actions as the victim."
                ),
                "solution": "Add a unique per-session CSRF token to every state-changing form and validate server-side.",
                "evidence": {
                    "type": "csrf_missing_token", "curl_poc": _curl(url, hdrs),
                    "form_snippet": form[:200].strip(),
                },
            }]
    return []


# ── INPV — Input Validation ────────────────────────────────────────────────────

@register("WSTG-INPV-01")
def probe_reflected_xss(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-INPV-01: Test for reflected XSS.
    Injects a unique canary into URL query parameters and checks if it
    appears unescaped in the HTML response.
    """
    parsed   = urlparse(url)
    findings = []

    CANARY   = "xss_probe_8472zq"
    PAYLOADS = [
        f'"><script>{CANARY}</script>',
        f"'><img src=x onerror={CANARY}>",
        f"<svg onload={CANARY}>",
        f"javascript:{CANARY}",
    ]

    REFLECT_RE = re.compile(re.escape(CANARY), re.I)

    def _check_params(target_url, inject_val):
        r = _fetch(target_url, hdrs)
        if r and REFLECT_RE.search(r.text):
            return r
        return None

    def _finding(hit_url, param, payload, snippet):
        return {
            "name": "Reflected XSS",
            "type": "web_vulnerability", "risk": "High", "url": hit_url,
            "description": (
                f"Parameter '{param}' reflects the injected payload "
                f"'{payload[:60]}' unescaped in the HTML response. "
                "An attacker can execute arbitrary JavaScript in the victim's browser."
            ),
            "solution": (
                "HTML-encode all user-supplied values before rendering them in responses. "
                "Apply a strict Content-Security-Policy."
            ),
            "evidence": {
                "type":             "reflected_xss",
                "curl_poc":         f'curl -sk -g "{hit_url}"',
                "param":            param,
                "payload":          payload,
                "response_snippet": snippet[:300],
            },
        }

    qs = parse_qs(parsed.query, keep_blank_values=True)

    # ── 1. inject into existing query params ──────────────────────────────────
    for param in list(qs.keys()):
        for payload in PAYLOADS:
            new_qs  = {**qs, param: [payload]}
            hit_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(new_qs, doseq=True), "",
            ))
            r = _check_params(hit_url, payload)
            if r:
                findings.append(_finding(hit_url, param, payload, r.text))
                break  # one payload hit per param; continue to next param

    # ── 2. inject into common params if no existing params in URL ─────────────
    COMMON_PARAMS = ["q", "s", "search", "query", "id", "name", "input",
                     "keyword", "term", "text", "page", "ref", "url"]
    base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
    for param in COMMON_PARAMS:
        for payload in PAYLOADS[:2]:
            hit_url = f"{base_url}?{param}={payload}"
            r = _check_params(hit_url, payload)
            if r:
                findings.append(_finding(hit_url, param, payload, r.text))
                break  # one payload hit per param; continue to next param

    return findings


@register("WSTG-INPV-04")
def probe_http_parameter_pollution(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-INPV-04: Test for HTTP Parameter Pollution.
    Sends duplicate query parameters and checks whether the server accepts
    an unexpected value, bypassing filters applied to the first occurrence.
    """
    parsed   = urlparse(url)
    findings = []

    qs = parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        return []

    CANARY = "hpp_probe_7391xz"

    for param, vals in qs.items():
        original_val = vals[0] if vals else ""
        # Build URL with original param first, then duplicate with canary
        base = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", ""
        ))
        polluted_url = f"{base}?{param}={original_val}&{param}={CANARY}"

        r_orig     = _fetch(url, hdrs)
        r_polluted = _fetch(polluted_url, hdrs)

        if not r_orig or not r_polluted:
            continue

        # Flag if: canary appears in response (server used the duplicate value)
        if CANARY in r_polluted.text:
            findings.append({
                "name": "HTTP Parameter Pollution",
                "type": "web_vulnerability", "risk": "Medium", "url": polluted_url,
                "description": (
                    f"Parameter '{param}' is vulnerable to HTTP Parameter Pollution. "
                    "The server processed the duplicate (injected) value instead of "
                    "the original, which can bypass input validation and WAF rules."
                ),
                "solution": (
                    "Accept only the first (or last) occurrence of each parameter. "
                    "Reject requests with duplicate parameter names."
                ),
                "evidence": {
                    "type":             "hpp",
                    "curl_poc":         f'curl -sk -g "{polluted_url}"',
                    "param":            param,
                    "original_val":     original_val,
                    "injected_val":     CANARY,
                    "response_snippet": r_polluted.text[:300],
                },
            })
            return findings

    return findings


@register("WSTG-INPV-05")
def probe_sql_injection(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-INPV-05: Test for SQL Injection.
    Three detection strategies: error-based, boolean-based, and time-based.
    """
    parsed   = urlparse(url)
    findings = []

    qs = parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        # No query params in URL — probe common parameter names with a neutral value.
        # Many SQLi-vulnerable endpoints use params like id, q, user even when the
        # base URL has none (e.g. /search, /product, /user).
        qs = {p: ["1"] for p in [
            "id", "q", "search", "user", "page", "item",
            "product", "category", "name", "ref",
        ]}

    def _make_url(param, value):
        new_qs = {**qs, param: [value]}
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(new_qs, doseq=True), "",
        ))

    def _finding(strategy, hit_url, param, payload, detail):
        return {
            "name": f"SQL Injection ({strategy})",
            "type": "web_vulnerability", "risk": "Critical", "url": hit_url,
            "description": (
                f"Parameter '{param}' appears vulnerable to SQL injection "
                f"({strategy} detection). {detail}"
            ),
            "solution": (
                "Use parameterised queries / prepared statements. "
                "Never concatenate user input into SQL strings."
            ),
            "evidence": {
                "type":     "sqli",
                "strategy": strategy,
                "curl_poc": f'curl -sk -g "{hit_url}"',
                "param":    param,
                "payload":  payload,
            },
        }

    for param, vals in qs.items():
        original = vals[0] if vals else ""

        # ── error-based ───────────────────────────────────────────────────────
        confirmed = False
        for payload in [f"{original}'", f"{original}\"", f"{original}';--"]:
            r = _fetch(_make_url(param, payload), hdrs)
            if r and SQL_ERRORS.search(r.text):
                findings.append(_finding(
                    "error-based", _make_url(param, payload), param, payload,
                    "A database error message was returned.",
                ))
                confirmed = True
                break
        if confirmed:
            continue

        # ── boolean-based ─────────────────────────────────────────────────────
        r_orig  = _fetch(url, hdrs)
        r_true  = _fetch(_make_url(param, f"{original} AND 1=1"), hdrs)
        r_false = _fetch(_make_url(param, f"{original} AND 1=2"), hdrs)

        if r_orig and r_true and r_false:
            len_orig  = len(r_orig.text)
            len_true  = len(r_true.text)
            len_false = len(r_false.text)
            # True condition ≈ original; false condition differs significantly
            if (abs(len_true - len_orig) < 50 and
                    abs(len_false - len_orig) > 100):
                payload = f"{original} AND 1=2"
                findings.append(_finding(
                    "boolean-based", _make_url(param, payload), param, payload,
                    "True/false conditions produce detectably different responses.",
                ))
                continue  # confirmed on this param; skip time-based, move to next param

        # ── time-based ────────────────────────────────────────────────────────
        t_base0  = time.monotonic()
        _fetch(_make_url(param, original), hdrs, timeout=20)
        baseline = time.monotonic() - t_base0
        threshold = max(4.5, baseline + 4.0)  # at least 4s above server baseline

        TIME_PAYLOADS = [
            f"{original}; WAITFOR DELAY '0:0:5'--",  # MSSQL
            f"{original}' AND SLEEP(5)--",            # MySQL
            f"{original}'; SELECT pg_sleep(5)--",    # PostgreSQL
            f"{original}' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",  # Oracle
        ]
        for payload in TIME_PAYLOADS:
            t0 = time.monotonic()
            r  = _fetch(_make_url(param, payload), hdrs, timeout=20)
            elapsed = time.monotonic() - t0
            if r and elapsed >= threshold:
                findings.append(_finding(
                    "time-based", _make_url(param, payload), param, payload,
                    f"Response delayed by {elapsed:.1f}s — blind time-based injection.",
                ))
                break  # one time-based hit per param; continue to next param

    return findings


@register("WSTG-INPV-15")
def probe_http_smuggling(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-INPV-15: Test for HTTP Request Smuggling (CL.TE and TE.CL).
    Sends an ambiguous request and looks for 400/500 errors or unexpected
    responses that indicate the front-end and back-end disagree on body length.
    """
    import socket
    import ssl

    parsed   = urlparse(url)
    host     = parsed.hostname or ""
    port     = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_ssl  = parsed.scheme == "https"
    path     = parsed.path or "/"
    findings = []

    def _raw_request(request_bytes, timeout=10):
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            if use_ssl:
                ctx  = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.sendall(request_bytes)
            resp = b""
            sock.settimeout(timeout)
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if b"\r\n\r\n" in resp:
                    break
            return resp.decode("utf-8", errors="replace")
        except Exception:
            return ""
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def _status(raw: str) -> int:
        try:
            return int(raw.split()[1])
        except Exception:
            return 0

    # ── CL.TE probe: Content-Length shorter than actual body ──────────────────
    cl_te = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 6\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n\r\n"
        f"0\r\n\r\nX"
    ).encode()

    # ── TE.CL probe: chunked body shorter than Content-Length ─────────────────
    te_cl = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n\r\n"
        f"1\r\nZ\r\n0\r\n\r\n"
    ).encode()

    for label, payload in [("CL.TE", cl_te), ("TE.CL", te_cl)]:
        raw = _raw_request(payload)
        status = _status(raw)
        # A 400 means the server correctly rejected the malformed request — that is safe.
        # Flag only 5xx responses, which indicate the server processed the ambiguous request unexpectedly.
        if status in (500, 501, 505):
            findings.append({
                "name": f"Potential HTTP Request Smuggling ({label})",
                "type": "web_vulnerability", "risk": "High", "url": url,
                "description": (
                    f"An ambiguous {label} request (conflicting Content-Length and "
                    f"Transfer-Encoding headers) returned HTTP {status}. "
                    "The server may be susceptible to HTTP request smuggling, which "
                    "can allow cache poisoning, session hijacking, or firewall bypass."
                ),
                "solution": (
                    "Configure the front-end proxy and back-end server to use the same "
                    "HTTP framing method. Reject requests with both CL and TE headers. "
                    "Use HTTP/2 end-to-end where possible."
                ),
                "evidence": {
                    "type":            "http_smuggling",
                    "variant":         label,
                    "response_status": status,
                    "response_snippet": raw[:300],
                },
            })
            break

    return findings


@register("WSTG-INPV-18")
def probe_ssti(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-INPV-18: Test for Server-Side Template Injection.
    Injects math expressions used by common template engines and checks
    whether the result is evaluated in the response.
    """
    parsed   = urlparse(url)
    findings = []

    # Payloads: (inject_string, expected_result_pattern, engine_hint)
    PAYLOADS = [
        ("{{7*7}}",          "49",       "Jinja2/Twig"),
        ("${7*7}",           "49",       "FreeMarker/Velocity"),
        ("#{7*7}",           "49",       "Ruby ERB / Spring"),
        ("<%= 7*7 %>",       "49",       "ERB/EJS"),
        ("{{7*'7'}}",        "7777777",  "Jinja2"),
        ("${{7*7}}",         "49",       "Pebble/Jinja"),
        ("{7*7}",            "49",       "Smarty"),
        ("*{7*7}",           "49",       "Spring SpEL"),
    ]

    qs = parse_qs(parsed.query, keep_blank_values=True)

    def _make_url(param, value):
        new_qs = {**qs, param: [value]}
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(new_qs, doseq=True), "",
        ))

    def _finding(hit_url, param, payload, engine, snippet):
        return {
            "name": f"Server-Side Template Injection ({engine})",
            "type": "web_vulnerability", "risk": "Critical", "url": hit_url,
            "description": (
                f"Parameter '{param}' evaluated the template expression '{payload}' "
                f"server-side ({engine}). SSTI can lead to full remote code execution."
            ),
            "solution": (
                "Never pass user input directly to a template engine. "
                "Use sandboxed rendering or escape all user-supplied data before templating."
            ),
            "evidence": {
                "type":             "ssti",
                "curl_poc":         f'curl -sk -g "{hit_url}"',
                "param":            param,
                "payload":          payload,
                "engine_hint":      engine,
                "response_snippet": snippet[:300],
            },
        }

    params_to_test = list(qs.keys()) or ["q", "search", "input", "name", "id"]
    base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))

    for param in params_to_test:
        for payload, expected, engine in PAYLOADS:
            if param in qs:
                hit_url = _make_url(param, payload)
            else:
                hit_url = f"{base_url}?{param}={payload}"
            r = _fetch(hit_url, hdrs)
            if r and expected in r.text:
                findings.append(_finding(hit_url, param, payload, engine, r.text))
                break  # one confirmed engine hit per param; continue to next param

    return findings


@register("WSTG-INPV-17")
def probe_host_header_injection(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-INPV-17: Test for Host Header Injection via X-Forwarded-Host.
    """
    evil_host = "probe-host-injection.invalid"
    inject = {**hdrs, "X-Forwarded-Host": evil_host, "X-Host": evil_host}
    r      = _fetch(url, inject, follow_redirects=False)
    if r is not None:
        body   = r.text
        rheads = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        if evil_host in body or evil_host in rheads:
            return [{
                "name": "Host Header Injection",
                "type": "web_vulnerability", "risk": "Medium", "url": url,
                "description": (
                    "Application reflects X-Forwarded-Host in its response. "
                    "Enables cache poisoning, password-reset hijacking, or SSRF."
                ),
                "solution": "Whitelist accepted Host values. Use deploy-time config for absolute URLs.",
                "evidence": {
                    "type": "host_injection",
                    "curl_poc": f'curl -sk -i -H "X-Forwarded-Host: {evil_host}" "{url}"',
                    "response_snippet": (body[:300] if evil_host in body else rheads[:300]),
                },
            }]
    return []


# ── ERRH — Error Handling ──────────────────────────────────────────────────────

@register("WSTG-ERRH-01", "WSTG-ERRH-02")
def probe_error_disclosure(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-ERRH-01: Analysis of error codes.
    WSTG-ERRH-02: Analysis of stack traces in HTTP responses.
    """
    resp = _fetch(url, hdrs)
    if resp is None:
        return []

    findings = []
    body = resp.text.lower()
    patterns = [
        ("sql syntax",        "SQL Error in Response",     "High",
         "SQL error message leaks database structure — possible SQLi indicator."),
        ("stack trace",       "Stack Trace Exposed",       "Medium",
         "Server-side stack trace reveals code paths and framework internals."),
        ("warning: mysql",    "MySQL Warning Exposed",     "High",
         "MySQL warning in HTTP response leaks database details."),
        ("fatal error",       "PHP Fatal Error Exposed",   "Medium",
         "PHP fatal error reveals file paths and application structure."),
        ("traceback (most",   "Python Traceback Exposed",  "Medium",
         "Python traceback in response reveals server-side code paths."),
        ("undefined index",   "PHP Notice Exposed",        "Low",
         "PHP notice reveals internal variable names."),
        ("microsoft ole db",  "OLE DB Error Exposed",      "High",
         "Microsoft OLE DB provider error reveals database technology."),
        ("odbc driver",       "ODBC Error Exposed",        "High",
         "ODBC driver error reveals database technology and structure."),
    ]
    for pattern, name, risk, desc in patterns:
        if pattern in body:
            findings.append({
                "name": name, "type": "information_disclosure",
                "risk": risk, "url": url,
                "description": desc,
                "solution": "Disable verbose errors in production. Return generic error pages.",
                "evidence": {
                    "type": "error_disclosure", "curl_poc": _curl(url, hdrs),
                    "response_snippet": resp.text[:400],
                },
            })
    return findings


# ── CRYP — Cryptography ───────────────────────────────────────────────────────

@register("WSTG-CRYP-01")
def probe_weak_tls(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-CRYP-01: Test for weak TLS protocols and ciphers.
    Connects via ssl and inspects negotiated protocol version and cipher suite.
    """
    import ssl, socket

    parsed = urlparse(url)
    if parsed.scheme != "https":
        return []

    host = parsed.hostname or ""
    port = parsed.port or 443
    findings = []

    WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
    WEAK_CIPHER_KW = ["RC4", "DES", "3DES", "EXPORT", "NULL", "ANON", "MD5",
                      "ADH", "AECDH", "aNULL", "eNULL"]

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                proto  = ssock.version()          # e.g. "TLSv1.2"
                cipher = ssock.cipher()           # (name, protocol, bits)
                cert   = ssock.getpeercert()

        cipher_name = cipher[0] if cipher else ""
        cipher_bits = cipher[2] if cipher else 0

        # ── weak protocol ────────────────────────────────────────────────────
        if proto in WEAK_PROTOCOLS:
            findings.append({
                "name": f"Weak TLS Protocol: {proto}",
                "type": "ssl_error", "risk": "High", "url": url,
                "description": (
                    f"The server negotiated {proto}, which is considered cryptographically "
                    "weak and vulnerable to known attacks (BEAST, POODLE, etc.)."
                ),
                "solution": "Disable TLS 1.0 and 1.1. Support TLS 1.2 and TLS 1.3 only.",
                "evidence": {
                    "type":        "weak_tls_protocol",
                    "curl_poc":    f'curl -sk --tlsv1 "{url}"',
                    "protocol":    proto,
                    "cipher":      cipher_name,
                },
            })

        # ── weak cipher ──────────────────────────────────────────────────────
        if any(kw.lower() in cipher_name.lower() for kw in WEAK_CIPHER_KW):
            findings.append({
                "name": f"Weak TLS Cipher: {cipher_name}",
                "type": "ssl_error", "risk": "High", "url": url,
                "description": (
                    f"The negotiated cipher suite '{cipher_name}' is considered weak. "
                    "Weak ciphers can be exploited to decrypt traffic."
                ),
                "solution": "Configure the server to prefer AEAD ciphers (AES-GCM, ChaCha20). Disable RC4, DES, 3DES, EXPORT, and NULL ciphers.",
                "evidence": {
                    "type":        "weak_cipher",
                    "curl_poc":    f'curl -sk --ciphers "{cipher_name}" "{url}"',
                    "cipher_name": cipher_name,
                    "cipher_bits": cipher_bits,
                },
            })

        # ── short key length ─────────────────────────────────────────────────
        if cipher_bits and cipher_bits < 128:
            findings.append({
                "name": f"Short TLS Key Length: {cipher_bits} bits",
                "type": "ssl_error", "risk": "Medium", "url": url,
                "description": (
                    f"The negotiated cipher uses only {cipher_bits}-bit keys, "
                    "which is below the recommended minimum of 128 bits."
                ),
                "solution": "Use cipher suites with at least 128-bit key strength.",
                "evidence": {
                    "type":        "short_key",
                    "curl_poc":    f'curl -sk "{url}"',
                    "cipher_name": cipher_name,
                    "cipher_bits": cipher_bits,
                },
            })

        # ── expired or self-signed cert ──────────────────────────────────────
        # Use a separate CERT_REQUIRED context — getpeercert() always returns {}
        # with CERT_NONE (falsy), so cert presence cannot be used here.
        try:
            ctx_valid = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock_v:
                with ctx_valid.wrap_socket(sock_v, server_hostname=host):
                    pass  # handshake succeeded — cert is valid
        except ssl.SSLCertVerificationError as cert_err:
            findings.append({
                "name": "TLS Certificate Validation Failed",
                "type": "ssl_error", "risk": "High", "url": url,
                "description": f"The server presented an invalid, self-signed, or expired TLS certificate: {cert_err}.",
                "solution": "Install a valid certificate from a trusted CA. Use Let's Encrypt for free certificates.",
                "evidence": {
                    "type":     "invalid_cert",
                    "curl_poc": f'curl -v "{url}" 2>&1 | grep -i "certificate"',
                    "error":    str(cert_err),
                },
            })
        except Exception:
            pass

    except ssl.SSLError as e:
        findings.append({
            "name": "TLS Configuration Error",
            "type": "ssl_error", "risk": "Medium", "url": url,
            "description": f"SSL handshake failed: {e}. The server may have a misconfigured TLS stack.",
            "solution": "Review server TLS configuration. Ensure a valid certificate and supported cipher suites are configured.",
            "evidence": {"type": "ssl_error", "error": str(e)},
        })
    except Exception:
        pass

    return findings


# ── BUSL — Business Logic Testing ─────────────────────────────────────────────

@register("WSTG-BUSL-08")
def probe_file_upload(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-BUSL-08: Test for unrestricted file upload.
    Discovers upload endpoints and attempts to upload a minimal PHP file
    with a spoofed image Content-Type and a double-extension filename.
    """
    parsed   = urlparse(url)
    base     = f"{parsed.scheme}://{parsed.netloc}"
    findings = []

    UPLOAD_PATHS = [
        "/upload", "/api/upload", "/file/upload", "/files/upload",
        "/media/upload", "/image/upload", "/avatar/upload",
        "/api/v1/upload", "/api/files", "/upload/file",
        "/admin/upload", "/wp-admin/async-upload.php",
    ]

    MINIMAL_PHP = b"<?php echo 'probe_7391'; ?>"

    def _find_upload_endpoint():
        for path in UPLOAD_PATHS:
            endpoint = base + path
            r = _fetch(endpoint, hdrs, timeout=6)
            if r is not None and r.status_code not in (404, 410):
                return endpoint
            r = _fetch(endpoint, hdrs, method="POST", timeout=6)
            if r is not None and r.status_code not in (404, 410, 405):
                return endpoint
        return None

    def _try_upload(endpoint, filename, content_type, file_bytes):
        files = {"file": (filename, file_bytes, content_type)}
        return _fetch(endpoint, hdrs, method="POST",
                      files=files, timeout=10)

    def _upload_accepted(r) -> bool:
        if r is None:
            return False
        if r.status_code in (200, 201):
            body = r.text.lower()
            return any(k in body for k in ["url", "path", "filename", "uploaded",
                                           "success", "file_id", "location"])
        return False

    endpoint = _find_upload_endpoint()
    if not endpoint:
        return []

    # ── attempt 1: PHP file with image/jpeg MIME type ─────────────────────────
    r1 = _try_upload(endpoint, "probe_test.php", "image/jpeg", MINIMAL_PHP)
    if _upload_accepted(r1):
        findings.append({
            "name": "Unrestricted File Upload — PHP via MIME Bypass",
            "type": "web_vulnerability", "risk": "Critical", "url": endpoint,
            "description": (
                "The upload endpoint accepted a PHP file disguised with an image/jpeg "
                "Content-Type. If the file is served by the web server, this leads to "
                "Remote Code Execution."
            ),
            "solution": (
                "Validate file type by magic bytes, not Content-Type. "
                "Store uploads outside the web root or serve via a dedicated storage service. "
                "Block execution of uploaded files."
            ),
            "evidence": {
                "type":             "file_upload_php_mime",
                "curl_poc":         (
                    f'curl -sk -X POST "{endpoint}" '
                    f'-F "file=@shell.php;type=image/jpeg"'
                ),
                "filename":         "probe_test.php",
                "response_snippet": (r1.text[:300] if r1 else ""),
            },
        })
        return findings

    # ── attempt 2: double-extension filename ──────────────────────────────────
    r2 = _try_upload(endpoint, "probe_test.php.jpg", "image/jpeg", MINIMAL_PHP)
    if _upload_accepted(r2):
        findings.append({
            "name": "Unrestricted File Upload — Double Extension Bypass",
            "type": "web_vulnerability", "risk": "High", "url": endpoint,
            "description": (
                "The upload endpoint accepted a file named 'probe_test.php.jpg'. "
                "Some web servers execute such files as PHP depending on configuration."
            ),
            "solution": (
                "Strip all extensions and assign a safe one after validating file content. "
                "Disable execution of uploaded files."
            ),
            "evidence": {
                "type":             "file_upload_double_ext",
                "curl_poc":         (
                    f'curl -sk -X POST "{endpoint}" '
                    f'-F "file=@shell.php.jpg;type=image/jpeg"'
                ),
                "filename":         "probe_test.php.jpg",
                "response_snippet": (r2.text[:300] if r2 else ""),
            },
        })

    return findings


# ── CLNT — Client-Side Testing ─────────────────────────────────────────────────

@register("WSTG-CLNT-03")
def probe_html_injection(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-CLNT-03: Test for HTML injection.
    Injects benign HTML tags into query parameters and checks if they are
    reflected unescaped in the response (distinct from script-based XSS).
    """
    parsed   = urlparse(url)
    findings = []

    CANARY   = "htmlinj_probe_5821"
    PAYLOADS = [
        f"<b>{CANARY}</b>",
        f"<i>{CANARY}</i>",
        f"<h1>{CANARY}</h1>",
        f'<a href="http://probe.invalid">{CANARY}</a>',
    ]

    qs = parse_qs(parsed.query, keep_blank_values=True)

    def _make_url(param, value):
        new_qs = {**qs, param: [value]}
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(new_qs, doseq=True), "",
        ))

    params_to_test = list(qs.keys()) or ["q", "search", "input", "name", "text"]
    base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))

    for param in params_to_test:
        for payload in PAYLOADS:
            if param in qs:
                hit_url = _make_url(param, payload)
            else:
                hit_url = f"{base_url}?{param}={payload}"
            r = _fetch(hit_url, hdrs)
            if r and CANARY in r.text and payload in r.text:
                findings.append({
                    "name": "HTML Injection",
                    "type": "web_vulnerability", "risk": "Medium", "url": hit_url,
                    "description": (
                        f"Parameter '{param}' reflects injected HTML tags unescaped. "
                        "An attacker can inject arbitrary HTML to deface the page, "
                        "phish users, or redirect them to malicious sites."
                    ),
                    "solution": (
                        "HTML-encode all user input before rendering it in responses. "
                        "Apply a Content-Security-Policy."
                    ),
                    "evidence": {
                        "type":             "html_injection",
                        "curl_poc":         f'curl -sk -g "{hit_url}"',
                        "param":            param,
                        "payload":          payload,
                        "response_snippet": r.text[:300],
                    },
                })
                return findings

    return findings


@register("WSTG-CLNT-04")
def probe_open_redirect(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-CLNT-04: Test for client-side URL redirect (open redirect).
    """
    parsed   = urlparse(url)
    evil_url = "https://evil.com"
    base     = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"

    redirect_params = [
        "url", "redirect", "redirect_url", "redirect_uri", "return",
        "returnUrl", "return_url", "next", "goto", "target", "dest",
        "destination", "redir", "ref", "continue", "callback",
    ]

    def _test(param):
        test_url = f"{base}?{param}={evil_url}"
        r        = _fetch(test_url, hdrs, follow_redirects=False)
        if r is not None:
            location = r.headers.get("location", "")
            loc_host = urlparse(location).netloc
            if r.status_code in (301, 302, 303, 307, 308) and (
                    loc_host == "evil.com" or loc_host.endswith(".evil.com")):
                return {
                    "name": "Open Redirect",
                    "type": "web_vulnerability", "risk": "Medium", "url": test_url,
                    "param": param,
                    "description": (
                        f"Parameter '{param}' accepts external URLs as redirect targets. "
                        "Attackers can craft phishing links from the trusted domain."
                    ),
                    "solution": "Validate redirect destinations against an allowlist. Reject external URLs.",
                    "evidence": {
                        "type": "open_redirect", "param": param,
                        "curl_poc": f'curl -sk -i "{test_url}"',
                        "response_snippet": f"HTTP {r.status_code}\nLocation: {location}",
                    },
                }
        return None

    findings = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        for result in ex.map(_test, redirect_params):
            if result:
                findings.append(result)
                break  # one confirmed redirect per target is enough
    return findings


@register("WSTG-CLNT-07")
def probe_cors(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-CLNT-07: Test Cross-Origin Resource Sharing policy.
    Checks wildcard origin, reflected arbitrary origin, null origin, and
    credentials with permissive origin.
    """
    evil_origin = "https://cors-probe.evil.com"
    findings = []

    r = _fetch(url, {**hdrs, "Origin": evil_origin})
    if r is not None:
        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "")

        if acao == "*":
            findings.append({
                "name": "CORS Wildcard Origin",
                "type": "web_vulnerability", "risk": "Medium", "url": url,
                "description": "ACAO: * permits any origin to make cross-origin requests.",
                "solution": "Restrict CORS to a specific list of trusted origins.",
                "evidence": {
                    "type": "cors_wildcard",
                    "curl_poc": f'curl -sk -H "Origin: https://evil.com" "{url}" -I',
                    "response_snippet": f"Access-Control-Allow-Origin: {acao}",
                },
            })
        elif acao == evil_origin:
            risk = "High" if acac.lower() == "true" else "Medium"
            desc = "Server reflects caller's Origin verbatim in ACAO. "
            if acac.lower() == "true":
                desc += "With Allow-Credentials: true, authenticated cross-origin attacks are possible."
            findings.append({
                "name": "CORS: Arbitrary Origin Reflected",
                "type": "web_vulnerability", "risk": risk, "url": url,
                "description": desc,
                "solution": "Maintain an explicit origin allowlist. Never reflect request Origin directly.",
                "evidence": {
                    "type": "cors_reflected",
                    "curl_poc": f'curl -sk -i -H "Origin: {evil_origin}" "{url}"',
                    "response_snippet": f"ACAO: {acao}\nACAC: {acac}",
                },
            })

    # Null origin — sent by sandboxed iframes and file:// pages; some servers
    # reflect it back, allowing any sandboxed page to make credentialed requests.
    r_null = _fetch(url, {**hdrs, "Origin": "null"})
    if r_null is not None:
        acao_null = r_null.headers.get("access-control-allow-origin", "")
        acac_null = r_null.headers.get("access-control-allow-credentials", "")
        if acao_null == "null":
            risk = "High" if acac_null.lower() == "true" else "Medium"
            desc = "Server accepts Origin: null — sent by sandboxed iframes and data URIs. "
            if acac_null.lower() == "true":
                desc += "With Allow-Credentials: true, any sandboxed page can make authenticated cross-origin requests."
            findings.append({
                "name": "CORS: Null Origin Accepted",
                "type": "web_vulnerability", "risk": risk, "url": url,
                "description": desc,
                "solution": "Remove 'null' from the CORS origin allowlist. Never reflect the null origin.",
                "evidence": {
                    "type": "cors_null_origin",
                    "curl_poc": f'curl -sk -i -H "Origin: null" "{url}"',
                    "response_snippet": f"ACAO: {acao_null}\nACAC: {acac_null}",
                },
            })

    return findings


@register("WSTG-INFO-04")
def probe_graphql_introspection(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-INFO-04: Enumerate application endpoints — detect GraphQL with introspection enabled.
    """
    parsed    = urlparse(url)
    base      = f"{parsed.scheme}://{parsed.netloc}"
    endpoints = ["/graphql", "/api/graphql", "/graphql/v1",
                 "/v1/graphql", "/api/v1/graphql", "/query", "/gql"]
    iq = '{"query":"{ __schema { queryType { name } } }"}'

    def _probe(path):
        ep = base + path
        r  = _fetch(ep, {**hdrs, "Content-Type": "application/json"},
                    method="POST", content=iq, follow_redirects=False)
        if r is not None and r.status_code == 200:
            try:
                data = r.json()
                if isinstance(data.get("data"), dict) and "__schema" in data.get("data", {}):
                    return {
                            "name": "GraphQL Introspection Enabled",
                            "type": "information_disclosure", "risk": "Medium", "url": ep,
                            "description": (
                                "GraphQL introspection enabled in production — attackers can enumerate "
                                "all types, queries, mutations, and arguments."
                            ),
                            "solution": "Disable introspection in production environments.",
                            "evidence": {
                                "type": "graphql_introspection",
                                "curl_poc": (
                                    f'curl -sk -X POST -H "Content-Type: application/json" '
                                    f"-d '{iq}' \"{ep}\""
                                ),
                                "response_snippet": r.text[:300],
                            },
                        }
            except Exception:
                pass
        return None

    findings = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        for result in ex.map(_probe, endpoints):
            if result:
                findings.append(result)
                break
    return findings


@register("WSTG-CLNT-13")
def probe_xssi(url: str, hdrs: dict, config=None) -> list:
    """
    WSTG-CLNT-13: Test for Cross-Site Script Inclusion (XSSI).
    Checks JSON/API endpoints for JSONP callbacks, JSON array responses
    (includable via <script>), and missing JSON security prefixes.
    """
    parsed   = urlparse(url)
    base     = f"{parsed.scheme}://{parsed.netloc}"
    findings = []

    API_PATHS = [
        "/api/user", "/api/me", "/api/profile", "/api/account",
        "/api/users", "/api/data", "/api/v1/user", "/api/v1/me",
        "/user.json", "/profile.json", "/account.json",
    ]

    ARRAY_RE          = re.compile(r"^\s*\[")
    PREFIX_RE         = re.compile(r"^\s*(\)\]\}',?|for\s*\(;;|while\s*\(1\)|/\*)")

    def _check_endpoint(endpoint):
        local = []

        # ── 1. JSONP callback parameter ───────────────────────────────────────
        for cb_param in ["callback", "jsonp", "cb", "json_callback"]:
            cb_url = f"{endpoint}?{cb_param}=xssi_probe_cb"
            r = _fetch(cb_url, {**hdrs, "Accept": "application/json"})
            if r and "xssi_probe_cb(" in r.text:
                local.append({
                    "name": "JSONP Endpoint Exposed",
                    "type": "web_vulnerability", "risk": "High", "url": cb_url,
                    "description": (
                        f"The endpoint supports JSONP via the '{cb_param}' parameter. "
                        "Any page on any origin can include this as a <script> tag and "
                        "read the JSON response, leaking authenticated user data."
                    ),
                    "solution": (
                        "Remove JSONP support. Use CORS with explicit allowed origins instead. "
                        "If JSONP is required, validate the callback name strictly."
                    ),
                    "evidence": {
                        "type":             "jsonp",
                        "curl_poc":         f'curl -sk "{cb_url}"',
                        "param":            cb_param,
                        "response_snippet": r.text[:300],
                    },
                })
                return local

        # ── 2. JSON array response without security prefix ────────────────────
        r = _fetch(endpoint, {**hdrs, "Accept": "application/json"})
        if not r or r.status_code != 200:
            return local
        ct = r.headers.get("content-type", "")
        if "json" not in ct and "javascript" not in ct:
            return local

        body = r.text.strip()
        if ARRAY_RE.match(body) and not PREFIX_RE.match(body):
            local.append({
                "name": "JSON Array Response — XSSI Risk",
                "type": "web_vulnerability", "risk": "Medium", "url": endpoint,
                "description": (
                    "This endpoint returns a top-level JSON array without an XSSI "
                    "protection prefix (e.g. )]}', while(1);). "
                    "Older browsers allow cross-origin <script> inclusion of JSON arrays, "
                    "enabling data theft via overriding Array constructors."
                ),
                "solution": (
                    "Prefix all JSON responses with )]}',\n or while(1); "
                    "and strip it client-side. Alternatively, return JSON objects, not arrays."
                ),
                "evidence": {
                    "type":             "json_array",
                    "curl_poc":         f'curl -sk -H "Accept: application/json" "{endpoint}"',
                    "response_snippet": body[:300],
                },
            })

        return local

    # Check target URL itself + common API paths
    targets = [url] + [base + p for p in API_PATHS]
    for target in targets:
        result = _check_endpoint(target)
        if result:
            findings.extend(result)
            break

    return findings
