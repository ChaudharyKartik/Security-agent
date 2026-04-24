"""
Vulnerability Enrichment Module
- Real CVSS 3.1 dynamic scoring (via cvss.py, not static maps)
- Per-finding attacker exploitation narrative
- Compliance tagging
- Deduplication
"""
import hashlib
import logging
from datetime import datetime

from cvss import calculate_cvss, cvss_from_finding_type, CVSSMetrics

logger = logging.getLogger(__name__)

COMPLIANCE_MAP = {
    "missing_security_header":  ["OWASP A05:2021", "PCI-DSS 6.2"],
    "insecure_cookie":          ["OWASP A02:2021", "PCI-DSS 6.2"],
    "web_vulnerability":        ["OWASP Top 10",   "NIST SP 800-53 SI-10"],
    "open_port":                ["CIS Controls 4.4","NIST SP 800-53 CM-7"],
    "vulnerable_version":       ["CVE Program",    "NIST SP 800-53 SI-2"],
    "auth_misconfiguration":    ["OWASP A07:2021", "CIS Controls 5.2"],
    "cloud_misconfiguration":   ["CIS AWS Benchmark","NIST CSF PR.AC"],
    "information_disclosure":   ["OWASP A05:2021", "PCI-DSS 6.5"],
    "ssl_error":                ["OWASP A02:2021", "PCI-DSS 4.1"],
}

SEVERITY_ORDER = {"Critical":0,"High":1,"Medium":2,"Low":3,"Info":4}
# NOTE: "Informational" is intentionally absent — _normalize_severity() maps it
# to "Info" before any sort/count, so we never have a duplicate key ambiguity.


def enrich_findings(all_module_results: list) -> list:
    logger.info("[ENRICHMENT] Starting enrichment...")
    enriched, seen = [], set()

    for module_result in all_module_results:
        module_name = module_result.get("module","unknown")
        target      = module_result.get("target","")
        tool_used   = module_result.get("tool_used","")
        raw_findings = module_result.get("findings",[])
        logger.info(f"[ENRICHMENT] {module_name}: {len(raw_findings)} raw findings")
        for finding in raw_findings:
            try:
                ef = _enrich_single(finding, module_name, target, tool_used)
                if ef["id"] not in seen:
                    seen.add(ef["id"])
                    enriched.append(ef)
                else:
                    logger.debug(f"[ENRICHMENT] Deduplicated: {ef['id']} ({ef.get('name','')})")
            except Exception as e:
                logger.warning(f"[ENRICHMENT] Skipping finding '{finding.get('name','?')}' "
                               f"in {module_name}: {e}")

    enriched.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity","Info"),99))
    logger.info(f"[ENRICHMENT] Done — {len(enriched)} unique findings enriched.")
    return enriched


def _enrich_single(finding: dict, module_name: str, target: str, tool_used: str) -> dict:
    ftype = finding.get("type", "unknown")

    # ── Real CVSS 3.1 calculation ─────────────────────────────────────────────
    cvss_metrics = cvss_from_finding_type(ftype, finding)
    cvss_result  = calculate_cvss(cvss_metrics)

    # Allow finding to override individual CVSS metrics if it specifies them
    if finding.get("cvss_override"):
        try:
            override = finding["cvss_override"]
            m = CVSSMetrics(**override)
            cvss_result = calculate_cvss(m)
        except Exception:
            pass

    severity = cvss_result["severity"]
    # Normalise CVSS severity to canonical set (collapse "Informational" → "Info")
    severity = _normalize_severity(severity)

    # Re-check: if the finding itself already carries a higher risk signal, bump up
    raw_risk   = finding.get("risk", "Info")
    stated_sev = _normalize_severity(raw_risk)
    if SEVERITY_ORDER.get(stated_sev, 99) < SEVERITY_ORDER.get(severity, 99):
        severity = stated_sev  # keep the higher (lower order number = higher severity)

    # ── Confidence scoring (heuristic — Phase 2) ──────────────────────────────
    confidence = _calculate_confidence(finding, tool_used, cvss_result)

    return {
        "id":                  _generate_id(finding, module_name),
        "name":                finding.get("name", _infer_name(finding)),
        "type":                ftype,
        "module":              module_name,
        "tool_used":           tool_used,
        "target":              target,
        "severity":            severity,
        "checklist_id":        finding.get("checklist_id"),
        "session_id":          finding.get("session_id"),   # injected by orchestrator

        # Real CVSS 3.1
        "cvss_score":           cvss_result["score"],
        "cvss_vector":          cvss_result["vector"],
        "cvss_metrics":         cvss_result["metrics"],
        "exploitability_score": cvss_result["exploitability_score"],
        "impact_score":         cvss_result["impact_score"],

        # Confidence (0.0 – 1.0 heuristic; replaced by LLM in Phase 3)
        "confidence_score":     confidence,

        # Human-readable exploitability
        "exploitability":       _exploitability_label(cvss_result["score"]),
        "exploit_available":    severity in ("Critical", "High"),
        "attack_complexity":    cvss_result["metrics"]["AC"],
        "privileges_required":  cvss_result["metrics"]["PR"],

        # Core finding data
        "description":          finding.get("description", ""),
        "solution":             finding.get("solution", ""),
        "url":                  finding.get("url", finding.get("host", target)),
        "port":                 finding.get("port"),
        "service":              finding.get("service"),
        "cve":                  finding.get("cve"),
        "cwe":                  finding.get("cwe"),

        # PoC evidence block (passed through from agent)
        "evidence":             finding.get("evidence", {}),

        # Developer-facing reproduction steps (numbered list)
        "reproduction_steps":  _generate_reproduction_steps(finding, ftype, target),

        # Attacker narrative
        "exploitation_narrative": _build_exploitation_narrative(finding, severity, ftype, target),
        "analyst_note":           _generate_analyst_note(finding, severity, module_name),

        # Compliance & metadata
        "compliance":          finding.get("compliance", COMPLIANCE_MAP.get(ftype, [])),
        "enriched_at":         datetime.utcnow().isoformat(),
        "validation_status":   "pending",
        "validated_by":        None,
        "false_positive":      False,
    }


def _normalize_severity(raw: str) -> str:
    return {"critical":"Critical","high":"High","medium":"Medium","moderate":"Medium",
            "low":"Low","info":"Info","informational":"Info","none":"Info"}.get(str(raw).lower(),"Info")


def _calculate_confidence(finding: dict, tool_used: str, cvss_result: dict) -> float:
    """
    Heuristic confidence score (0.0 – 1.0) based on evidence quality signals.
    Phase 3 will replace this with LLM-based reasoning.

    Signal weights:
      +0.20  Real tool (ZAP/Nmap/Prowler/Nuclei), not mock/probe
      +0.20  Evidence has both raw_request + response snippet
      +0.10  Evidence has a curl PoC command
      +0.15  CVSS score >= 7.0 (well-understood, high-signal finding class)
      +0.15  Finding type with reliable detection (port scan, header, cookie)
      +0.10  Has a CVE reference
      +0.05  Has a CWE reference
      +0.05  Evidence has a response snippet/body
    """
    score = 0.0
    evidence = finding.get("evidence") or {}

    # Real tool used (not probe/mock)
    real_tools = {"zap", "nmap", "nuclei", "sqlmap", "prowler", "openvas"}
    t = (tool_used or "").lower()
    if any(rt in t for rt in real_tools):
        score += 0.20

    # Evidence completeness
    has_request  = bool(evidence.get("request") or evidence.get("raw_request"))
    has_response = bool(evidence.get("response_snippet") or evidence.get("response_headers")
                        or evidence.get("raw_response"))
    if has_request and has_response:
        score += 0.20
    elif has_request or has_response:
        score += 0.10

    # PoC command present
    if evidence.get("curl_poc"):
        score += 0.10

    # High CVSS score = well-understood vulnerability class
    if cvss_result.get("score", 0) >= 7.0:
        score += 0.15
    elif cvss_result.get("score", 0) >= 4.0:
        score += 0.07

    # Finding type with reliable detection patterns
    reliable_types = {
        "open_port",            # port scanner result — hard to false-positive
        "missing_security_header",  # deterministic HTTP header check
        "insecure_cookie",      # deterministic attribute check
        "ssl_error",            # deterministic TLS check
        "information_disclosure",   # deterministic response body check
    }
    if finding.get("type") in reliable_types:
        score += 0.15

    # CVE / CWE reference
    if finding.get("cve"):
        score += 0.10
    if finding.get("cwe"):
        score += 0.05

    return round(min(score, 1.0), 2)


def _exploitability_label(score: float) -> str:
    if score >= 9.0: return "Easily Exploitable — Active exploits exist"
    if score >= 7.0: return "Exploitable — Exploit code available"
    if score >= 4.0: return "Moderately Exploitable — Requires some conditions"
    if score >= 0.1: return "Difficult to Exploit — Limited conditions"
    return "Not Directly Exploitable"


def _generate_id(finding: dict, module: str) -> str:
    from urllib.parse import urlparse

    name  = finding.get("name", "")
    ftype = finding.get("type", "")
    raw   = finding.get("url", "") or str(finding.get("port", ""))

    # Site-wide issues (missing headers, cookie flags, SSL) are the same finding
    # regardless of which page ZAP crawled — collapse to host level so 20 alerts
    # for "CSP Missing" on 20 pages don't all become separate report entries.
    _host_level = {"missing_security_header", "insecure_cookie", "ssl_error",
                   "information_disclosure", "auth_misconfiguration"}
    if ftype in _host_level:
        try:
            p = urlparse(raw)
            url = f"{p.scheme}://{p.netloc}" if p.netloc else raw
        except Exception:
            url = raw
    else:
        url = raw

    # Include param for web vulns so SQLi on ?user= and ?pass= stay separate
    param = finding.get("param", "") if ftype == "web_vulnerability" else ""
    key   = f"{module}_{name}_{url}_{param}"
    return "FIND-" + hashlib.md5(key.encode()).hexdigest()[:8].upper()


def _infer_name(finding: dict) -> str:
    if finding.get("type") == "open_port":
        return f"Open Port: {finding.get('port')}/{finding.get('service','unknown')}"
    return finding.get("type","Unknown Finding").replace("_"," ").title()


def _generate_reproduction_steps(finding: dict, ftype: str, target: str) -> list:
    """
    Auto-generate numbered developer-friendly reproduction steps from ZAP/tool fields.
    Returns a list of step strings (no numbering prefix — caller adds that).
    """
    url     = finding.get("url") or target
    param   = finding.get("param", "")
    attack  = finding.get("attack", "")
    evidence = (finding.get("evidence") or {})
    ev_str  = evidence.get("evidence", "") or evidence.get("match", "")
    banner  = evidence.get("banner", "")
    port    = str(finding.get("port", ""))
    service = finding.get("service", "")
    name    = finding.get("name", "")

    # Extract host for commands
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        host   = parsed.hostname or target
    except Exception:
        host = target

    if ftype == "web_vulnerability":
        steps = [
            f"Open a browser and navigate to: {url}",
        ]
        if param:
            steps.append(f"Locate the `{param}` parameter in the request (query string, form field, or header).")
        steps.append("Open a proxy tool such as Burp Suite or ZAP and intercept the request.")
        if param and attack:
            steps.append(f"Replace the value of `{param}` with the following payload: `{attack}`")
        elif attack:
            steps.append(f"Inject the following payload into the vulnerable parameter: `{attack}`")
        else:
            steps.append("Inject a test payload into the vulnerable parameter.")
        steps.append("Forward the modified request to the server.")
        if ev_str:
            steps.append(f"Observe the server response — look for: `{ev_str[:120]}`")
        else:
            steps.append("Observe the server response for signs of vulnerability (error messages, reflected input, or unexpected behaviour).")
        return steps

    if ftype == "missing_security_header":
        steps = [
            f"Open a browser and navigate to: {url}",
            "Open Developer Tools (press F12) and go to the Network tab.",
            "Reload the page and click on any request to the main domain.",
            "Select the 'Headers' tab and scroll to the Response Headers section.",
            f"Confirm that the `{name}` response header is absent.",
            "Any request to this origin will be served without this security control.",
        ]
        return steps

    if ftype == "insecure_cookie":
        steps = [
            f"Open a browser and navigate to: {url}",
            "Open Developer Tools (press F12) and go to the Application tab.",
            "In the left panel expand Storage → Cookies and select the domain.",
            f"Locate the session/auth cookie and check its attributes.",
            "Verify that the insecure flag is set (or the secure/HttpOnly flag is missing).",
            "A script on the page (via XSS) or a network attacker can now steal this cookie.",
        ]
        if param:
            steps[3] = f"Locate the `{param}` cookie and inspect its attribute flags."
        return steps

    if ftype == "ssl_error":
        steps = [
            f"Run the following command from a terminal: `openssl s_client -connect {host}:443`",
            "Inspect the TLS handshake output for protocol version and cipher suite.",
            f"Alternatively, run: `nmap --script ssl-enum-ciphers -p 443 {host}`",
            "Note any deprecated protocols (SSLv3, TLS 1.0/1.1) or weak ciphers reported.",
            "A network attacker in a MITM position can exploit this to intercept or decrypt traffic.",
        ]
        return steps

    if ftype == "open_port":
        steps = [
            f"Run a port scan: `nmap -sV -p {port} {host}`",
            f"Confirm that port {port}/{service or 'unknown'} is open and accepting connections.",
            f"Attempt a direct connection: `nc -v {host} {port}`",
        ]
        if banner:
            steps.append(f"Observe the banner: `{banner[:100]}`")
        steps.append(f"Query CVE databases for known vulnerabilities in the detected {service or 'service'} version.")
        steps.append("Attempt authentication with default or blank credentials if applicable.")
        return steps

    if ftype == "auth_misconfiguration":
        steps = [
            f"Connect to the service at: {url or f'{host}:{port}'}",
            "Attempt to authenticate using common default credentials (e.g., admin/admin, admin/password, root/root).",
            "Try authenticating with a blank password or no password at all.",
            "If access is granted, browse available data, configuration, and user listings.",
            "Document any sensitive information accessible without proper authorisation.",
        ]
        return steps

    if ftype == "information_disclosure":
        steps = [
            f"Send a standard HTTP request to: {url}",
            "Inspect the full response — headers, body, and any error messages.",
        ]
        if ev_str:
            steps.append(f"Look for the disclosed information: `{ev_str[:120]}`")
        steps.append(f"Run: `curl -s \"{url}\" | grep -i 'version\\|error\\|stack\\|path\\|debug'`")
        steps.append("Cross-reference any disclosed version strings against CVE databases for exploitable vulnerabilities.")
        return steps

    if ftype == "cloud_misconfiguration":
        steps = [
            f"Identify the affected cloud resource from the finding name: {name}",
            "Use the appropriate cloud CLI to verify the configuration:",
            "  AWS: `aws s3 ls s3://<bucket>` or `aws iam get-account-authorization-details`",
            "  GCP: `gcloud projects get-iam-policy <project>`",
            "  Azure: `az resource list --query \"[].{name:name,type:type}\"`",
            "Attempt unauthenticated or cross-account access to confirm exploitability.",
            "Document all data accessible via the misconfiguration.",
        ]
        return steps

    if ftype == "vulnerable_version":
        steps = [
            f"Run a service version scan: `nmap -sV -p {port or '0-65535'} {host}`",
            f"Note the exact version of {service or 'the service'} reported.",
            f"Search for known exploits: `searchsploit {service} {port}`",
            "Check the NVD (nvd.nist.gov) for CVEs matching this version.",
            f"If a PoC exploit exists, test it against {host}:{port} in an authorised test environment.",
        ]
        return steps

    # Generic fallback
    steps = [
        f"Navigate to the affected target: {url}",
        f"Reproduce the condition described in the finding: {name}",
        "Capture the request and response using a proxy tool (Burp Suite or ZAP).",
        "Verify the issue is consistently reproducible before reporting.",
    ]
    return steps


def _build_exploitation_narrative(finding: dict, severity: str, ftype: str, target: str) -> str:
    """
    Per-finding attacker step-by-step exploitation chain.
    Written from the attacker's perspective to make impact concrete.
    """
    name    = finding.get("name","")
    port    = finding.get("port","")
    service = finding.get("service","")
    cve     = finding.get("cve","")
    url     = finding.get("url", target)

    narratives = {
        "vulnerable_version": (
            f"**Step 1 — Reconnaissance:** Attacker scans target with `nmap -sV -p {port} {target}` "
            f"and identifies {service} version banner.\n"
            f"**Step 2 — CVE Lookup:** Attacker searches {cve or 'known CVE databases'} for a matching exploit. "
            f"Public PoC code is often available on GitHub/ExploitDB within hours of CVE publication.\n"
            f"**Step 3 — Exploitation:** Attacker executes the PoC exploit targeting {target}:{port}. "
            f"For {cve}, this typically results in RCE, privilege escalation, or data exfiltration.\n"
            f"**Step 4 — Persistence:** Attacker installs backdoor/webshell and pivots to internal network.\n"
            f"**Business Impact:** Full server compromise, potential lateral movement to internal systems, data theft."
        ),
        "auth_misconfiguration": (
            f"**Step 1 — Discovery:** Attacker finds {service or 'service'} on port {port or '?'} "
            f"through Shodan/Censys or direct port scan.\n"
            f"**Step 2 — Auth bypass:** Attacker attempts default or null credentials. "
            f"For databases like Redis/MongoDB, connection requires zero authentication by default.\n"
            f"**Step 3 — Data access:** Attacker dumps all database contents, reads configuration files, "
            f"extracts user credentials/PII.\n"
            f"**Step 4 — Lateral movement:** Credentials harvested from the database are used to authenticate "
            f"to other internal services.\n"
            f"**Business Impact:** Complete data breach, ransomware deployment, regulatory fines."
        ),
        "insecure_cookie": (
            f"**Step 1 — XSS or network position:** Attacker either exploits an XSS vulnerability on {url} "
            f"or is positioned on the same network (cafe WiFi, ISP, etc.).\n"
            f"**Step 2 — Cookie theft:** If HttpOnly is missing, `document.cookie` in an XSS payload "
            f"exfiltrates the session token to attacker's server. If Secure is missing, "
            f"the cookie is sent over plain HTTP and intercepted via MITM.\n"
            f"**Step 3 — Session hijack:** Attacker replays the stolen session cookie to impersonate the victim. "
            f"No password needed.\n"
            f"**Business Impact:** Account takeover, data theft, ability to perform actions as victim user."
        ),
        "ssl_error": (
            f"**Step 1 — Network positioning:** Attacker uses ARP spoofing or routes traffic through a "
            f"malicious access point on the same network as a target user.\n"
            f"**Step 2 — MITM:** With no HTTPS enforcement, HTTP traffic between victim and {target} "
            f"passes through attacker's machine in plaintext.\n"
            f"**Step 3 — Credential harvest:** Login credentials, session tokens, and sensitive data "
            f"are captured from HTTP requests in real time.\n"
            f"**Business Impact:** Credential theft, session hijacking, data interception at scale."
        ),
        "information_disclosure": (
            f"**Step 1 — Initial recon:** Attacker makes a standard request to {url} and observes "
            f"verbose error messages, version strings, or directory listings in the response.\n"
            f"**Step 2 — Intelligence gathering:** Disclosed technology versions (e.g., PHP 5.6, Apache 2.2) "
            f"are cross-referenced with CVE databases to identify exploitable vulnerabilities.\n"
            f"**Step 3 — Targeted attack:** Attacker selects and executes an exploit specifically "
            f"targeting the identified version, dramatically reducing the effort needed.\n"
            f"**Business Impact:** Lowers attacker effort by 60-80%. Enables precise, targeted attacks."
        ),
        "web_vulnerability": (
            f"**Step 1 — Discovery:** Attacker uses an automated scanner (Burp Suite, ZAP) to enumerate "
            f"endpoints on {target} and identifies the vulnerable parameter/endpoint.\n"
            f"**Step 2 — Exploitation:** The vulnerability ({name}) is exploited — "
            f"for XSS this means injecting a script payload; for SQLi it means extracting database contents; "
            f"for SSRF it means pivoting to internal services.\n"
            f"**Step 3 — Escalation:** XSS → session theft → account takeover. "
            f"SQLi → credential dump → admin access. SSRF → internal network enumeration.\n"
            f"**Business Impact:** Depends on vulnerability class — ranges from account compromise to full "
            f"server/database takeover."
        ),
        "missing_security_header": (
            f"**Step 1 — Identify missing header:** Attacker notes the absence of {name} in responses from {url}.\n"
            f"**Step 2 — Exploit the gap:** Without CSP, stored XSS attacks succeed without bypass. "
            f"Without X-Frame-Options, the site is embeddable in iframes for clickjacking attacks. "
            f"Without HSTS, SSL stripping attacks downgrade HTTPS to HTTP.\n"
            f"**Step 3 — Chain with other vulnerabilities:** Missing security headers are typically chained "
            f"with other vulnerabilities to amplify impact — e.g., no CSP + XSS = reliable session theft.\n"
            f"**Business Impact:** Enables other attack classes that would otherwise be mitigated."
        ),
        "cloud_misconfiguration": (
            f"**Step 1 — Cloud asset discovery:** Attacker uses cloud enumeration tools "
            f"(ScoutSuite, Prowler, CloudMapper) or passive reconnaissance (Shodan, Certificate Transparency) "
            f"to identify exposed cloud resources.\n"
            f"**Step 2 — Access misconfigured resource:** The misconfigured resource ({name}) "
            f"is accessed directly — public S3 bucket via AWS CLI, open RDS via TCP, unprotected "
            f"Elasticsearch via HTTP API — no credentials required.\n"
            f"**Step 3 — Data exfiltration / lateral movement:** "
            f"Customer PII, source code, credentials, and infrastructure configs are exfiltrated. "
            f"Discovered IAM keys or service credentials allow lateral movement across the cloud account.\n"
            f"**Business Impact:** Mass data breach, full cloud account compromise, regulatory consequences "
            f"(GDPR fines, HIPAA violations)."
        ),
        "open_port": (
            f"**Step 1 — Port scan:** Attacker runs `nmap -sV -p {port} {target}` — "
            f"takes under 30 seconds from anywhere on the internet.\n"
            f"**Step 2 — Service fingerprint:** Banner grab identifies exact {service} version running. "
            f"Attacker queries NVD/ExploitDB for known vulnerabilities in that version.\n"
            f"**Step 3 — Attack selection:** If vulnerable version found, exploit is executed directly. "
            f"If not, attacker attempts default credentials (extremely common for Redis, MongoDB, Elasticsearch).\n"
            f"**Business Impact:** Entry point for network compromise; severity depends on the service — "
            f"Redis/MongoDB without auth = immediate full data access."
        ),
    }

    return narratives.get(ftype, (
        f"**Step 1:** Attacker identifies '{name}' during reconnaissance of {target}.\n"
        f"**Step 2:** The vulnerability is confirmed and an appropriate exploit is selected.\n"
        f"**Step 3:** Exploitation proceeds based on the vulnerability characteristics. "
        f"Severity: {severity}.\n"
        f"**Business Impact:** Manual assessment required to determine full impact chain."
    ))


def _generate_analyst_note(finding: dict, severity: str, module: str) -> str:
    ftype = finding.get("type","")
    name  = finding.get("name","")
    notes = {
        "open_port":             f"Port {finding.get('port')} ({finding.get('service','?')}) exposed. Verify business justification. Cross-reference CVE database for version.",
        "missing_security_header": f"Missing header: {name}. Low-effort high-impact fix at web server level.",
        "web_vulnerability":     f"{name}: verify manually in both authenticated and unauthenticated contexts.",
        "cloud_misconfiguration":f"Cloud misconfig: {name}. Remediate before any production deployment.",
        "insecure_cookie":       f"Cookie issue: {name}. If session token — actual severity is higher than rated.",
        "ssl_error":             "SSL/TLS issue. Prioritise — Let's Encrypt provides free valid certificates.",
        "auth_misconfiguration": f"Auth misconfig: {name}. Attempt manual default credential test to confirm.",
        "vulnerable_version":    f"Vulnerable version: {name}. CVE: {finding.get('cve','?')}. Patch immediately.",
        "information_disclosure":f"Info disclosure: {name}. Low rated but enables targeted attacks.",
    }
    return notes.get(ftype, f"Finding: '{name}' via {module} module. Severity: {severity}. Manual review needed.")
