"""
Recon Agent
Performs DNS resolution, HTTP banner grab, port pre-check, and target classification.
Feeds the Orchestrator's module-selection decision engine.
"""
import socket
import logging
import re
from urllib.parse import urlparse
from datetime import datetime

import httpx

logger = logging.getLogger(__name__)

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                3306, 3389, 5432, 6379, 8080, 8443, 8000, 8888, 9200, 27017]

WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}

CLOUD_KEYWORDS = ["aws", "amazon", "azure", "gcp", "google", "cloudfront",
                  "s3.", "blob.core", "appspot", "lambda", "elasticbeanstalk"]


def run_recon(target: str) -> dict:
    """
    Entry point called by the Orchestrator.
    Returns a structured recon result dict.
    """
    logger.info(f"[RECON] Starting recon on: {target}")
    start = datetime.utcnow()

    hostname, scheme = _parse_target(target)
    ip_address = _resolve_dns(hostname)
    open_ports = _port_prescan(ip_address or hostname)
    http_info = _http_banner(target, scheme)
    host_type = _classify_host(target, open_ports, http_info)
    technologies = _detect_technologies(http_info)

    result = {
        "module": "recon",
        "target": target,
        "hostname": hostname,
        "ip_address": ip_address,
        "scheme": scheme,
        "host_type": host_type,
        "open_ports": open_ports,
        "http_info": http_info,
        "technologies": technologies,
        "scan_time": (datetime.utcnow() - start).total_seconds(),
        "findings": _recon_findings(open_ports, http_info, host_type),
    }

    logger.info(f"[RECON] Done. Host type: {host_type} | Open ports: {len(open_ports)} | "
                f"Findings: {len(result['findings'])}")
    return result


# ── Helpers ──────────────────────────────────────────────────────────────────

def _parse_target(target: str) -> tuple:
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        return parsed.hostname or target, parsed.scheme
    return target, "http"


def _resolve_dns(hostname: str) -> str | None:
    try:
        ip = socket.gethostbyname(hostname)
        logger.info(f"[RECON] DNS resolved {hostname} -> {ip}")
        return ip
    except socket.gaierror:
        logger.warning(f"[RECON] DNS resolution failed for {hostname}")
        return None


def _port_prescan(host: str) -> list:
    """Quick TCP connect scan on common ports (3s timeout)."""
    open_ports = []
    for port in COMMON_PORTS:
        try:
            with socket.create_connection((host, port), timeout=3):
                service = _guess_service(port)
                open_ports.append({"port": port, "service": service, "state": "open"})
                logger.debug(f"[RECON] Open: {port}/{service}")
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
    logger.info(f"[RECON] Pre-scan: {len(open_ports)} open ports on {host}")
    return open_ports


def _http_banner(target: str, scheme: str) -> dict:
    """Grab HTTP headers and basic page info."""
    info = {"status_code": None, "server": None, "headers": {}, "title": None,
            "redirect_url": None, "https": scheme == "https"}
    url = target if target.startswith("http") else f"{scheme}://{target}"
    try:
        resp = httpx.get(url, timeout=8, follow_redirects=True,
                         headers={"User-Agent": "Mozilla/5.0 SecurityAgent/1.0"})
        info["status_code"] = resp.status_code
        info["headers"] = dict(resp.headers)
        info["server"] = resp.headers.get("server", "")
        info["redirect_url"] = str(resp.url) if str(resp.url) != url else None
        title_match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
        if title_match:
            info["title"] = title_match.group(1).strip()[:120]
        info["https"] = str(resp.url).startswith("https")
        logger.info(f"[RECON] HTTP {resp.status_code} from {url} | Server: {info['server']}")
    except httpx.RequestError as e:
        logger.warning(f"[RECON] HTTP banner failed for {url}: {e}")
    return info


def _classify_host(target: str, open_ports: list, http_info: dict) -> str:
    port_nums = {p["port"] for p in open_ports}
    t_lower = target.lower()

    if any(kw in t_lower for kw in CLOUD_KEYWORDS):
        return "cloud_endpoint"
    if http_info.get("status_code") or bool(port_nums & WEB_PORTS):
        return "web_application"
    if {22, 23} & port_nums and not (port_nums & WEB_PORTS):
        return "network_device"
    if port_nums:
        return "network_host"
    return "unknown"


def _detect_technologies(http_info: dict) -> list:
    techs = []
    headers = {k.lower(): v for k, v in http_info.get("headers", {}).items()}
    server = (http_info.get("server") or "").lower()

    tech_map = {
        "nginx": "Nginx", "apache": "Apache", "iis": "Microsoft IIS",
        "cloudflare": "Cloudflare", "gunicorn": "Gunicorn", "openresty": "OpenResty",
    }
    for key, name in tech_map.items():
        if key in server:
            techs.append(name)

    if "x-powered-by" in headers:
        techs.append(headers["x-powered-by"])
    if "x-generator" in headers:
        techs.append(headers["x-generator"])
    if headers.get("content-type", "").startswith("text/html"):
        techs.append("HTML")

    return list(dict.fromkeys(techs))  # dedupe preserving order


def _recon_findings(open_ports: list, http_info: dict, host_type: str) -> list:
    findings = []
    headers = {k.lower(): v for k, v in http_info.get("headers", {}).items()}

    # Risky open ports
    risky = {21: "FTP", 23: "Telnet", 25: "SMTP", 110: "POP3",
             143: "IMAP", 3389: "RDP", 5432: "PostgreSQL",
             6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB"}
    for p in open_ports:
        if p["port"] in risky:
            findings.append({
                "name": f"Exposed {risky[p['port']]} Service",
                "type": "open_port",
                "risk": "Medium",
                "port": p["port"],
                "service": p["service"],
                "description": (f"Port {p['port']} ({risky[p['port']]}) is publicly accessible. "
                                "Unauthenticated or weakly-authenticated services may expose sensitive data."),
                "solution": (f"Restrict access to port {p['port']} via firewall rules. "
                             "Ensure strong authentication is enforced.")
            })

    # HTTP-only (no redirect to HTTPS)
    if http_info.get("status_code") and not http_info.get("https"):
        findings.append({
            "name": "Unencrypted HTTP Detected",
            "type": "ssl_error",
            "risk": "Medium",
            "description": "The application is accessible over plain HTTP without TLS encryption.",
            "solution": "Force HTTPS redirect and enable HSTS."
        })

    # Missing security headers
    security_headers = {
        "strict-transport-security": "HSTS Missing",
        "content-security-policy": "CSP Missing",
        "x-frame-options": "Clickjacking Protection Missing",
        "x-content-type-options": "MIME Sniffing Protection Missing",
        "referrer-policy": "Referrer Policy Missing",
        "permissions-policy": "Permissions Policy Missing",
    }
    if http_info.get("status_code"):
        for h, name in security_headers.items():
            if h not in headers:
                findings.append({
                    "name": name,
                    "type": "missing_security_header",
                    "risk": "Low",
                    "description": f"The HTTP response does not include the '{h}' security header.",
                    "solution": f"Add '{h}' to all HTTP responses at the web server or application level."
                })

    return findings


def _guess_service(port: int) -> str:
    services = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
        3306: "mysql", 3389: "rdp", 5432: "postgresql", 6379: "redis",
        8080: "http-alt", 8443: "https-alt", 8000: "http-alt",
        8888: "http-alt", 9200: "elasticsearch", 27017: "mongodb",
    }
    return services.get(port, "unknown")
