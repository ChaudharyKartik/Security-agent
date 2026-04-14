"""
Recon Agent
DNS resolution, HTTP banner grab, port pre-check, target classification.
Now accepts ScanConfig for authenticated recon and captures PoC evidence.
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
WEB_PORTS    = {80, 443, 8080, 8443, 8000, 8888}
CLOUD_KEYWORDS = ["aws","amazon","azure","gcp","google","cloudfront",
                  "s3.","blob.core","appspot","lambda","elasticbeanstalk"]


def run_recon(target: str, config=None) -> dict:
    logger.info(f"[RECON] Starting recon on: {target}")
    start = datetime.utcnow()

    auth_headers = config.build_auth_headers() if config else {}
    hostname, scheme = _parse_target(target)
    ip_address = _resolve_dns(hostname)
    open_ports = _port_prescan(ip_address or hostname)
    http_info  = _http_banner(target, scheme, auth_headers)
    host_type  = _classify_host(target, open_ports, http_info)
    technologies = _detect_technologies(http_info)

    findings = _recon_findings(open_ports, http_info, host_type)

    return {
        "module":       "recon",
        "target":       target,
        "hostname":     hostname,
        "ip_address":   ip_address,
        "scheme":       scheme,
        "host_type":    host_type,
        "open_ports":   open_ports,
        "http_info":    http_info,
        "technologies": technologies,
        "scan_time":    (datetime.utcnow() - start).total_seconds(),
        "findings":     findings,
        "tool_used":    "socket + httpx",
        "auth_used":    config.build_auth_summary() if config else "Unauthenticated",
    }


def _parse_target(target: str) -> tuple:
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        return parsed.hostname or target, parsed.scheme
    return target, "http"


def _resolve_dns(hostname: str) -> str | None:
    try:
        ip = socket.gethostbyname(hostname)
        logger.info(f"[RECON] DNS {hostname} -> {ip}")
        return ip
    except socket.gaierror:
        logger.warning(f"[RECON] DNS failed: {hostname}")
        return None


def _port_prescan(host: str) -> list:
    open_ports = []
    for port in COMMON_PORTS:
        try:
            with socket.create_connection((host, port), timeout=3):
                open_ports.append({"port": port, "service": _guess_service(port), "state": "open"})
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
    return open_ports


def _http_banner(target: str, scheme: str, extra_headers: dict = None) -> dict:
    info = {"status_code": None, "server": None, "headers": {}, "title": None,
            "redirect_url": None, "https": scheme == "https",
            "raw_request": "", "raw_response_headers": ""}
    url = target if target.startswith("http") else f"{scheme}://{target}"
    hdrs = {"User-Agent": "Mozilla/5.0 SecurityAgent/1.0"}
    hdrs.update(extra_headers or {})
    try:
        resp = httpx.get(url, timeout=8, follow_redirects=True, headers=hdrs)
        info["status_code"]          = resp.status_code
        info["headers"]              = dict(resp.headers)
        info["server"]               = resp.headers.get("server", "")
        info["redirect_url"]         = str(resp.url) if str(resp.url) != url else None
        info["https"]                = str(resp.url).startswith("https")
        info["raw_response_headers"] = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        # Build PoC curl command
        header_flags = " ".join(f'-H "{k}: {v}"' for k, v in hdrs.items()
                                if k.lower() != "user-agent")
        info["raw_request"] = f'curl -sk -i {header_flags} "{url}"'
        m = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
        if m:
            info["title"] = m.group(1).strip()[:120]
    except httpx.RequestError as e:
        logger.warning(f"[RECON] HTTP banner failed: {e}")
    return info


def _classify_host(target: str, open_ports: list, http_info: dict) -> str:
    port_nums = {p["port"] for p in open_ports}
    t = target.lower()
    if any(kw in t for kw in CLOUD_KEYWORDS):           return "cloud_endpoint"
    if http_info.get("status_code") or port_nums & WEB_PORTS: return "web_application"
    if {22, 23} & port_nums and not port_nums & WEB_PORTS:     return "network_device"
    if port_nums:                                              return "network_host"
    return "unknown"


def _detect_technologies(http_info: dict) -> list:
    techs = []
    headers = {k.lower(): v for k, v in http_info.get("headers", {}).items()}
    server  = (http_info.get("server") or "").lower()
    for key, name in [("nginx","Nginx"),("apache","Apache"),("iis","Microsoft IIS"),
                      ("cloudflare","Cloudflare"),("gunicorn","Gunicorn")]:
        if key in server:
            techs.append(name)
    if "x-powered-by" in headers: techs.append(headers["x-powered-by"])
    if "x-generator"  in headers: techs.append(headers["x-generator"])
    return list(dict.fromkeys(techs))


def _recon_findings(open_ports: list, http_info: dict, host_type: str) -> list:
    findings = []
    headers  = {k.lower(): v for k, v in http_info.get("headers", {}).items()}
    risky    = {21:"FTP",23:"Telnet",25:"SMTP",110:"POP3",143:"IMAP",
                3389:"RDP",5432:"PostgreSQL",6379:"Redis",9200:"Elasticsearch",27017:"MongoDB"}

    for p in open_ports:
        if p["port"] in risky:
            findings.append({
                "name":        f"Exposed {risky[p['port']]} Service",
                "type":        "open_port",
                "risk":        "Medium",
                "port":        p["port"],
                "service":     p["service"],
                "description": f"Port {p['port']} ({risky[p['port']]}) is publicly reachable.",
                "solution":    f"Restrict port {p['port']} to trusted IPs only.",
                "evidence": {
                    "curl_poc":  f'nc -zv {http_info.get("raw_request","target")} {p["port"]}',
                    "type":      "port_open",
                },
            })

    if http_info.get("status_code") and not http_info.get("https"):
        findings.append({
            "name": "Unencrypted HTTP Detected", "type": "ssl_error", "risk": "Medium",
            "description": "Application accessible over plain HTTP.",
            "solution":    "Force HTTPS redirect and enable HSTS.",
            "evidence": {"curl_poc": http_info.get("raw_request", ""), "type": "http_plain"},
        })

    sec_headers = {
        "strict-transport-security": ("HSTS Missing",                 "Medium"),
        "content-security-policy":   ("Content-Security-Policy Missing","Medium"),
        "x-frame-options":           ("Clickjacking Protection Missing","Low"),
        "x-content-type-options":    ("MIME Sniffing Protection Missing","Low"),
        "referrer-policy":           ("Referrer Policy Missing",        "Low"),
    }
    if http_info.get("status_code"):
        for h, (name, risk) in sec_headers.items():
            if h not in headers:
                findings.append({
                    "name": name, "type": "missing_security_header", "risk": risk,
                    "description": f"Response missing '{h}' security header.",
                    "solution":    f"Add '{h}' header at web server or middleware level.",
                    "evidence": {
                        "curl_poc":       http_info.get("raw_request", ""),
                        "response_headers": http_info.get("raw_response_headers", ""),
                        "type":           "missing_header",
                    },
                })
    return findings


def _guess_service(port: int) -> str:
    return {21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",80:"http",110:"pop3",
            143:"imap",443:"https",445:"smb",3306:"mysql",3389:"rdp",
            5432:"postgresql",6379:"redis",8080:"http-alt",8443:"https-alt",
            8000:"http-alt",8888:"http-alt",9200:"elasticsearch",27017:"mongodb"}.get(port,"unknown")
