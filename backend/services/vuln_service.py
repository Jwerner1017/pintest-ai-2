"""Vulnerability scanning: nmap NSE vuln scripts + HTTP probe + NVD CVE enrichment."""
import asyncio
import logging
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from services import nmap_runner, nvd_service

logger = logging.getLogger(__name__)

SECURITY_HEADERS = {
    "strict-transport-security": ("Missing HSTS — enforce HTTPS via Strict-Transport-Security header.", "medium"),
    "content-security-policy": ("Missing CSP — implement Content-Security-Policy to mitigate XSS.", "medium"),
    "x-frame-options": ("Missing X-Frame-Options — pages may be clickjacked.", "low"),
    "x-content-type-options": ("Missing X-Content-Type-Options — set to 'nosniff'.", "low"),
    "referrer-policy": ("Missing Referrer-Policy — potential referrer URL leak.", "low"),
    "permissions-policy": ("Missing Permissions-Policy — restrict browser feature access.", "low"),
}


async def run_vuln_scan(target: str, options: dict | None = None) -> dict:
    """Combines nmap NSE vuln scripts, HTTP probe, TLS check, and NVD enrichment."""
    options = options or {}
    progress_cb = options.get("progress_cb")
    nmap_args = options.get("nmap_args", "-sT -sV -T4 --top-ports 100 -Pn --script vuln --host-timeout 90s")
    host = _extract_host(target)
    is_url = target.startswith(("http://", "https://"))

    vulns: list[dict] = []
    nmap_summary: dict = {}
    http_summary: dict = {}
    raw_xml = ""

    if progress_cb:
        await progress_cb(10, "Resolving target")

    if nmap_runner.is_available():
        if progress_cb:
            await progress_cb(20, "Running nmap vulnerability scripts")
        run = await nmap_runner.run(host, nmap_args)
        raw_xml = run.raw_xml
        if run.error and not run.hosts:
            nmap_summary = {"error": run.error}
        else:
            nmap_summary, nmap_vulns = _extract_nmap_findings(run.hosts)
            vulns.extend(nmap_vulns)
    else:
        nmap_summary = {"error": "nmap binary not installed"}

    if progress_cb:
        await progress_cb(70, "Probing HTTP endpoints")

    try:
        http_summary, http_vulns = await asyncio.to_thread(
            _http_probe_blocking, target if is_url else f"http://{host}"
        )
        vulns.extend(http_vulns)
    except Exception as e:  # noqa: BLE001
        logger.warning("http probe failed for %s: %s", target, e)
        http_summary = {"error": str(e)}

    if target.startswith("https://"):
        try:
            cert_info, cert_vulns = await asyncio.to_thread(
                _ssl_cert_blocking, host, urlparse(target).port or 443
            )
            http_summary["ssl"] = cert_info
            vulns.extend(cert_vulns)
        except Exception as e:  # noqa: BLE001
            logger.warning("ssl cert check failed: %s", e)

    if progress_cb:
        await progress_cb(85, "Enriching findings via NVD")

    try:
        cve_findings = await nvd_service.enrich_ports(nmap_summary.get("ports") or [])
        vulns.extend(cve_findings)
    except Exception as e:  # noqa: BLE001
        logger.warning("NVD enrichment failed: %s", e)

    if progress_cb:
        await progress_cb(95, "Aggregating findings")

    severities = [v["severity"] for v in vulns]
    return {
        "target": target,
        "scan_type": "vulnerability",
        "scan_engine": "nmap+http",
        "vulnerabilities": vulns,
        "nmap_summary": nmap_summary,
        "http_summary": http_summary,
        "risk_score": _risk_score(severities),
        "compliance": {"owasp_top10_hits": _owasp_hits(vulns)},
        "nmap_xml": raw_xml,
    }


def _extract_host(target: str) -> str:
    if "://" in target:
        return urlparse(target).hostname or target
    return target.split("/")[0]


def _extract_nmap_findings(hosts: list[dict]):
    ports_summary = []
    vulns = []
    for h in hosts:
        for p in h.get("ports", []):
            ports_summary.append({
                "port": p["port"],
                "service": p["service"],
                "product": p.get("product") or "",
                "version": p.get("version") or "",
            })
            for script_id, output in p.get("scripts", []):
                vulns.append({
                    "id": f"NSE-{script_id}-port{p['port']}",
                    "severity": _severity_from_output(output),
                    "description": f"[port {p['port']}/{p['service']}] {script_id}: {_first_line(output)}",
                    "source": "nmap-nse",
                    "remediation": "Patch the affected service to the latest version.",
                })
    return {"hosts_scanned": len(hosts), "ports": ports_summary}, vulns


def _severity_from_output(output: str) -> str:
    o = (output or "").upper()
    if "STATE: VULNERABLE" in o:
        return "high"
    if "VULNERABLE" in o or "LIKELY VULNERABLE" in o:
        return "medium"
    return "info"


def _first_line(text: str) -> str:
    if not text:
        return ""
    return text.strip().splitlines()[0][:200]


def _http_probe_blocking(url: str):
    vulns: list[dict] = []
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True, verify=False)
    except Exception as e:
        return {"error": f"http request failed: {e}"}, []

    summary = {
        "url": url,
        "status_code": resp.status_code,
        "server": resp.headers.get("Server", "n/a"),
        "powered_by": resp.headers.get("X-Powered-By"),
        "final_url": resp.url,
        "headers_present": list(resp.headers.keys()),
    }
    lower_headers = {k.lower(): v for k, v in resp.headers.items()}
    for header, (msg, sev) in SECURITY_HEADERS.items():
        if header not in lower_headers:
            vulns.append({
                "id": f"HTTP-MISSING-{header.upper()}",
                "severity": sev,
                "description": msg,
                "source": "http-probe",
                "remediation": f"Add the `{header}` response header.",
            })
    if summary["server"] and any(c.isdigit() for c in summary["server"]):
        vulns.append({
            "id": "HTTP-SERVER-DISCLOSURE",
            "severity": "low",
            "description": f"Server version disclosed: {summary['server']}",
            "source": "http-probe",
            "remediation": "Hide the Server header version.",
        })
    if summary.get("powered_by"):
        vulns.append({
            "id": "HTTP-XPOWEREDBY",
            "severity": "low",
            "description": f"X-Powered-By reveals stack: {summary['powered_by']}",
            "source": "http-probe",
            "remediation": "Remove the X-Powered-By header.",
        })
    for c in resp.cookies:
        if not c.secure:
            vulns.append({
                "id": f"HTTP-COOKIE-NOSECURE-{c.name}",
                "severity": "low",
                "description": f"Cookie '{c.name}' missing Secure flag.",
                "source": "http-probe",
                "remediation": "Set Secure flag on session cookies.",
            })
    return summary, vulns


def _ssl_cert_blocking(host: str, port: int):
    vulns: list[dict] = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=8) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert(binary_form=False) or {}
            tls_version = ssock.version()
    info = {"tls_version": tls_version}
    if tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        vulns.append({
            "id": "TLS-OUTDATED",
            "severity": "high",
            "description": f"Server negotiates outdated protocol: {tls_version}",
            "source": "tls-probe",
            "remediation": "Disable TLS < 1.2; prefer TLS 1.3.",
        })
    not_after = cert.get("notAfter")
    if not_after:
        try:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expires - datetime.now(timezone.utc)).days
            info["days_until_expiry"] = days_left
            if days_left < 0:
                vulns.append({
                    "id": "TLS-EXPIRED-CERT", "severity": "critical",
                    "description": f"Certificate expired on {not_after}",
                    "source": "tls-probe",
                    "remediation": "Renew the TLS certificate immediately.",
                })
            elif days_left < 30:
                vulns.append({
                    "id": "TLS-CERT-EXPIRING", "severity": "medium",
                    "description": f"Certificate expires in {days_left} days ({not_after}).",
                    "source": "tls-probe",
                    "remediation": "Renew the TLS certificate before expiry.",
                })
        except Exception:
            pass
    return info, vulns


def _risk_score(severities: list[str]) -> float:
    weights = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 1.0}
    if not severities:
        return 0.0
    total = sum(weights.get(s, 1.0) for s in severities)
    return round(min(total / max(len(severities), 1), 10.0), 1)


def _owasp_hits(vulns: list[dict]) -> list[str]:
    hits = set()
    for v in vulns:
        d = (v.get("description", "") + v.get("id", "")).lower()
        if "xss" in d or "cross-site scripting" in d:
            hits.add("A03:2021 - Injection (XSS)")
        if "sql" in d:
            hits.add("A03:2021 - Injection (SQLi)")
        if "csrf" in d:
            hits.add("A01:2021 - Broken Access Control")
        if "tls" in d or "ssl" in d:
            hits.add("A02:2021 - Cryptographic Failures")
        if "header" in d and "missing" in d:
            hits.add("A05:2021 - Security Misconfiguration")
    return sorted(hits)
