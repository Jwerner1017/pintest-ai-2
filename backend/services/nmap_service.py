"""Nmap scanning service with graceful fallback to mocked results."""
import logging
import shutil
import asyncio

logger = logging.getLogger(__name__)

NMAP_AVAILABLE = shutil.which("nmap") is not None

try:
    import nmap  # python-nmap
except ImportError:
    nmap = None


async def run_recon_scan(target: str, options: dict | None = None) -> dict:
    """Run an nmap reconnaissance scan against `target`.

    Returns a dict with ports, os_detection, hostnames, vulnerabilities.
    Falls back to a small, clearly-labelled mocked result if nmap is unavailable
    or the target cannot be resolved (preview environments may block outbound).
    """
    options = options or {}
    args = options.get("nmap_args", "-sT -sV -T4 --top-ports 100 -Pn")

    if not (NMAP_AVAILABLE and nmap):
        return _mock_result(target, "nmap binary not installed")

    try:
        result = await asyncio.to_thread(_run_nmap_blocking, target, args)
        return result
    except Exception as e:  # noqa: BLE001
        logger.warning("nmap scan failed for %s: %s", target, e)
        return _mock_result(target, f"nmap scan failed: {e}")


def _run_nmap_blocking(target: str, args: str) -> dict:
    scanner = nmap.PortScanner()
    scanner.scan(hosts=target, arguments=args)

    ports: list[dict] = []
    os_detection = "unknown"
    hostnames: list[str] = []

    for host in scanner.all_hosts():
        hostnames.extend([h.get("name", "") for h in scanner[host].get("hostnames", []) if h.get("name")])
        if "osmatch" in scanner[host] and scanner[host]["osmatch"]:
            os_detection = scanner[host]["osmatch"][0].get("name", "unknown")
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto]:
                info = scanner[host][proto][port]
                ports.append({
                    "port": port,
                    "protocol": proto,
                    "service": info.get("name", "unknown"),
                    "state": info.get("state", "unknown"),
                    "version": f"{info.get('product', '')} {info.get('version', '')}".strip() or "unknown",
                })

    if not hostnames:
        hostnames = [target]

    return {
        "target": target,
        "scan_type": "reconnaissance",
        "scan_engine": "nmap",
        "ports": ports,
        "os_detection": os_detection,
        "hostnames": hostnames,
        "vulnerabilities": _derive_vulns_from_ports(ports),
    }


def _derive_vulns_from_ports(ports: list[dict]) -> list[dict]:
    """Lightweight heuristic vuln hints from service banners."""
    vulns = []
    for p in ports:
        svc = (p.get("service") or "").lower()
        version = (p.get("version") or "").lower()
        if svc == "ftp" and "anonymous" not in version:
            vulns.append({
                "id": f"PORT-{p['port']}-FTP",
                "severity": "medium",
                "description": f"FTP service exposed on port {p['port']} — verify anonymous login is disabled.",
            })
        if svc == "telnet":
            vulns.append({
                "id": f"PORT-{p['port']}-TELNET",
                "severity": "high",
                "description": "Telnet transmits credentials in cleartext. Replace with SSH.",
            })
        if svc == "http" and p["port"] == 80:
            vulns.append({
                "id": f"PORT-{p['port']}-HTTP",
                "severity": "low",
                "description": "Plain HTTP exposed — consider redirecting to HTTPS.",
            })
    return vulns


def _mock_result(target: str, reason: str) -> dict:
    return {
        "target": target,
        "scan_type": "reconnaissance",
        "scan_engine": "mock",
        "mock_reason": reason,
        "ports": [
            {"port": 22, "protocol": "tcp", "service": "ssh", "state": "open", "version": "OpenSSH 8.9"},
            {"port": 80, "protocol": "tcp", "service": "http", "state": "open", "version": "nginx 1.24.0"},
            {"port": 443, "protocol": "tcp", "service": "https", "state": "open", "version": "nginx 1.24.0"},
        ],
        "os_detection": "Linux 5.x (simulated)",
        "hostnames": [target],
        "vulnerabilities": [
            {"id": "CVE-2024-1234", "severity": "high", "description": "Demo: SSH authentication bypass (mocked)"},
            {"id": "CVE-2024-5678", "severity": "medium", "description": "Demo: HTTP information disclosure (mocked)"},
        ],
    }
