"""Nmap reconnaissance scanning service — subprocess+XML, graceful mock fallback."""
import logging

from services import nmap_runner

logger = logging.getLogger(__name__)


async def run_recon_scan(target: str, options: dict | None = None) -> dict:
    """Run an nmap reconnaissance scan against `target`."""
    options = options or {}
    args = options.get("nmap_args", "-sT -sV -T4 --top-ports 100 -Pn")
    progress_cb = options.get("progress_cb")

    if not nmap_runner.is_available():
        if progress_cb:
            await progress_cb(90, "nmap unavailable — using mock")
        return _mock_result(target, "nmap binary not installed")

    if progress_cb:
        await progress_cb(20, "Running nmap recon")

    run = await nmap_runner.run(target, args)
    if run.error and not run.hosts:
        logger.warning("recon scan failed: %s", run.error)
        return _mock_result(target, run.error)

    if progress_cb:
        await progress_cb(95, "Aggregating results")

    ports: list[dict] = []
    hostnames: set[str] = set()
    os_detection = "unknown"
    for h in run.hosts:
        if h.get("hostname"):
            hostnames.add(h["hostname"])
        if h.get("os_match"):
            os_detection = h["os_match"]
        for p in h.get("ports", []):
            product = p.get("product") or ""
            version = p.get("version") or ""
            ports.append({
                "port": p["port"],
                "protocol": p["protocol"],
                "service": p["service"],
                "state": p["state"],
                "version": f"{product} {version}".strip() or "unknown",
            })

    return {
        "target": target,
        "scan_type": "reconnaissance",
        "scan_engine": "nmap",
        "ports": ports,
        "os_detection": os_detection,
        "hostnames": sorted(hostnames) or [target],
        "vulnerabilities": _derive_vulns_from_ports(ports),
        "nmap_xml": run.raw_xml,  # retained as evidence artifact
    }


def _derive_vulns_from_ports(ports: list[dict]) -> list[dict]:
    vulns = []
    for p in ports:
        svc = (p.get("service") or "").lower()
        if svc == "telnet":
            vulns.append({
                "id": f"PORT-{p['port']}-TELNET",
                "severity": "high",
                "description": "Telnet transmits credentials in cleartext. Replace with SSH.",
            })
        elif svc == "ftp":
            vulns.append({
                "id": f"PORT-{p['port']}-FTP",
                "severity": "medium",
                "description": f"FTP exposed on port {p['port']} — verify anonymous login is disabled.",
            })
        elif svc == "http" and p["port"] == 80:
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
            {"id": "CVE-2024-1234", "severity": "high", "description": "Demo: SSH auth bypass (mocked)"},
        ],
        "nmap_xml": "",
    }
