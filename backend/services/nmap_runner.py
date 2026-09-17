"""Unified async nmap runner — subprocess + XML parsing.

Replaces the `python-nmap` library dependency across recon/vuln/network services.
Retains the raw XML output so it can be exported as an evidence artifact (pairs
well with the DEFT forensics workflow).
"""
import asyncio
import logging
import shutil
import shlex
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

PROCESS_TIMEOUT_SEC = 300  # hard safety cap on any nmap invocation


def is_available() -> bool:
    return shutil.which("nmap") is not None


class NmapRunResult:
    __slots__ = ("hosts", "raw_xml", "raw_stdout", "raw_stderr", "returncode", "error")

    def __init__(self) -> None:
        self.hosts: list[dict] = []
        self.raw_xml: str = ""
        self.raw_stdout: str = ""
        self.raw_stderr: str = ""
        self.returncode: Optional[int] = None
        self.error: Optional[str] = None


async def run(target: str, args: str, timeout: int = PROCESS_TIMEOUT_SEC) -> NmapRunResult:
    """Run `nmap {args} -oX <tmp> {target}` and return parsed results + raw XML.

    Never raises for scan failures — returns an NmapRunResult with `.error` set.
    Only raises if nmap binary is missing (caller should check `is_available()` first).
    """
    result = NmapRunResult()

    if not is_available():
        result.error = "nmap binary not installed"
        return result

    with tempfile.NamedTemporaryFile(prefix="nmap_", suffix=".xml", delete=False) as tf:
        xml_path = Path(tf.name)

    try:
        cmd = ["nmap", *shlex.split(args), "-oX", str(xml_path), target]
        logger.info("nmap exec: %s", " ".join(cmd))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            result.error = f"nmap timeout after {timeout}s"
            return result

        result.returncode = proc.returncode
        result.raw_stdout = stdout.decode(errors="replace")
        result.raw_stderr = stderr.decode(errors="replace")

        # returncode 0 = clean, 1 = some hosts unreachable (still usable).
        if proc.returncode not in (0, 1):
            result.error = f"nmap exit {proc.returncode}: {result.raw_stderr[:200]}"

        if xml_path.exists():
            result.raw_xml = xml_path.read_text(errors="replace")
            try:
                result.hosts = _parse_xml(result.raw_xml)
            except ET.ParseError as e:
                result.error = result.error or f"xml parse: {e}"

        return result
    finally:
        xml_path.unlink(missing_ok=True)


def _parse_xml(xml_text: str) -> list[dict]:
    """Return a list of hosts. Each host: {ip, hostname, state, ports[], os_match}."""
    root = ET.fromstring(xml_text)
    hosts: list[dict] = []
    for host_elem in root.findall("host"):
        status = host_elem.find("status")
        state = status.get("state") if status is not None else "unknown"

        addr = host_elem.find("address")
        ip = addr.get("addr") if addr is not None else None

        hostname = None
        hn = host_elem.find(".//hostname")
        if hn is not None:
            hostname = hn.get("name")

        ports = []
        for p in host_elem.findall(".//port"):
            st = p.find("state")
            svc = p.find("service")
            port = {
                "port": int(p.get("portid")),
                "protocol": p.get("protocol") or "tcp",
                "state": st.get("state") if st is not None else "unknown",
                "service": svc.get("name") if svc is not None else "unknown",
                "product": svc.get("product") if svc is not None else "",
                "version": svc.get("version") if svc is not None else "",
                # NSE script output — list of (script_id, output) tuples.
                "scripts": [
                    (s.get("id"), s.get("output", ""))
                    for s in p.findall("script")
                    if s.get("id")
                ],
            }
            ports.append(port)

        os_match = None
        om = host_elem.find(".//osmatch")
        if om is not None:
            os_match = om.get("name")

        hosts.append({
            "ip": ip,
            "hostname": hostname or ip,
            "state": state,
            "ports": ports,
            "os_match": os_match,
        })
    return hosts
