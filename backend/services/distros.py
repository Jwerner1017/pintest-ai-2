"""Curated security-focused Linux distribution catalogue with contextual recommendations.

Surfaces purpose-built distros so users know which environment is ideal for which task.
"""

DISTROS = [
    {
        "id": "deft",
        "name": "DEFT Linux",
        "full_name": "Digital Evidence & Forensic Toolkit",
        "focus": "Digital forensics & incident response",
        "tagline": "Court-admissible forensic acquisition and analysis.",
        "best_for": [
            "Disk imaging & write-blocking",
            "Memory forensics (Volatility)",
            "Mobile device extraction",
            "Post-incident artifact recovery",
        ],
        "key_tools": ["dc3dd", "Sleuth Kit", "Autopsy", "Volatility", "Xplico", "Foremost"],
        "use_when": "You are responding to an incident, preserving evidence, or reconstructing an attack timeline.",
        "site": "https://www.deftlinux.net",
        "tags": ["forensics", "incident-response", "evidence"],
    },
    {
        "id": "backbox",
        "name": "BackBox",
        "full_name": "BackBox Linux",
        "focus": "Penetration testing & security assessment",
        "tagline": "Ubuntu-based pentest distro with curated, regularly-updated toolset.",
        "best_for": [
            "Web application testing",
            "Network vulnerability assessment",
            "Stress testing",
            "Forensic analysis (light)",
        ],
        "key_tools": ["Metasploit", "OWASP ZAP", "Nikto", "SQLmap", "John the Ripper", "Aircrack-ng"],
        "use_when": "You want a clean, lightweight Ubuntu-based environment for routine pentesting engagements.",
        "site": "https://www.backbox.org",
        "tags": ["pentest", "web", "vuln-assessment"],
    },
    {
        "id": "kodachi",
        "name": "Kodachi",
        "full_name": "Linux Kodachi",
        "focus": "Privacy, anonymity & secure communications",
        "tagline": "Anti-forensic, VPN+Tor-by-default OS for sensitive operations.",
        "best_for": [
            "OPSEC-critical reconnaissance",
            "Anonymous research on threat actors",
            "Whistleblower / source protection workflows",
            "Travel & hostile-network use",
        ],
        "key_tools": ["Tor", "DNSCrypt", "VPN chains", "VeraCrypt", "Anti-forensic tools"],
        "use_when": "You need to research targets without revealing your origin, or to operate on untrusted networks.",
        "site": "https://www.digi77.com/linux-kodachi/",
        "tags": ["privacy", "anonymity", "opsec"],
    },
    {
        "id": "pentoo",
        "name": "Pentoo",
        "full_name": "Pentoo Linux",
        "focus": "Advanced penetration testing (Gentoo-based)",
        "tagline": "Hardened, rolling-release pentest distro with hardened-kernel & cuda-cracking support.",
        "best_for": [
            "Wireless / RF assessments",
            "GPU-accelerated password cracking",
            "Custom exploit development",
            "Long-running engagements requiring tuned environments",
        ],
        "key_tools": ["Aircrack-ng", "Kismet", "Hashcat (CUDA)", "Wireshark", "Metasploit", "GDB+PEDA"],
        "use_when": "You need maximum performance, hardware control, or are doing wireless / GPU-bound work.",
        "site": "https://www.pentoo.ch",
        "tags": ["pentest", "wireless", "gpu-cracking", "advanced"],
    },
]


# Contextual recommendations: which distro shines for each scan_type / situation.
RECOMMENDATIONS = {
    "recon": {
        "primary": ["kodachi", "backbox"],
        "rationale": "Use Kodachi for OPSEC-critical recon (your IP stays hidden); BackBox for routine engagement workflow.",
    },
    "vuln": {
        "primary": ["backbox", "pentoo"],
        "rationale": "BackBox bundles OWASP ZAP, Nikto, SQLmap. Pentoo adds GPU password cracking and exploit-dev tooling.",
    },
    "network": {
        "primary": ["pentoo", "backbox"],
        "rationale": "Pentoo's hardened kernel + wireless tooling is best for network sweeps and RF work; BackBox is the comfortable daily driver.",
    },
    "forensics": {
        "primary": ["deft", "kodachi"],
        "rationale": "DEFT is the gold standard for evidence preservation; Kodachi for anti-forensic analysis & live triage on untrusted media.",
    },
    "incident_response": {
        "primary": ["deft", "backbox"],
        "rationale": "DEFT for evidence handling, BackBox for follow-up active testing.",
    },
}


def list_distros() -> list[dict]:
    return DISTROS


def get_distro(distro_id: str) -> dict | None:
    return next((d for d in DISTROS if d["id"] == distro_id), None)


def recommend_for(scan_type: str) -> dict:
    """Return distro IDs + rationale recommended for a given scan_type."""
    rec = RECOMMENDATIONS.get(scan_type)
    if not rec:
        return {"primary": [], "rationale": ""}
    by_id = {d["id"]: d for d in DISTROS}
    return {
        "primary": [by_id[did] for did in rec["primary"] if did in by_id],
        "rationale": rec["rationale"],
    }


def assistant_system_addendum() -> str:
    """Short reference block injected into the AI assistant's system prompt."""
    lines = ["", "## Specialised Security Linux Distros (when to recommend them):"]
    for d in DISTROS:
        lines.append(f"- **{d['name']}** ({d['focus']}): {d['use_when']}")
    return "\n".join(lines)
