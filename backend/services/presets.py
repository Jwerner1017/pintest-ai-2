"""Scan presets — fast / thorough / stealth — per scan type.

Defines nmap arguments and behavioural toggles. Selected via `options.preset` on POST /api/scans.
"""

PRESETS = {
    "recon": {
        "fast": {
            "label": "Fast",
            "description": "Top 20 ports, TCP connect, T4 timing.",
            "nmap_args": "-sT -T4 --top-ports 20 -Pn --host-timeout 30s",
        },
        "thorough": {
            "label": "Thorough",
            "description": "Top 1000 ports + service detection, T4.",
            "nmap_args": "-sT -sV -T4 --top-ports 1000 -Pn --host-timeout 180s",
        },
        "stealth": {
            "label": "Stealth",
            "description": "Top 100 ports, T2 timing (slower, less noisy).",
            "nmap_args": "-sT -sV -T2 --top-ports 100 -Pn --host-timeout 240s",
        },
    },
    "vuln": {
        "fast": {
            "label": "Fast",
            "description": "Top 20 ports + lightweight NSE vuln scripts.",
            "nmap_args": "-sT -sV -T4 --top-ports 20 -Pn --script vuln --host-timeout 60s",
        },
        "thorough": {
            "label": "Thorough",
            "description": "Top 200 ports + full NSE vuln category + NVD enrichment.",
            "nmap_args": "-sT -sV -T4 --top-ports 200 -Pn --script vuln --host-timeout 240s",
        },
        "stealth": {
            "label": "Stealth",
            "description": "Top 100 ports, T2 timing, NSE vuln scripts.",
            "nmap_args": "-sT -sV -T2 --top-ports 100 -Pn --script vuln --host-timeout 300s",
        },
    },
    "network": {
        "fast": {
            "label": "Fast",
            "description": "Ping sweep + top 20 ports per alive host.",
            "discovery_args": "-sn -T4 -PS22,80,443 --host-timeout 30s",
            "service_args": "-sT -sV -T4 --top-ports 20 -Pn --host-timeout 30s",
        },
        "thorough": {
            "label": "Thorough",
            "description": "Ping sweep + top 200 ports per alive host.",
            "discovery_args": "-sn -T4 -PS22,80,443,8080,3389 --host-timeout 60s",
            "service_args": "-sT -sV -T4 --top-ports 200 -Pn --host-timeout 120s",
        },
        "stealth": {
            "label": "Stealth",
            "description": "Slower ping sweep + top 50 ports, T2 timing.",
            "discovery_args": "-sn -T2 -PS22,80,443 --host-timeout 60s",
            "service_args": "-sT -sV -T2 --top-ports 50 -Pn --host-timeout 240s",
        },
    },
}

DEFAULT_PRESET = "fast"


def get_preset(scan_type: str, preset: str | None) -> dict:
    """Return the preset config dict for the given scan_type, falling back to default."""
    types = PRESETS.get(scan_type, {})
    if not types:
        return {}
    name = (preset or DEFAULT_PRESET).lower()
    return types.get(name) or types[DEFAULT_PRESET]


def list_presets() -> dict:
    """Return a metadata-only view (no internal nmap args) for the frontend."""
    return {
        scan_type: [
            {"name": name, "label": cfg["label"], "description": cfg["description"]}
            for name, cfg in presets.items()
        ]
        for scan_type, presets in PRESETS.items()
    }
