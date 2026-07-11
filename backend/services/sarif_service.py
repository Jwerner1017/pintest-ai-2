"""SARIF 2.1.0 export for PentestAI scan/report data.

SARIF is consumed by GitHub Code Scanning, GitLab SAST, Azure DevOps, etc.
Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""
from datetime import datetime, timezone

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json"

# SARIF mandates: none / note / warning / error
SEV_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
}


def build_sarif_for_scans(scans: list[dict]) -> dict:
    """Generate a SARIF 2.1 document from a list of scan documents."""
    runs = []
    for scan in scans:
        runs.append(_run_for_scan(scan))
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": runs,
    }


def _run_for_scan(scan: dict) -> dict:
    results = scan.get("results") or {}
    vulns = results.get("vulnerabilities") or []

    # Build the rules table from unique vulnerability ids.
    rules_index: dict[str, int] = {}
    rules: list[dict] = []
    sarif_results: list[dict] = []

    for v in vulns:
        rule_id = v.get("id") or "PENTESTAI-UNKNOWN"
        if rule_id not in rules_index:
            rules_index[rule_id] = len(rules)
            rules.append(_rule(v))

        sarif_results.append(_result(v, rules_index[rule_id], scan.get("target")))

    return {
        "tool": {
            "driver": {
                "name": "PentestAI",
                "version": "1.5.0",
                "informationUri": "https://pentestai.example",
                "rules": rules,
                "properties": {
                    "scanType": scan.get("scan_type"),
                    "preset": results.get("preset"),
                    "scanEngine": results.get("scan_engine"),
                },
            }
        },
        "invocations": [{
            "executionSuccessful": scan.get("status") == "completed",
            "startTimeUtc": _iso(scan.get("created_at")),
            "endTimeUtc": _iso(datetime.now(timezone.utc).isoformat()),
        }],
        "results": sarif_results,
        "properties": {
            "scanId": scan.get("id"),
            "target": scan.get("target"),
            "riskScore": results.get("risk_score"),
            "owaspHits": (results.get("compliance") or {}).get("owasp_top10_hits") or [],
        },
    }


def _rule(v: dict) -> dict:
    rule_id = v.get("id") or "PENTESTAI-UNKNOWN"
    severity = (v.get("severity") or "info").lower()
    return {
        "id": rule_id,
        "name": _camel(rule_id),
        "shortDescription": {"text": (v.get("description") or rule_id)[:120]},
        "fullDescription": {"text": v.get("description") or rule_id},
        "help": {
            "text": v.get("remediation") or "See description.",
        },
        "defaultConfiguration": {
            "level": SEV_TO_SARIF_LEVEL.get(severity, "none"),
        },
        "properties": {
            "tags": [v.get("source") or "pentestai", severity],
            "security-severity": _cvss_for_severity(v),
        },
    }


def _result(v: dict, rule_index: int, target: str | None) -> dict:
    severity = (v.get("severity") or "info").lower()
    return {
        "ruleId": v.get("id") or "PENTESTAI-UNKNOWN",
        "ruleIndex": rule_index,
        "level": SEV_TO_SARIF_LEVEL.get(severity, "none"),
        "message": {"text": v.get("description") or "No description"},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    # SARIF needs a uri — synthesize one from the target so consumers can group.
                    "uri": _target_to_uri(target),
                },
                "region": {"startLine": 1},
            },
            "logicalLocations": [{
                "name": target or "unknown",
                "kind": "host",
            }],
        }],
        "properties": {
            "severity": severity,
            "cvss": v.get("cvss"),
            "source": v.get("source"),
            "references": v.get("references", []),
        },
    }


def _target_to_uri(target: str | None) -> str:
    if not target:
        return "pentestai://unknown"
    if "://" in target:
        return target
    return f"pentestai://target/{target}"


def _camel(s: str) -> str:
    return "".join(p.capitalize() for p in s.replace("-", "_").split("_") if p) or "Rule"


def _cvss_for_severity(v: dict) -> str:
    """SARIF security-severity is a CVSS 0.0-10.0 numeric string."""
    if isinstance(v.get("cvss"), (int, float)):
        return f"{float(v['cvss']):.1f}"
    fallback = {
        "critical": "9.5",
        "high": "8.0",
        "medium": "5.5",
        "low": "3.0",
        "info": "1.0",
    }
    return fallback.get((v.get("severity") or "info").lower(), "1.0")


def _iso(ts: str | None) -> str:
    if not ts:
        return datetime.now(timezone.utc).isoformat()
    return ts
