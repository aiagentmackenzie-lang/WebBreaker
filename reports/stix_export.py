"""STIX 2.1 Export — Threat intelligence sharing format."""

import json
from datetime import datetime, timezone


def generate_stix_bundle(findings: list[dict], target: str, scan_id: str) -> dict:
    """Convert scan findings to a STIX 2.1 Bundle."""
    objects = []
    now = datetime.now(timezone.utc).isoformat()

    # Identity object (WebBreaker)
    identity_id = "identity--webbreaker-1-0-0"
    objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now,
        "modified": now,
        "name": "WebBreaker",
        "identity_class": "software",
        "description": "WebBreaker Web Application Penetration Testing Toolkit",
    })

    # Target as infrastructure
    target_id = f"infrastructure--{scan_id}"
    objects.append({
        "type": "infrastructure",
        "spec_version": "2.1",
        "id": target_id,
        "created": now,
        "modified": now,
        "name": f"Assessed Target: {target}",
        "infrastructure_types": ["targeted"],
    })

    # Map finding types to MITRE ATT&CK / CAPEC
    ATTACK_MAP = {
        "SQL Injection": {"attack": "T1190", "capec": "CAPEC-108", "name": "Exploit Public-Facing Application"},
        "Cross-Site Scripting": {"attack": "T1059.007", "capec": "CAPEC-63", "name": "XSS"},
        "CSRF": {"capec": "CAPEC-62", "name": "Cross-Site Request Forgery"},
        "Command Injection": {"attack": "T1190", "capec": "CAPEC-88", "name": "OS Command Injection"},
        "Local File Inclusion": {"attack": "T1083", "capec": "CAPEC-31", "name": "Path Traversal"},
        "Remote File Inclusion": {"attack": "T1083", "capec": "CAPEC-31", "name": "Remote File Inclusion"},
        "Parameter Fuzzing": {"attack": "T1595", "name": "Active Scanning"},
        "Security Headers": {"attack": "T1595", "name": "Configuration Weakness"},
        "Session Analysis": {"attack": "T1539", "name": "Steal Session"},
        "Directory Discovery": {"attack": "T1083", "capec": "CAPEC-116", "name": "Directory Discovery"},
    }

    for i, finding in enumerate(findings):
        ftype = finding.get("type", "")
        mapping = ATTACK_MAP.get(ftype, {"name": ftype})

        # Vulnerability object
        vuln_id = f"vulnerability--{scan_id}-{i:04d}"
        objects.append({
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": vuln_id,
            "created": now,
            "modified": now,
            "name": f"{ftype}: {finding.get('parameter', '')}",
            "description": finding.get("evidence", ""),
            "severity": finding.get("severity", "INFO").lower(),
            "external_references": [
                {"source_name": "url", "url": finding.get("url", "")},
            ] + ([{"source_name": "mitre-attack", "external_id": mapping["attack"]}] if "attack" in mapping else [])
            + ([{"source_name": "capec", "external_id": mapping["capec"]}] if "capec" in mapping else []),
        })

        # Attack pattern object
        attack_id = f"attack-pattern--{scan_id}-{i:04d}"
        objects.append({
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": attack_id,
            "created": now,
            "modified": now,
            "name": mapping.get("name", ftype),
        })

        # Relationship: vulnerability targets infrastructure
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{scan_id}-{i:04d}-targets",
            "created": now,
            "modified": now,
            "relationship_type": "targets",
            "source_ref": vuln_id,
            "target_ref": target_id,
        })

        # Indicator object for payloads
        if finding.get("payload"):
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{scan_id}-{i:04d}",
                "created": now,
                "modified": now,
                "name": f"Payload: {finding['payload'][:50]}",
                "pattern": f"[url:value = '{finding.get('url', '')}']",
                "pattern_type": "stix",
                "valid_from": now,
            })

    return {
        "type": "bundle",
        "id": f"bundle--{scan_id}",
        "objects": objects,
    }


def export_stix_json(findings: list[dict], target: str, scan_id: str, output_path: str = None) -> str:
    """Export findings as STIX 2.1 JSON."""
    bundle = generate_stix_bundle(findings, target, scan_id)
    json_str = json.dumps(bundle, indent=2)
    if output_path:
        with open(output_path, "w") as f:
            f.write(json_str)
    return json_str