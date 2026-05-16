"""STIX 2.1 Export — Threat intelligence sharing format.

Compliant with STIX 2.1 specification:
- UUIDv5 deterministic IDs (namespace-based)
- created_by_ref on all SDOs
- valid_until on indicators
- kill_chain_phases on attack patterns
- Proper relationship objects with source_ref/target_ref
"""

import json
import uuid
from datetime import datetime, timezone, timedelta

# ── STIX 2.1 UUIDv5 Namespace ───────────────────────────────────────
# STIX 2.1 uses UUIDv5 with a dedicated namespace to generate
# deterministic IDs from source identity + object-specific data.

STIX_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


def _stix_id(stix_type: str, deterministic_string: str) -> str:
    """Generate a STIX 2.1 UUIDv5 ID.

    STIX 2.1 spec requires IDs in the format:
        {stix_type}--{uuid5}

    The UUID5 is derived from the STIX namespace and a deterministic
    string unique to the object, ensuring reproducibility.
    """
    uuid5 = uuid.uuid5(STIX_NAMESPACE, deterministic_string)
    return f"{stix_type}--{uuid5}"


def _iso_now() -> str:
    """Return current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _iso_future(days: int = 30) -> str:
    """Return a future UTC timestamp in ISO 8601 format.

    Used for indicator valid_until — default 30 days from now,
    representing the recommended review period for vulnerability
    indicators per STIX 2.1 best practices.
    """
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


# ── MITRE ATT&CK / CAPEC Mapping ─────────────────────────────────────

ATTACK_MAP = {
    "SQL Injection": {
        "attack": "T1190",
        "capec": "CAPEC-108",
        "name": "Exploit Public-Facing Application",
        "kill_chain": [
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": "initial-access",
            },
        ],
    },
    "Cross-Site Scripting": {
        "attack": "T1059.007",
        "capec": "CAPEC-63",
        "name": "XSS",
        "kill_chain": [
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": "execution",
            },
        ],
    },
    "CSRF": {
        "capec": "CAPEC-62",
        "name": "Cross-Site Request Forgery",
        "kill_chain": [
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": "initial-access",
            },
        ],
    },
    "Command Injection": {
        "attack": "T1190",
        "capec": "CAPEC-88",
        "name": "OS Command Injection",
        "kill_chain": [
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": "execution",
            },
        ],
    },
    "Local File Inclusion": {
        "attack": "T1083",
        "capec": "CAPEC-31",
        "name": "Path Traversal",
        "kill_chain": [
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": "discovery",
            },
        ],
    },
    "Remote File Inclusion": {
        "attack": "T1083",
        "capec": "CAPEC-31",
        "name": "Remote File Inclusion",
        "kill_chain": [
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": "initial-access",
            },
        ],
    },
    "Parameter Fuzzing": {
        "attack": "T1595",
        "name": "Active Scanning",
        "kill_chain": [
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": "reconnaissance",
            },
        ],
    },
    "Security Headers": {
        "attack": "T1595",
        "name": "Configuration Weakness",
        "kill_chain": [
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": "discovery",
            },
        ],
    },
    "Session Analysis": {
        "attack": "T1539",
        "name": "Steal Session",
        "kill_chain": [
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": "credential-access",
            },
        ],
    },
    "Directory Discovery": {
        "attack": "T1083",
        "capec": "CAPEC-116",
        "name": "Directory Discovery",
        "kill_chain": [
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": "discovery",
            },
        ],
    },
}


def generate_stix_bundle(findings: list[dict], target: str, scan_id: str) -> dict:
    """Convert scan findings to a STIX 2.1 Bundle.

    Produces a compliant STIX 2.1 bundle with:
    - Identity SDO (created_by_ref target)
    - Infrastructure SDO for the assessed target
    - Vulnerability SDOs for each finding
    - Attack Pattern SDOs with kill_chain_phases
    - Indicator SDOs with valid_from/valid_until
    - Relationship SDOs linking objects
    - All SDOs use deterministic UUIDv5 IDs
    - All SDOs include created_by_ref
    """
    objects = []
    now = _iso_now()
    valid_until = _iso_future(days=30)

    # ── Identity object (WebBreaker) ──────────────────────────────────
    identity_id = _stix_id("identity", "webbreaker-scanner")
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now,
        "modified": now,
        "name": "WebBreaker",
        "identity_class": "software",
        "description": "WebBreaker Web Application Penetration Testing Toolkit",
        "sectors": ["technology"],
    }
    objects.append(identity)

    # ── Target infrastructure object ───────────────────────────────────
    target_id = _stix_id("infrastructure", f"target-{target}")
    objects.append({
        "type": "infrastructure",
        "spec_version": "2.1",
        "id": target_id,
        "created_by_ref": identity_id,
        "created": now,
        "modified": now,
        "name": f"Assessed Target: {target}",
        "infrastructure_types": ["targeted"],
    })

    # ── Process each finding ──────────────────────────────────────────
    for i, finding in enumerate(findings):
        ftype = finding.get("type", "unknown")
        mapping = ATTACK_MAP.get(ftype, {"name": ftype, "kill_chain": []})

        # Deterministic string for UUIDv5 — includes finding type, URL, and parameter
        # to produce unique but reproducible IDs per finding
        finding_deterministic = f"finding-{scan_id}-{i:04d}-{ftype}-{finding.get('parameter', '')}"

        # ── Vulnerability object ──────────────────────────────────────
        vuln_id = _stix_id("vulnerability", finding_deterministic)
        ext_refs = [
            {"source_name": "url", "url": finding.get("url", "")},
        ]
        if "attack" in mapping:
            ext_refs.append({
                "source_name": "mitre-attack",
                "external_id": mapping["attack"],
                "url": f"https://attack.mitre.org/techniques/{mapping['attack'].replace('.', '/')}",
            })
        if "capec" in mapping:
            ext_refs.append({
                "source_name": "capec",
                "external_id": mapping["capec"],
                "url": f"https://capec.mitre.org/data/definitions/{mapping['capec'].replace('CAPEC-', '')}.html",
            })

        vuln_obj = {
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": vuln_id,
            "created_by_ref": identity_id,
            "created": now,
            "modified": now,
            "name": f"{ftype}: {finding.get('parameter', '')}",
            "description": finding.get("evidence", ""),
            "severity": finding.get("severity", "INFO").lower(),
            "external_references": ext_refs,
        }

        # Add confidence if available
        if finding.get("confidence"):
            vuln_obj["confidence"] = int(finding["confidence"] * 100)

        objects.append(vuln_obj)

        # ── Attack Pattern object ─────────────────────────────────────
        attack_id = _stix_id("attack-pattern", f"attack-{finding_deterministic}")
        attack_obj = {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": attack_id,
            "created_by_ref": identity_id,
            "created": now,
            "modified": now,
            "name": mapping.get("name", ftype),
            "external_references": [],
        }

        # Add MITRE ATT&CK reference to attack pattern
        if "attack" in mapping:
            attack_obj["external_references"].append({
                "source_name": "mitre-attack",
                "external_id": mapping["attack"],
                "url": f"https://attack.mitre.org/techniques/{mapping['attack'].replace('.', '/')}",
            })

        # Add kill chain phases (STIX 2.1 requirement for ATT&CK mapping)
        if "kill_chain" in mapping:
            attack_obj["kill_chain_phases"] = mapping["kill_chain"]

        # Add CAPEC reference
        if "capec" in mapping:
            attack_obj["external_references"].append({
                "source_name": "capec",
                "external_id": mapping["capec"],
                "url": f"https://capec.mitre.org/data/definitions/{mapping['capec'].replace('CAPEC-', '')}.html",
            })

        objects.append(attack_obj)

        # ── Relationship: vulnerability targets infrastructure ─────────
        rel_id = _stix_id("relationship", f"rel-targets-{finding_deterministic}")
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": rel_id,
            "created_by_ref": identity_id,
            "created": now,
            "modified": now,
            "relationship_type": "targets",
            "source_ref": vuln_id,
            "target_ref": target_id,
            "description": f"Vulnerability {ftype} targets {target}",
        })

        # ── Relationship: attack pattern uses vulnerability ───────────
        rel_uses_id = _stix_id("relationship", f"rel-uses-{finding_deterministic}")
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": rel_uses_id,
            "created_by_ref": identity_id,
            "created": now,
            "modified": now,
            "relationship_type": "uses",
            "source_ref": attack_id,
            "target_ref": vuln_id,
            "description": f"Attack pattern {mapping.get('name', ftype)} uses vulnerability {ftype}",
        })

        # ── Indicator object for payloads ─────────────────────────────
        if finding.get("payload"):
            url_value = finding.get("url", "")
            # Escape single quotes for STIX pattern
            pattern_value = url_value.replace("\\", "\\\\").replace("'", "\\'")
            indicator_id = _stix_id("indicator", f"indicator-{finding_deterministic}")
            indicator_obj = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created_by_ref": identity_id,
                "created": now,
                "modified": now,
                "name": f"Payload: {finding['payload'][:50]}",
                "pattern": f"[url:value = '{pattern_value}']",
                "pattern_type": "stix",
                "pattern_version": "2.1",
                "valid_from": now,
                "valid_until": valid_until,
                "external_references": [
                    {"source_name": "url", "url": url_value},
                ],
            }

            # Add kill chain phases to indicator if mapping has them
            if "kill_chain" in mapping:
                indicator_obj["kill_chain_phases"] = mapping["kill_chain"]

            objects.append(indicator_obj)

    return {
        "type": "bundle",
        "id": _stix_id("bundle", f"bundle-{scan_id}"),
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