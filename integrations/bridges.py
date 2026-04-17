"""Portfolio integration bridges — connect WebBreaker to GHOSTWIRE, HATCHERY, DEADDROP, HONEYTRAP."""


class GhostwireBridge:
    """Send captured HTTP traffic to GHOSTWIRE for network-level analysis."""

    def __init__(self, ghostwire_url: str = "http://localhost:3001"):
        self.ghostwire_url = ghostwire_url

    def send_pcap_data(self, scan_id: str, requests: list[dict]) -> dict:
        """Export scan HTTP requests in PCAP-like format for GHOSTWIRE ingestion."""
        return {
            "source": "webbreaker",
            "scan_id": scan_id,
            "type": "http_traffic",
            "entries": requests,
            "format": "webbreaker-http-v1",
        }

    def export_for_ghostwire(self, scan_data: dict, findings: list[dict]) -> dict:
        """Prepare data package for GHOSTWIRE import."""
        suspicious_ips = set()
        suspicious_domains = set()
        for f in findings:
            if f.get("severity") in ("CRITICAL", "HIGH"):
                url = f.get("url", "")
                if "://" in url:
                    domain = url.split("://")[1].split("/")[0].split(":")[0]
                    suspicious_domains.add(domain)

        return {
            "source": "webbreaker",
            "scan_id": scan_data.get("id", ""),
            "target": scan_data.get("target", ""),
            "suspicious_domains": list(suspicious_domains),
            "suspicious_ips": list(suspicious_ips),
            "findings_count": len(findings),
            "high_severity_count": sum(1 for f in findings if f.get("severity") in ("CRITICAL", "HIGH")),
        }


class HatcheryBridge:
    """Send discovered malicious payloads to HATCHERY for sandbox analysis."""

    def __init__(self, hatchery_url: str = "http://localhost:3002"):
        self.hatchery_url = hatchery_url

    def prepare_submission(self, scan_id: str, findings: list[dict]) -> list[dict]:
        """Convert payloads into HATCHERY submission format."""
        submissions = []
        for f in findings:
            if f.get("severity") in ("CRITICAL", "HIGH") and f.get("payload"):
                submissions.append({
                    "source": f"webbreaker:{scan_id}",
                    "payload": f.get("payload", ""),
                    "finding_type": f.get("type", ""),
                    "url": f.get("url", ""),
                    "parameter": f.get("parameter", ""),
                    "evidence": f.get("evidence", ""),
                    "auto_submit": False,  # Require manual confirmation
                })
        return submissions


class DeaddropBridge:
    """Export findings as forensic evidence for DEADDROP."""

    def __init__(self, deaddrop_url: str = "http://localhost:3003"):
        self.deaddrop_url = deaddrop_url

    def export_evidence_package(self, scan_id: str, scan_data: dict, findings: list[dict], recon: list[dict] = None) -> dict:
        """Create a chain-of-custody evidence package for DEADDROP."""
        import hashlib
        import json
        import time

        evidence_items = []
        for i, f in enumerate(findings):
            item_json = json.dumps(f, sort_keys=True)
            item_hash = hashlib.sha256(item_json.encode()).hexdigest()
            evidence_items.append({
                "id": f"WB-{scan_id}-{i:04d}",
                "type": "web_finding",
                "finding": f,
                "sha256": item_hash,
                "collected_at": f.get("timestamp", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
                "collector": "WebBreaker/1.0.0",
                "chain_of_custody": [
                    {
                        "action": "collected",
                        "by": "WebBreaker",
                        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    }
                ],
            })

        package_json = json.dumps(evidence_items, sort_keys=True)
        package_hash = hashlib.sha256(package_json.encode()).hexdigest()

        return {
            "source": "webbreaker",
            "scan_id": scan_id,
            "target": scan_data.get("target", ""),
            "evidence_items": evidence_items,
            "total_items": len(evidence_items),
            "package_sha256": package_hash,
            "export_format": "deaddrop-v1",
        }


class HoneytrapBridge:
    """Feed attacker IOCs to HONEYTRAP for deception deployment."""

    def __init__(self, honeytrap_url: str = "http://localhost:3004"):
        self.honeytrap_url = honeytrap_url

    def extract_iocs(self, findings: list[dict]) -> dict:
        """Extract indicators of compromise for HONEYTRAP honeypot deployment."""
        iocs = {
            "payloads": [],
            "attack_patterns": [],
            "target_endpoints": [],
        }

        seen_payloads = set()
        for f in findings:
            payload = f.get("payload", "")
            if payload and payload not in seen_payloads and len(payload) > 5:
                seen_payloads.add(payload)
                iocs["payloads"].append({
                    "value": payload,
                    "type": f.get("type", ""),
                    "severity": f.get("severity", ""),
                })

            ftype = f.get("type", "")
            if ftype and ftype not in iocs["attack_patterns"]:
                iocs["attack_patterns"].append(ftype)

            url = f.get("url", "")
            if url and url not in iocs["target_endpoints"]:
                iocs["target_endpoints"].append(url)

        return iocs