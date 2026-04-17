"""WebBreaker AI Triage — Ollama-powered finding prioritization and analysis."""

import json
from typing import Optional


AI_TRIAGE_PROMPT = """You are a security analyst triaging web application pentest findings.
Given the following findings from a scan, provide:

1. **Prioritized findings** — Rank by real-world exploitability and business impact (not just severity label)
2. **False positive assessment** — Flag findings likely to be false positives
3. **Attack narrative** — Describe how an attacker would chain these findings
4. **Remediation priority** — What to fix first, second, third
5. **Executive summary** — 3-4 sentence non-technical summary for leadership

Findings:
{findings_json}

Respond in JSON format:
{{
  "prioritized": [{{"index": 0, "priority": "P1|P2|P3", "reason": "..."}}],
  "false_positives": [{{"index": 0, "reason": "..."}}],
  "attack_narrative": "...",
  "remediation_priority": [{{"order": 1, "finding_index": 0, "action": "..."}}],
  "executive_summary": "..."
}}"""


class AITriage:
    """Ollama-powered AI triage for scan findings."""

    def __init__(self, model: str = "webbreaker-triage", ollama_host: str = "http://localhost:11434"):
        self.model = model
        self.ollama_host = ollama_host
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                import ollama
                self._client = ollama.Client(host=self.ollama_host)
            except ImportError:
                return None
        return self._client

    def triage_findings(self, findings: list[dict]) -> Optional[dict]:
        """Analyze and prioritize findings using AI."""
        client = self._get_client()
        if not client:
            return self._fallback_triage(findings)

        findings_text = json.dumps(findings[:20], indent=2)  # Limit to 20 findings for context
        prompt = AI_TRIAGE_PROMPT.format(findings_json=findings_text)

        try:
            response = client.chat(model=self.model, messages=[
                {"role": "system", "content": "You are a senior web application security analyst. Respond only in valid JSON."},
                {"role": "user", "content": prompt},
            ])

            content = response["message"]["content"]
            # Try to parse JSON from response
            try:
                # Handle markdown-wrapped JSON
                if "```json" in content:
                    content = content.split("```json")[1].split("```")[0].strip()
                elif "```" in content:
                    content = content.split("```")[1].split("```")[0].strip()
                return json.loads(content)
            except json.JSONDecodeError:
                return {"raw_analysis": content, "parsed": False}

        except Exception as e:
            return self._fallback_triage(findings, error=str(e))

    def generate_payload_mutations(self, finding: dict, response_sample: str = "") -> list[str]:
        """Generate mutated payloads based on a finding and response context."""
        client = self._get_client()
        if not client:
            return self._heuristic_mutations(finding)

        prompt = f"""Given this vulnerability finding:
{json.dumps(finding, indent=2)}

And this response sample:
{response_sample[:500]}

Generate 5 mutated payloads that might bypass WAF/filtering for this vulnerability type.
Return as a JSON array of strings."""

        try:
            response = client.chat(model=self.model, messages=[
                {"role": "system", "content": "You are an offensive security expert. Respond only in valid JSON array."},
                {"role": "user", "content": prompt},
            ])
            content = response["message"]["content"]
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            return json.loads(content)
        except Exception:
            return self._heuristic_mutations(finding)

    def generate_report_summary(self, findings: list[dict], target: str) -> str:
        """Generate an AI executive summary for a report."""
        client = self._get_client()
        if not client:
            return self._fallback_summary(findings, target)

        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        prompt = f"""Write a professional executive summary for a security assessment of {target}.

Findings summary:
- Total findings: {len(findings)}
- By severity: {json.dumps(severity_counts)}

Top 5 findings:
{json.dumps(findings[:5], indent=2)}

Write 3-4 sentences suitable for executive leadership. Focus on risk and recommended actions."""

        try:
            response = client.chat(model=self.model, messages=[
                {"role": "system", "content": "You are a CISO writing an executive summary. Be concise and professional."},
                {"role": "user", "content": prompt},
            ])
            return response["message"]["content"]
        except Exception:
            return self._fallback_summary(findings, target)

    def _fallback_triage(self, findings: list[dict], error: str = "") -> dict:
        """Rule-based fallback when AI is unavailable."""
        prioritized = []
        for i, f in enumerate(findings):
            sev = f.get("severity", "INFO")
            priority = {"CRITICAL": "P1", "HIGH": "P1", "MEDIUM": "P2", "LOW": "P3", "INFO": "P3"}.get(sev, "P3")
            confidence = f.get("confidence", 1.0)
            if confidence < 0.5:
                priority = "P3"  # Low confidence = lower priority
            prioritized.append({"index": i, "priority": priority, "reason": f"Severity: {sev}, Confidence: {confidence}"})

        false_positives = [
            {"index": i, "reason": f"Low confidence ({f.get('confidence', 1.0)})"}
            for i, f in enumerate(findings) if f.get("confidence", 1.0) < 0.5
        ]

        return {
            "prioritized": prioritized,
            "false_positives": false_positives,
            "attack_narrative": "AI analysis unavailable. Review findings manually.",
            "remediation_priority": [{"order": i + 1, "finding_index": p["index"], "action": findings[p["index"]].get("remediation", "Review and remediate")}
                                     for i, p in enumerate(prioritized[:5]) if p["priority"] in ("P1", "P2")],
            "executive_summary": self._fallback_summary(findings, findings[0]["url"] if findings else "unknown"),
            "ai_available": False,
            "error": error,
        }

    def _fallback_summary(self, findings: list[dict], target: str) -> str:
        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        parts = [f"A security assessment of {target} identified {len(findings)} findings."]
        if severity_counts.get("CRITICAL"):
            parts.append(f"CRITICAL: {severity_counts['CRITICAL']} critical vulnerabilities require immediate attention.")
        if severity_counts.get("HIGH"):
            parts.append(f"HIGH: {severity_counts['HIGH']} high-severity issues need priority remediation.")
        if severity_counts.get("MEDIUM"):
            parts.append(f"{severity_counts.get('MEDIUM', 0)} medium findings should be addressed in the next sprint.")
        parts.append("Full remediation details are available in the technical report.")
        return " ".join(parts)

    def _heuristic_mutations(self, finding: dict) -> list[str]:
        """Generate heuristic payload mutations when AI is unavailable."""
        ftype = finding.get("type", "").lower()
        payload = finding.get("payload", "")
        mutations = []

        if "sql" in ftype:
            mutations = [
                payload.replace(" ", "/**/"),
                payload.replace("'", "\""),
                payload.replace("1=1", "2=2"),
                payload + "%00",
                payload.replace("SELECT", "SeLeCt"),
            ]
        elif "xss" in ftype:
            mutations = [
                payload.replace("alert", "confirm"),
                payload.replace("<script", "<ScRiPt"),
                payload.replace(" ", "/"),
                payload.replace(">", "%3e"),
                payload.replace("onerror", "onfocus"),
            ]
        elif "command" in ftype:
            mutations = [
                payload.replace(";", "%0a"),
                payload.replace("sleep", "timeout"),
                payload.replace("|", "||"),
                payload.replace("echo", "printf"),
                payload.replace(" ", "$IFS"),
            ]
        else:
            mutations = [payload + suffix for suffix in ["%00", "%0a", "../", "'\"", "\"'"]]

        return [m for m in mutations if m != payload][:5]