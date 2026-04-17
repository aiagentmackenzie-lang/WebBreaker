"""Shared configuration and constants for WebBreaker."""

from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingType(Enum):
    SQLI = "SQL Injection"
    XSS = "Cross-Site Scripting"
    CSRF = "CSRF"
    CMDI = "Command Injection"
    LFI = "Local File Inclusion"
    RFI = "Remote File Inclusion"
    DIRBRUTE = "Directory Discovery"
    FUZZ = "Parameter Fuzzing"
    HEADERS = "Security Headers"
    SESSION = "Session Analysis"


@dataclass
class Finding:
    finding_type: FindingType
    severity: Severity
    url: str
    parameter: str
    payload: str
    evidence: str
    request: str = ""
    response: str = ""
    remediation: str = ""
    confidence: float = 1.0  # 0.0 - 1.0
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "type": self.finding_type.value,
            "severity": self.severity.value,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "request": self.request,
            "response": self.response,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
        }


@dataclass
class ScanConfig:
    target: str
    modules: list[str] = field(default_factory=list)
    depth: int = 3
    threads: int = 20
    timeout: int = 10
    delay: float = 0.0
    proxy: Optional[str] = None
    auth_header: Optional[str] = None
    cookies: Optional[dict] = None
    user_agent: str = "WebBreaker/1.0"
    scope: Optional[str] = None
    authorized: bool = False
    stealth: bool = False
    rate_limit: int = 100  # requests per second

    def __post_init__(self):
        if not self.authorized:
            raise PermissionError(
                "❌ Authorization required. Use --auth flag to confirm authorized testing."
            )
        if self.scope is None:
            self.scope = self.target