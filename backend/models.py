"""
Core data models for the VA orchestration engine.
Every Finding here is produced by a real check that actually ran against
the target — nothing is pre-scripted or hardcoded per-target.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
import itertools

_id_counter = itertools.count(1)


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_WEIGHT = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

# Rough CVSS band -> severity anchor used for reporting only (not a real CVSS calculator)
SEVERITY_CVSS = {
    Severity.CRITICAL: 9.1,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.3,
    Severity.LOW: 3.1,
    Severity.INFO: 0.0,
}


@dataclass
class Finding:
    phase_id: str
    module: str
    title: str
    severity: Severity
    cwe: str
    endpoint: str
    evidence: str
    description: str
    remediation: str
    finding_id: str = field(default_factory=lambda: f"FIND-{next(_id_counter):04d}")
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    cvss: float = 0.0

    def __post_init__(self):
        if not self.cvss:
            self.cvss = SEVERITY_CVSS.get(self.severity, 0.0)

    def to_dict(self):
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class LogEvent:
    level: str  # INFO | WARN | CRIT | SUCCESS
    message: str
    phase_id: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self):
        return asdict(self)


PHASES = [
    {"id": "phase-1", "name": "Transport Layer & TLS Hardening", "module": "tls_scanner"},
    {"id": "phase-2", "name": "HTTP Header & Config Hardening", "module": "http_headers_scanner"},
    {"id": "phase-3", "name": "Identity, Session & Token Verification", "module": "session_scanner"},
    {"id": "phase-4", "name": "Input Validation & Injection", "module": "injection_scanner"},
    {"id": "phase-5", "name": "Access Control (BOLA/IDOR)", "module": "access_control_scanner"},
    {"id": "phase-6", "name": "External Tool Integration (Kali/Parrot)", "module": "external_tools"},
]
