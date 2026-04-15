from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import hashlib
from pathlib import Path


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> float:
        return {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.5,
            Severity.LOW: 0.25,
            Severity.INFO: 0.1,
        }[self]


def normalize_severity(value: str | Severity) -> Severity:
    if isinstance(value, Severity):
        return value
    value_norm = str(value).strip().lower()
    for sev in Severity:
        if sev.value == value_norm:
            return sev
    return Severity.LOW


@dataclass(slots=True)
class BugFinding:
    file_path: Path
    line: int
    bug_type: str
    severity: str | Severity
    description: str
    debug_steps: list[str]
    combined_debug_note: str
    column: int | None = None
    rule_id: str | None = None
    confidence: float = 0.8
    cwe_tags: list[str] = field(default_factory=list)
    owasp_tags: list[str] = field(default_factory=list)
    evidence: str | None = None
    remediation_snippet: str | None = None
    references: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.file_path = Path(self.file_path)
        self.line = max(1, int(self.line))
        if self.column is not None:
            self.column = max(1, int(self.column))
        self.confidence = min(1.0, max(0.0, float(self.confidence)))
        self.severity = normalize_severity(self.severity).value
        self.bug_type = self.bug_type.strip()
        self.description = self.description.strip()

    @property
    def severity_level(self) -> Severity:
        return normalize_severity(self.severity)

    @property
    def risk_score(self) -> float:
        return round(self.severity_level.weight * self.confidence, 4)

    @property
    def fingerprint(self) -> str:
        payload = f"{self.file_path}|{self.line}|{self.bug_type}|{self.description}"
        return hashlib.sha1(payload.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict:
        return {
            "file_path": str(self.file_path),
            "line": self.line,
            "column": self.column,
            "bug_type": self.bug_type,
            "severity": self.severity,
            "rule_id": self.rule_id,
            "description": self.description,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "cwe_tags": list(self.cwe_tags),
            "owasp_tags": list(self.owasp_tags),
            "references": list(self.references),
            "fingerprint": self.fingerprint,
        }


@dataclass(slots=True)
class AnalysisSummary:
    project_path: Path
    started_at: str
    ended_at: str
    scanned_files: int
    findings: list[BugFinding] = field(default_factory=list)

    def _count(self, severity: Severity) -> int:
        return sum(1 for x in self.findings if x.severity_level == severity)

    @property
    def critical_count(self) -> int:
        return self._count(Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return self._count(Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return self._count(Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return self._count(Severity.LOW)

    @property
    def info_count(self) -> int:
        return self._count(Severity.INFO)

    @property
    def duration_seconds(self) -> float:
        try:
            start = datetime.fromisoformat(self.started_at)
            end = datetime.fromisoformat(self.ended_at)
            return max(0.0, (end - start).total_seconds())
        except ValueError:
            return 0.0

    @property
    def total_risk_score(self) -> float:
        return round(sum(f.risk_score for f in self.findings), 4)

    @property
    def severity_distribution(self) -> dict[str, int]:
        return {
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "info": self.info_count,
        }

    @property
    def type_distribution(self) -> dict[str, int]:
        dist: dict[str, int] = {}
        for finding in self.findings:
            dist[finding.bug_type] = dist.get(finding.bug_type, 0) + 1
        return dict(sorted(dist.items(), key=lambda kv: (-kv[1], kv[0])))

    @property
    def deduplicated_findings(self) -> list[BugFinding]:
        seen: set[str] = set()
        dedup: list[BugFinding] = []
        for finding in self.findings:
            if finding.fingerprint in seen:
                continue
            seen.add(finding.fingerprint)
            dedup.append(finding)
        return dedup

    @property
    def prioritized_findings(self) -> list[BugFinding]:
        return sorted(
            self.deduplicated_findings,
            key=lambda f: (-f.risk_score, str(f.file_path), f.line),
        )

    def to_dict(self) -> dict:
        return {
            "project_path": str(self.project_path),
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_seconds": self.duration_seconds,
            "scanned_files": self.scanned_files,
            "findings_total": len(self.findings),
            "severity_distribution": self.severity_distribution,
            "type_distribution": self.type_distribution,
            "total_risk_score": self.total_risk_score,
            "findings": [f.to_dict() for f in self.prioritized_findings],
        }
