from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class BugFinding:
    file_path: Path
    line: int
    bug_type: str
    severity: str
    description: str
    debug_steps: list[str]
    combined_debug_note: str


@dataclass(slots=True)
class AnalysisSummary:
    project_path: Path
    started_at: str
    ended_at: str
    scanned_files: int
    findings: list[BugFinding] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for x in self.findings if x.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for x in self.findings if x.severity == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for x in self.findings if x.severity == "medium")

    @property
    def low_count(self) -> int:
        return sum(1 for x in self.findings if x.severity == "low")
