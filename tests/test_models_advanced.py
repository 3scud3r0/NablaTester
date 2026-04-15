from pathlib import Path

from nablatester.models import AnalysisSummary, BugFinding, Severity


def test_bug_finding_normalization_and_risk_score() -> None:
    f = BugFinding(
        file_path=Path("x.py"),
        line=0,
        bug_type="security/test",
        severity="CRITICAL",
        description=" demo ",
        debug_steps=["a"],
        combined_debug_note="b",
        confidence=1.2,
    )
    assert f.line == 1
    assert f.severity == "critical"
    assert f.severity_level == Severity.CRITICAL
    assert f.risk_score == 1.0
    assert len(f.fingerprint) == 40


def test_analysis_summary_distributions_and_prioritization() -> None:
    findings = [
        BugFinding(Path("a.py"), 1, "x", "low", "d", ["s"], "n", confidence=1.0),
        BugFinding(Path("a.py"), 2, "y", "critical", "d", ["s"], "n", confidence=0.5),
        BugFinding(Path("a.py"), 2, "y", "critical", "d", ["s"], "n", confidence=0.5),
    ]
    summary = AnalysisSummary(
        project_path=Path("."),
        started_at="2026-04-15T00:00:00+00:00",
        ended_at="2026-04-15T00:00:10+00:00",
        scanned_files=1,
        findings=findings,
    )

    assert summary.duration_seconds == 10.0
    assert summary.severity_distribution["critical"] == 2
    assert len(summary.deduplicated_findings) == 2
    assert summary.prioritized_findings[0].severity == "critical"
    assert "findings" in summary.to_dict()
