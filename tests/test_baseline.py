from pathlib import Path

from nablatester.engine import run_analysis


def test_run_analysis_can_ignore_fingerprints(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "main.py").write_text("eval('1+1')\n", encoding="utf-8")

    first = run_analysis(project, project / "a.pdf")
    assert first.findings

    ignored = {first.findings[0].fingerprint}
    second = run_analysis(project, project / "b.pdf", ignore_fingerprints=ignored)

    assert len(second.findings) < len(first.findings)
