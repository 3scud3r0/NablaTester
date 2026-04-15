from pathlib import Path

from nablatester.detectors import TEXT_EXTENSIONS
from nablatester.engine import run_analysis


def test_language_extension_coverage_is_enterprise_scale() -> None:
    assert len(TEXT_EXTENSIONS) >= 35


def test_run_analysis_emits_progress_with_eta(tmp_path: Path) -> None:
    project = tmp_path / "repo"
    project.mkdir()
    (project / "a.py").write_text("x = 1\n", encoding="utf-8")
    (project / "b.py").write_text("y = input('v')\n", encoding="utf-8")

    events: list[dict] = []

    def callback(event: dict) -> None:
        events.append(event)

    output = project / "nablatester_report.pdf"
    run_analysis(project, output, progress_callback=callback)

    assert events
    assert events[-1]["percent"] == 100.0
    assert "eta_seconds" in events[-1]
    assert output.exists()
