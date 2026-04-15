import json
from pathlib import Path

from nablatester.engine import run_analysis
from nablatester.sarif_writer import write_sarif


def test_parallel_and_single_worker_produce_findings(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "a.py").write_text("x = input('cmd:')\n", encoding="utf-8")
    (project / "b.py").write_text("eval('1+1')\n", encoding="utf-8")

    summary_single = run_analysis(project, project / "single.pdf", workers=1)
    summary_multi = run_analysis(project, project / "multi.pdf", workers=4)

    assert len(summary_single.findings) == len(summary_multi.findings)


def test_sarif_writer_outputs_valid_structure(tmp_path: Path) -> None:
    project = tmp_path / "p"
    project.mkdir()
    (project / "main.py").write_text("eval('1+1')\n", encoding="utf-8")

    summary = run_analysis(project, project / "report.pdf")
    sarif_path = project / "report.sarif"
    write_sarif(summary, sarif_path)

    payload = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"]
