from pathlib import Path

from bugsuite.engine import run_analysis


def test_run_analysis_detects_findings_and_writes_pdf(tmp_path: Path) -> None:
    project = tmp_path / "demo"
    project.mkdir()
    (project / "main.py").write_text(
        "import subprocess\n"
        "TOKEN = 'abc12345678910'\n"
        "def x(a):\n"
        "    return eval(a)\n"
        "subprocess.run('echo hi', shell=True)\n",
        encoding="utf-8",
    )

    output = project / "bugsuite_report.pdf"
    summary = run_analysis(project, output)

    assert summary.scanned_files == 1
    assert len(summary.findings) >= 3
    assert output.exists()
    assert output.read_bytes().startswith(b"%PDF-1.4")
