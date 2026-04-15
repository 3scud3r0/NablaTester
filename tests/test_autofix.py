from pathlib import Path

from bugsuite.autofix import cascade_autofix


def test_cascade_autofix_clones_project_applies_actions_and_streams(tmp_path: Path) -> None:
    source = tmp_path / "source_project"
    source.mkdir()
    (source / "app.py").write_text(
        "import subprocess\n"
        "API_KEY = 'token-super-secreto-123'\n"
        "# TODO: remover risco\n"
        "def run(x):\n"
        "    assert x\n"
        "    return eval(x)\n"
        "subprocess.run('echo oi', shell=True)\n",
        encoding="utf-8",
    )

    target = tmp_path / "source_project_bugsuite_fixed"
    stream = target / "cascade_stream.jsonl"

    fixed_path, summary, actions = cascade_autofix(
        project_path=source,
        target_path=target,
        report_stream_path=stream,
        max_iterations=4,
    )

    assert fixed_path.exists()
    assert stream.exists()
    assert actions

    fixed_code = (fixed_path / "app.py").read_text(encoding="utf-8")
    assert "ast.literal_eval" in fixed_code
    assert "shell=False" in fixed_code
    assert "os.getenv('API_KEY', '')" in fixed_code
    assert "TODO" not in fixed_code

    assert (fixed_path / "bugsuite_report.pdf").exists()
    assert len(summary.findings) >= 0
