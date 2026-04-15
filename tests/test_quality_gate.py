from pathlib import Path

from nablatester.autofix import cascade_autofix
from nablatester.quality_gate import run_quality_gate


def test_quality_gate_passes_compileall(tmp_path: Path) -> None:
    project = tmp_path / "p"
    project.mkdir()
    (project / "a.py").write_text("x = 1\n", encoding="utf-8")

    result = run_quality_gate(project, ["python -m compileall ."])
    assert result.passed is True


def test_autofix_rewrites_shell_true_string_to_safe_list(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "runner.py").write_text(
        "import subprocess\n"
        "def runit():\n"
        "    subprocess.run('ls -la /tmp', shell=True)\n",
        encoding="utf-8",
    )

    target = tmp_path / "source_nablatester_fixed"
    stream = target / "cascade_stream.jsonl"
    fixed_path, _summary, _actions = cascade_autofix(source, target, stream, max_iterations=2)

    fixed = (fixed_path / "runner.py").read_text(encoding="utf-8")
    assert "subprocess.run(['ls', '-la', '/tmp'], shell=False)" in fixed
