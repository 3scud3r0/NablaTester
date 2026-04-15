from pathlib import Path

from nablatester.autofix import cascade_autofix
from nablatester.engine import run_analysis


def test_autofix_handles_use_before_assign_with_safe_initialization(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "u.py").write_text(
        "def f():\n"
        "    x\n"
        "    x = 1\n",
        encoding="utf-8",
    )

    target = tmp_path / "source_nablatester_fixed"
    stream = target / "cascade_stream.jsonl"
    fixed_path, _summary, _actions = cascade_autofix(source, target, stream, max_iterations=2)

    code = (fixed_path / "u.py").read_text(encoding="utf-8")
    assert "x = None  # inicialização automática NablaTester" in code


def test_interprocedural_import_alias_detection_across_files(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "sinks.py").write_text(
        "def do_exec(v):\n"
        "    eval(v)\n",
        encoding="utf-8",
    )
    (project / "main.py").write_text(
        "from sinks import do_exec\n"
        "payload = input('cmd:')\n"
        "do_exec(payload)\n",
        encoding="utf-8",
    )

    summary = run_analysis(project, project / "nablatester_report.pdf")
    types = {f.bug_type for f in summary.findings}
    assert "security/interprocedural-taint" in types
