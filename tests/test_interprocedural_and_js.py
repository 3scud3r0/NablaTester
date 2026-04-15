from pathlib import Path

from nablatester.engine import run_analysis


def test_interprocedural_taint_detects_cross_function_flow(tmp_path: Path) -> None:
    project = tmp_path / "p"
    project.mkdir()
    (project / "app.py").write_text(
        "def sink(v):\n"
        "    eval(v)\n\n"
        "x = input('cmd:')\n"
        "sink(x)\n",
        encoding="utf-8",
    )

    summary = run_analysis(project, project / "nablatester_report.pdf")
    bug_types = {f.bug_type for f in summary.findings}
    assert "security/interprocedural-taint" in bug_types


def test_javascript_semantic_detection_eval(tmp_path: Path) -> None:
    project = tmp_path / "js"
    project.mkdir()
    (project / "index.js").write_text("const a = input; eval(a);\n", encoding="utf-8")

    summary = run_analysis(project, project / "nablatester_report.pdf")
    bug_types = {f.bug_type for f in summary.findings}
    assert "security/js-eval" in bug_types


def test_interprocedural_multihop_flow_detection(tmp_path: Path) -> None:
    project = tmp_path / "mh"
    project.mkdir()
    (project / "chain.py").write_text(
        "def sink(v):\n"
        "    eval(v)\n\n"
        "def middle(m):\n"
        "    sink(m)\n\n"
        "data = input('cmd:')\n"
        "middle(data)\n",
        encoding="utf-8",
    )

    summary = run_analysis(project, project / "nablatester_report.pdf")
    bug_types = {f.bug_type for f in summary.findings}
    assert "security/interprocedural-taint" in bug_types


def test_interprocedural_detects_module_alias_call(tmp_path: Path) -> None:
    project = tmp_path / "pkgproj"
    (project / "pkg").mkdir(parents=True)
    (project / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (project / "pkg" / "sinks.py").write_text(
        "def do_exec(v):\n"
        "    eval(v)\n",
        encoding="utf-8",
    )
    (project / "main.py").write_text(
        "import pkg.sinks as s\n"
        "payload = input('cmd:')\n"
        "s.do_exec(payload)\n",
        encoding="utf-8",
    )

    summary = run_analysis(project, project / "nablatester_report.pdf")
    types = {f.bug_type for f in summary.findings}
    assert "security/interprocedural-taint" in types
