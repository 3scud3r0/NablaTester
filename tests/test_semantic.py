from pathlib import Path

from nablatester.engine import analyze_file
from nablatester.rule_engine import load_rules


def test_rule_loader_reads_default_rules() -> None:
    rules = load_rules(Path("src/nablatester/rules"))
    assert "eval" in rules["dangerous_calls"]
    assert "subprocess.run" in rules["taint_sinks"]


def test_taint_to_sink_detection(tmp_path: Path) -> None:
    file_path = tmp_path / "taint.py"
    file_path.write_text(
        "import subprocess\n"
        "user = input('cmd:')\n"
        "subprocess.run(user)\n",
        encoding="utf-8",
    )
    findings = analyze_file(file_path)
    bug_types = {f.bug_type for f in findings}
    assert "security/taint-to-sink" in bug_types
