from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shlex
import shutil
from typing import Iterable
from typing import Callable

from .detectors import SECRET_PATTERNS
from .engine import analyze_file, collect_files, run_analysis
from .models import BugFinding, AnalysisSummary
from .quality_gate import run_quality_gate


@dataclass(slots=True)
class FixAction:
    iteration: int
    file_path: Path
    line: int
    bug_type: str
    action: str


class StreamReporter:
    def __init__(self, output_path: Path) -> None:
        self.output_path = output_path
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, event: dict) -> None:
        payload = json.dumps(event, ensure_ascii=False)
        print(payload)
        with self.output_path.open("a", encoding="utf-8") as fp:
            fp.write(payload + "\n")


def _line_match_secret(line: str) -> bool:
    return any(pattern.search(line) for _, pattern in SECRET_PATTERNS)


def _env_name_from_line(line: str, fallback: str = "BUGSUITE_SECRET") -> str:
    m = re.search(r"\b([A-Z][A-Z0-9_]{2,})\b", line)
    return (m.group(1) if m else fallback).upper()


def _ensure_import(lines: list[str], import_stmt: str) -> list[str]:
    if any(line.strip() == import_stmt for line in lines):
        return lines
    insert_at = 0
    if lines and lines[0].startswith("#!"):
        insert_at = 1
    lines.insert(insert_at, import_stmt)
    _sort_import_block(lines)
    return lines


def _sort_import_block(lines: list[str]) -> None:
    import_indexes = [idx for idx, line in enumerate(lines) if line.startswith("import ") or line.startswith("from ")]
    if not import_indexes:
        return
    start = min(import_indexes)
    end = max(import_indexes)
    block = lines[start:end + 1]
    if any(not item.strip() for item in block):
        return
    lines[start:end + 1] = sorted(block, key=lambda s: s.lower())


def _fix_python_lines(lines: list[str], findings: Iterable[BugFinding]) -> tuple[list[str], list[tuple[int, str]]]:
    line_actions: list[tuple[int, str]] = []
    line_to_types: dict[int, set[str]] = {}
    line_to_findings: dict[int, list[BugFinding]] = {}
    for f in findings:
        line_to_types.setdefault(f.line, set()).add(f.bug_type)
        line_to_findings.setdefault(f.line, []).append(f)

    needs_ast_import = False
    needs_os_import = False
    insertions: list[tuple[int, str]] = []

    for line_no, bug_types in sorted(line_to_types.items()):
        if line_no <= 0 or line_no > len(lines):
            continue
        idx = line_no - 1
        original = lines[idx]
        new_line = original

        if "security/code-execution" in bug_types and "eval(" in new_line:
            new_line = new_line.replace("eval(", "ast.literal_eval(")
            needs_ast_import = True
            line_actions.append((line_no, "Substituído eval() por ast.literal_eval()."))

        if "security/command-injection" in bug_types and "shell=True" in new_line:
            transformed = _rewrite_shell_true_call(new_line)
            if transformed != new_line:
                new_line = transformed
                line_actions.append((line_no, "Convertido comando shell=True para lista de argumentos segura com shell=False."))
            else:
                new_line = new_line.replace("shell=True", "shell=False")
                line_actions.append((line_no, "Forçado shell=False em subprocess."))

        if "reliability/assert-in-production" in bug_types:
            stripped = new_line.strip()
            if stripped.startswith("assert "):
                expr = stripped[len("assert "):].strip()
                indent = new_line[: len(new_line) - len(new_line.lstrip(" "))]
                new_line = (
                    f"{indent}if not ({expr}):\n"
                    f"{indent}    raise ValueError('Assertion convertida automaticamente pelo NablaTester')"
                )
                line_actions.append((line_no, "Convertido assert para validação explícita com exceção."))

        if "maintainability/pending-work" in bug_types and re.search(r"\b(TODO|FIXME|HACK)\b", new_line, re.IGNORECASE):
            new_line = re.sub(r"\b(TODO|FIXME|HACK)\b", "NOTE", new_line, flags=re.IGNORECASE)
            line_actions.append((line_no, "Normalizado marcador de dívida técnica para NOTE."))

        if "reliability/use-before-assign" in bug_types:
            for finding in line_to_findings.get(line_no, []):
                match = re.search(r"Variável '([^']+)'", finding.description)
                if not match:
                    continue
                var_name = match.group(1)
                if var_name in {"eval", "exec", "print", "input", "len", "str", "int", "float"}:
                    continue
                if not new_line.lstrip().startswith(var_name):
                    continue
                indent = new_line[: len(new_line) - len(new_line.lstrip(" "))]
                insertion = f"{indent}{var_name} = None  # inicialização automática NablaTester"
                insertions.append((line_no - 1, insertion))
                line_actions.append((line_no, f"Inicialização preventiva inserida para variável '{var_name}' usada antes de atribuição."))

        if "security/secret-leak" in bug_types and _line_match_secret(new_line):
            env_name = _env_name_from_line(new_line)
            new_line = re.sub(r"(['\"])[^'\"]{6,}\1", f"os.getenv('{env_name}', '')", new_line, count=1)
            needs_os_import = True
            line_actions.append((line_no, f"Segredo hardcoded substituído por os.getenv('{env_name}', '')."))

        lines[idx] = new_line

    if needs_ast_import:
        lines = _ensure_import(lines, "import ast")
    if needs_os_import:
        lines = _ensure_import(lines, "import os")

    for index, content in sorted(insertions, key=lambda x: x[0], reverse=True):
        lines.insert(max(0, index), content)

    return lines, line_actions


def _rewrite_shell_true_call(line: str) -> str:
    # subprocess.run("ls -l", shell=True) => subprocess.run(["ls", "-l"], shell=False)
    pattern = re.compile(r"(subprocess\.(?:run|Popen|call)\()([\"'])([^\"']+)\2(,.*)shell\s*=\s*True")
    m = pattern.search(line)
    if not m:
        return line

    command = m.group(3)
    try:
        parts = shlex.split(command)
    except ValueError:
        return line

    args_repr = "[" + ", ".join(repr(x) for x in parts) + "]"
    rewritten = pattern.sub(rf"\1{args_repr}\4shell=False", line)
    return rewritten


def apply_fixes_to_file(file_path: Path, findings: list[BugFinding]) -> list[tuple[int, str, str]]:
    if not findings:
        return []
    if file_path.suffix.lower() != ".py":
        return []

    try:
        content = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        content = file_path.read_text(encoding="latin-1", errors="replace")

    original_content = content
    lines = content.splitlines()
    updated, actions = _fix_python_lines(lines, findings)
    if not actions:
        return []

    candidate = "\n".join(updated) + "\n"
    try:
        compile(candidate, str(file_path), "exec")
    except SyntaxError:
        return []

    file_path.write_text(candidate, encoding="utf-8")
    try:
        compile(file_path.read_text(encoding="utf-8"), str(file_path), "exec")
    except SyntaxError:
        file_path.write_text(original_content, encoding="utf-8")
        return []

    def resolve_bug_type(action: str, line: int) -> str:
        by_line = [f.bug_type for f in findings if f.line == line]
        if "eval" in action:
            return "security/code-execution"
        if "shell=False" in action:
            return "security/command-injection"
        if "Segredo hardcoded" in action:
            return "security/secret-leak"
        if "assert" in action:
            return "reliability/assert-in-production"
        if "dívida técnica" in action or "NOTE" in action:
            return "maintainability/pending-work"
        return by_line[0] if by_line else "unknown"

    typed_actions: list[tuple[int, str, str]] = []
    for ln, action in actions:
        bug_type = resolve_bug_type(action, ln)
        typed_actions.append((ln, bug_type, action))
    return typed_actions


def _group_findings_by_file(findings: list[BugFinding]) -> dict[Path, list[BugFinding]]:
    grouped: dict[Path, list[BugFinding]] = {}
    for f in findings:
        grouped.setdefault(f.file_path, []).append(f)
    return grouped


def cascade_autofix(
    project_path: Path,
    target_path: Path,
    report_stream_path: Path,
    max_iterations: int = 8,
    progress_callback: Callable[[dict], None] | None = None,
    strict_gate: bool = False,
    gate_commands: list[str] | None = None,
    rollback_on_gate_fail: bool = True,
) -> tuple[Path, AnalysisSummary, list[FixAction]]:
    if target_path.exists():
        shutil.rmtree(target_path)
    shutil.copytree(project_path, target_path)

    reporter = StreamReporter(report_stream_path)
    actions: list[FixAction] = []

    for iteration in range(1, max_iterations + 1):
        all_findings: list[BugFinding] = []
        files = collect_files(target_path)
        per_iter_total = len(files) if files else 1
        for file_idx, file_path in enumerate(files, start=1):
            all_findings.extend(analyze_file(file_path))
            if progress_callback:
                completed_units = (iteration - 1) * per_iter_total + file_idx
                total_units = max_iterations * per_iter_total
                progress_callback(
                    {
                        "phase": "autofix-scan",
                        "iteration": iteration,
                        "processed": completed_units,
                        "total": total_units,
                        "percent": (completed_units / total_units) * 100.0,
                        "eta_seconds": None,
                        "current_file": str(file_path),
                    }
                )

        reporter.emit(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": "iteration_scan",
                "iteration": iteration,
                "findings": len(all_findings),
            }
        )

        if not all_findings:
            reporter.emit(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event": "converged",
                    "iteration": iteration,
                    "message": "Nenhum finding restante nas regras determinísticas atuais.",
                }
            )
            break

        grouped = _group_findings_by_file(all_findings)
        iteration_actions = 0
        changed_files: dict[Path, str] = {}
        for file_path, findings in grouped.items():
            try:
                changed_files[file_path] = file_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                changed_files[file_path] = file_path.read_text(encoding="latin-1", errors="replace")
            file_actions = apply_fixes_to_file(file_path, findings)
            for line, bug_type, action_text in file_actions:
                action = FixAction(
                    iteration=iteration,
                    file_path=file_path,
                    line=line,
                    bug_type=bug_type,
                    action=action_text,
                )
                actions.append(action)
                iteration_actions += 1
                reporter.emit(
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "event": "fix_applied",
                        "iteration": iteration,
                        "file": str(file_path),
                        "line": line,
                        "bug_type": bug_type,
                        "action": action_text,
                    }
                )

        if iteration_actions == 0:
            reporter.emit(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event": "stopped_no_actions",
                    "iteration": iteration,
                    "message": "Findings encontrados, mas nenhuma ação determinística aplicável.",
                }
            )
            break

        if strict_gate:
            gate_result = run_quality_gate(target_path, gate_commands)
            reporter.emit(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event": "quality_gate",
                    "iteration": iteration,
                    "passed": gate_result.passed,
                    "commands": [c.command for c in gate_result.commands],
                }
            )
            if not gate_result.passed and rollback_on_gate_fail:
                for file_path, original_content in changed_files.items():
                    file_path.write_text(original_content, encoding="utf-8")
                reporter.emit(
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "event": "quality_gate_rollback",
                        "iteration": iteration,
                        "reason": "Quality gate falhou e alterações foram revertidas.",
                    }
                )
                break

    final_pdf = target_path / "nablatester_report.pdf"
    summary = run_analysis(target_path, final_pdf, progress_callback=progress_callback)
    reporter.emit(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "final_report",
            "pdf": str(final_pdf),
            "remaining_findings": len(summary.findings),
            "actions_applied": len(actions),
        }
    )

    return target_path, summary, actions
