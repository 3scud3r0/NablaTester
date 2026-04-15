from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path

from .detectors import detect_python_ast_issues, detect_secrets, detect_todo_hack, is_scannable
from .models import AnalysisSummary
from .pdf_writer import write_pdf_report


EXCLUDED_DIRS = {".git", ".idea", ".vscode", "node_modules", "venv", ".venv", "dist", "build", "__pycache__"}


def collect_files(project_path: Path) -> list[Path]:
    files: list[Path] = []
    for root, dirs, filenames in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        root_path = Path(root)
        for file_name in filenames:
            file_path = root_path / file_name
            if is_scannable(file_path):
                files.append(file_path)
    return files


def analyze_file(file_path: Path) -> list:
    try:
        raw = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raw = file_path.read_text(encoding="latin-1", errors="replace")

    lines = raw.splitlines()
    findings = []
    findings.extend(detect_secrets(file_path, lines))
    findings.extend(detect_todo_hack(file_path, lines))
    if file_path.suffix.lower() == ".py":
        findings.extend(detect_python_ast_issues(file_path, raw))
    return findings


def run_analysis(project_path: Path, output_pdf: Path) -> AnalysisSummary:
    start = datetime.now(timezone.utc)
    files = collect_files(project_path)

    all_findings = []
    for file_path in files:
        all_findings.extend(analyze_file(file_path))

    end = datetime.now(timezone.utc)
    summary = AnalysisSummary(
        project_path=project_path,
        started_at=start.isoformat(),
        ended_at=end.isoformat(),
        scanned_files=len(files),
        findings=sorted(all_findings, key=lambda x: (x.severity, str(x.file_path), x.line)),
    )

    write_pdf_report(summary, output_pdf)
    return summary
