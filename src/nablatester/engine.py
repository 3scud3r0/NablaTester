from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import time
from typing import Callable

from .detectors import detect_python_comment_markers, detect_python_semantic_issues, detect_secrets, is_scannable
from .models import AnalysisSummary
from .pdf_writer import write_pdf_report
from .rule_engine import load_rules


EXCLUDED_DIRS = {".git", ".idea", ".vscode", "node_modules", "venv", ".venv", "dist", "build", "__pycache__"}
DEFAULT_RULE_DIR = Path(__file__).parent / "rules"
DEFAULT_RULES = load_rules(DEFAULT_RULE_DIR)


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
    if file_path.suffix.lower() == ".py":
        findings.extend(detect_python_comment_markers(file_path, raw))
        findings.extend(detect_python_semantic_issues(file_path, raw, DEFAULT_RULES))
    return findings


def run_analysis(
    project_path: Path,
    output_pdf: Path,
    progress_callback: Callable[[dict], None] | None = None,
) -> AnalysisSummary:
    start = datetime.now(timezone.utc)
    files = collect_files(project_path)
    started_monotonic = time.monotonic()

    all_findings = []
    total = len(files) if files else 1
    for idx, file_path in enumerate(files, start=1):
        all_findings.extend(analyze_file(file_path))
        if progress_callback:
            elapsed = time.monotonic() - started_monotonic
            avg = elapsed / idx
            remaining = max(0.0, (total - idx) * avg)
            progress_callback(
                {
                    "phase": "analysis",
                    "processed": idx,
                    "total": total,
                    "percent": (idx / total) * 100.0,
                    "eta_seconds": remaining,
                    "current_file": str(file_path),
                }
            )

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
