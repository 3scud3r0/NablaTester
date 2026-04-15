from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import time
from typing import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from .detectors import (
    detect_javascript_semantic_issues,
    detect_python_comment_markers,
    detect_python_sql_injection_heuristics,
    detect_python_semantic_issues,
    detect_secrets,
    is_scannable,
)
from .interprocedural import detect_project_interprocedural_taint
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
        findings.extend(detect_python_sql_injection_heuristics(file_path, raw))
    if file_path.suffix.lower() in {".js", ".jsx", ".ts", ".tsx"}:
        findings.extend(detect_javascript_semantic_issues(file_path, lines))
    return findings


def run_analysis(
    project_path: Path,
    output_pdf: Path,
    progress_callback: Callable[[dict], None] | None = None,
    workers: int = 1,
    ignore_fingerprints: set[str] | None = None,
) -> AnalysisSummary:
    start = datetime.now(timezone.utc)
    files = collect_files(project_path)
    started_monotonic = time.monotonic()

    all_findings = []
    total = len(files) if files else 1
    if workers <= 1:
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
    else:
        completed = 0
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_map = {executor.submit(analyze_file, file_path): file_path for file_path in files}
            for future in as_completed(future_map):
                file_path = future_map[future]
                all_findings.extend(future.result())
                completed += 1
                if progress_callback:
                    elapsed = time.monotonic() - started_monotonic
                    avg = elapsed / completed
                    remaining = max(0.0, (total - completed) * avg)
                    progress_callback(
                        {
                            "phase": "analysis",
                            "processed": completed,
                            "total": total,
                            "percent": (completed / total) * 100.0,
                            "eta_seconds": remaining,
                            "current_file": str(file_path),
                        }
                    )

    py_files = [f for f in files if f.suffix.lower() == ".py"]
    all_findings.extend(detect_project_interprocedural_taint(py_files))

    end = datetime.now(timezone.utc)
    filtered_findings = all_findings
    if ignore_fingerprints:
        filtered_findings = [f for f in all_findings if f.fingerprint not in ignore_fingerprints]

    summary = AnalysisSummary(
        project_path=project_path,
        started_at=start.isoformat(),
        ended_at=end.isoformat(),
        scanned_files=len(files),
        findings=sorted(filtered_findings, key=lambda x: (x.severity, str(x.file_path), x.line)),
    )

    write_pdf_report(summary, output_pdf)
    return summary
