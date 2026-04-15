from __future__ import annotations

import json
from pathlib import Path

from .models import AnalysisSummary


def _level_from_severity(severity: str) -> str:
    sev = severity.lower()
    if sev == "critical":
        return "error"
    if sev in {"high", "medium"}:
        return "warning"
    return "note"


def write_sarif(summary: AnalysisSummary, output: Path) -> None:
    rules_index: dict[str, str] = {}
    rules: list[dict] = []
    results: list[dict] = []

    for finding in summary.prioritized_findings:
        rule_id = finding.rule_id or finding.bug_type
        if rule_id not in rules_index:
            rules_index[rule_id] = rule_id
            rules.append(
                {
                    "id": rule_id,
                    "name": finding.bug_type,
                    "shortDescription": {"text": finding.description},
                }
            )

        results.append(
            {
                "ruleId": rule_id,
                "level": _level_from_severity(finding.severity),
                "message": {"text": finding.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(finding.file_path)},
                            "region": {"startLine": finding.line},
                        }
                    }
                ],
            }
        )

    sarif_payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "NablaTester",
                        "informationUri": "https://example.local/nablatester",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }

    output.write_text(json.dumps(sarif_payload, ensure_ascii=False, indent=2), encoding="utf-8")
