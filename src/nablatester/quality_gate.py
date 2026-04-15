from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import subprocess


@dataclass(slots=True)
class GateCommandResult:
    command: str
    returncode: int
    output: str


@dataclass(slots=True)
class GateResult:
    passed: bool
    commands: list[GateCommandResult]


def run_quality_gate(project_path: Path, commands: list[str] | None = None) -> GateResult:
    gate_commands = commands or ["python -m compileall ."]
    results: list[GateCommandResult] = []

    for cmd in gate_commands:
        proc = subprocess.run(
            cmd,
            cwd=project_path,
            shell=True,
            text=True,
            capture_output=True,
            check=False,
        )
        output = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        result = GateCommandResult(command=cmd, returncode=proc.returncode, output=output.strip())
        results.append(result)
        if proc.returncode != 0:
            return GateResult(passed=False, commands=results)

    return GateResult(passed=True, commands=results)
