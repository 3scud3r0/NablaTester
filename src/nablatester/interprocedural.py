from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from .models import BugFinding


@dataclass(slots=True)
class FunctionSpec:
    file_path: Path
    module: str
    name: str
    params: list[str]
    sink_param_indexes: set[int]
    param_flows: list[tuple[int, str, int]]


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _call_full_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_full_name(node.value)
        if parent:
            return f"{parent}.{node.attr}"
        return node.attr
    return None


def _module_name(base: Path, file_path: Path) -> str:
    rel = file_path.relative_to(base).with_suffix("")
    return ".".join(rel.parts)


def detect_project_interprocedural_taint(py_files: list[Path]) -> list[BugFinding]:
    sinks = {"eval", "exec", "system", "run", "Popen", "call"}
    sources = {"input", "argv", "getenv", "os.environ.get"}

    functions: dict[str, FunctionSpec] = {}
    file_asts: dict[Path, ast.AST] = {}
    alias_maps: dict[Path, dict[str, str]] = {}

    root = Path(".")
    if py_files:
        root = Path(py_files[0]).parent
        for p in py_files[1:]:
            while not Path(p).is_relative_to(root):
                root = root.parent

    for file_path in py_files:
        try:
            code = file_path.read_text(encoding="utf-8")
            tree = ast.parse(code)
        except Exception:
            continue
        file_asts[file_path] = tree
        module_name = _module_name(root, file_path)
        alias_map: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                base = node.module
                for alias in node.names:
                    alias_map[alias.asname or alias.name] = f"{base}.{alias.name}"
            if isinstance(node, ast.Import):
                for alias in node.names:
                    base = alias.name
                    alias_map[alias.asname or base.split(".")[-1]] = base
        alias_maps[file_path] = alias_map

        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            params = [a.arg for a in node.args.args]
            sink_indexes: set[int] = set()
            param_flows: list[tuple[int, str, int]] = []
            for call in [n for n in ast.walk(node) if isinstance(n, ast.Call)]:
                call_name = _call_name(call.func)
                if call_name in sinks:
                    for idx, arg in enumerate(call.args):
                        if isinstance(arg, ast.Name) and arg.id in params:
                            sink_indexes.add(params.index(arg.id))
                callee_name = _resolve_local_callee(module_name, alias_map, call)
                if callee_name:
                    for callee_arg_idx, arg in enumerate(call.args):
                        if isinstance(arg, ast.Name) and arg.id in params:
                            param_flows.append((params.index(arg.id), callee_name, callee_arg_idx))
            functions[f"{module_name}.{node.name}"] = FunctionSpec(
                file_path=file_path,
                module=module_name,
                name=node.name,
                params=params,
                sink_param_indexes=sink_indexes,
                param_flows=param_flows,
            )

    # Fixed-point: propaga índices de parâmetros que alcançam sink via cadeia de chamadas
    changed = True
    while changed:
        changed = False
        for spec in functions.values():
            for src_param_idx, callee_name, callee_param_idx in spec.param_flows:
                callee = functions.get(callee_name)
                if not callee:
                    continue
                if callee_param_idx in callee.sink_param_indexes and src_param_idx not in spec.sink_param_indexes:
                    spec.sink_param_indexes.add(src_param_idx)
                    changed = True

    findings: list[BugFinding] = []
    for file_path, tree in file_asts.items():
        tainted_vars: set[str] = set()
        module_name = _module_name(root, file_path)
        alias_map = alias_maps.get(file_path, {})

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                source_name = _call_full_name(node.value.func) or _call_name(node.value.func)
                if source_name in sources:
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            tainted_vars.add(t.id)

            if isinstance(node, ast.Call):
                called_name = _call_name(node.func)
                called_full = _call_full_name(node.func)
                candidates: list[str] = []
                if isinstance(node.func, ast.Name) and called_name:
                    if called_name in alias_map:
                        candidates.append(alias_map[called_name])
                    candidates.append(f"{module_name}.{called_name}")
                if isinstance(node.func, ast.Attribute) and called_name:
                    if called_full:
                        parts = called_full.split(".")
                        head = parts[0]
                        if head in alias_map:
                            candidates.append(".".join([alias_map[head], *parts[1:]]))
                    candidates.append(called_name)

                matched = next((functions[c] for c in candidates if c in functions), None)
                if matched:
                    spec = matched
                    for idx, arg in enumerate(node.args):
                        if idx in spec.sink_param_indexes and isinstance(arg, ast.Name) and arg.id in tainted_vars:
                            findings.append(
                                BugFinding(
                                    file_path=file_path,
                                    line=getattr(node, "lineno", 1),
                                    bug_type="security/interprocedural-taint",
                                    severity="critical",
                                    description=(
                                        f"Dado contaminado passado para função '{spec.module}.{spec.name}' que propaga para sink perigoso."
                                    ),
                                    debug_steps=[
                                        "Rastreie origem do argumento contaminado.",
                                        "Aplique sanitização antes da chamada.",
                                        "Valide no callee e no caller.",
                                    ],
                                    combined_debug_note="Interrompa fluxo contaminado entre módulos/funções antes de novos fixes.",
                                )
                            )
    return findings


def _resolve_local_callee(module_name: str, alias_map: dict[str, str], node: ast.Call) -> str | None:
    name = _call_name(node.func)
    full = _call_full_name(node.func)
    if isinstance(node.func, ast.Name) and name:
        if name in alias_map:
            return alias_map[name]
        return f"{module_name}.{name}"
    if isinstance(node.func, ast.Attribute) and full:
        head = full.split(".")[0]
        if head in alias_map:
            return ".".join([alias_map[head], *full.split(".")[1:]])
        return full
    return None
