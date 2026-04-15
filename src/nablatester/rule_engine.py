from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _simple_yaml_to_dict(raw: str) -> dict[str, Any]:
    """Parser mínimo para YAML simples de pares chave: valor/listas.

    Mantém o projeto sem dependências externas obrigatórias.
    """
    data: dict[str, Any] = {}
    current_list_key: str | None = None
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- ") and current_list_key:
            data.setdefault(current_list_key, []).append(stripped[2:].strip().strip('"\''))
            continue
        if ":" in stripped:
            key, value = stripped.split(":", 1)
            key = key.strip()
            value = value.strip()
            if value == "":
                data[key] = []
                current_list_key = key
            else:
                current_list_key = None
                data[key] = value.strip('"\'')
    return data


def load_rule_file(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        payload = json.loads(text)
        if not isinstance(payload, dict):
            raise ValueError(f"Arquivo de regra inválido: {path}")
        return payload
    if path.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore

            payload = yaml.safe_load(text)
            if not isinstance(payload, dict):
                raise ValueError(f"Arquivo de regra inválido: {path}")
            return payload
        except ModuleNotFoundError:
            return _simple_yaml_to_dict(text)
    raise ValueError(f"Formato não suportado para regra: {path}")


def load_rules(rule_dir: Path) -> dict[str, Any]:
    merged: dict[str, Any] = {
        "dangerous_calls": [],
        "taint_sources": [],
        "taint_sinks": [],
        "sanitizers": [],
    }
    for file in sorted(rule_dir.glob("*")):
        if file.suffix.lower() not in {".json", ".yaml", ".yml"}:
            continue
        payload = load_rule_file(file)
        for key in merged:
            values = payload.get(key, [])
            if isinstance(values, list):
                merged[key].extend(str(v) for v in values)
    for key in merged:
        merged[key] = sorted(set(merged[key]))
    return merged
