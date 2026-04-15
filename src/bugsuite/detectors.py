from __future__ import annotations

import ast
import re
from pathlib import Path

from .models import BugFinding


TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rs", ".c", ".cpp", ".h", ".hpp", ".cs", ".php", ".rb", ".kt", ".swift", ".scala", ".sql", ".sh", ".yml", ".yaml", ".json", ".toml",
}


SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Possível chave AWS hardcoded", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Possível token privado hardcoded", re.compile(r"(?i)(api[_-]?key|token|secret)\s*[:=]\s*['\"][^'\"]{12,}['\"]")),
    ("Senha hardcoded", re.compile(r"(?i)password\s*[:=]\s*['\"][^'\"]{6,}['\"]")),
]


DANGEROUS_CALLS = {
    "eval": ("high", "Uso de eval pode executar código arbitrário."),
    "exec": ("high", "Uso de exec pode executar código arbitrário."),
}


SUBPROCESS_SHELL_PATTERN = re.compile(r"subprocess\.(run|Popen|call)\(.*shell\s*=\s*True")


def is_scannable(file_path: Path) -> bool:
    return file_path.suffix.lower() in TEXT_EXTENSIONS


def detect_secrets(file_path: Path, lines: list[str]) -> list[BugFinding]:
    findings: list[BugFinding] = []
    for idx, line in enumerate(lines, start=1):
        for bug_desc, pattern in SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(
                    BugFinding(
                        file_path=file_path,
                        line=idx,
                        bug_type="security/secret-leak",
                        severity="critical",
                        description=bug_desc,
                        debug_steps=[
                            "Confirme se a credencial é real e ativa.",
                            "Revogue/rotacione a credencial imediatamente.",
                            "Remova do código e injete por variável de ambiente.",
                            "Reescreva histórico do git se já foi commitado.",
                        ],
                        combined_debug_note="Trate este achado antes de qualquer outro: exposição de segredo compromete todo o ambiente.",
                    )
                )
    return findings


def detect_python_ast_issues(file_path: Path, code: str) -> list[BugFinding]:
    findings: list[BugFinding] = []
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        findings.append(
            BugFinding(
                file_path=file_path,
                line=exc.lineno or 1,
                bug_type="syntax-error",
                severity="high",
                description=f"SyntaxError: {exc.msg}",
                debug_steps=[
                    "Abra o arquivo na linha indicada.",
                    "Valide parênteses, identação e delimitadores.",
                    "Rode o formatter/linter e execute novamente.",
                ],
                combined_debug_note="Erros de sintaxe impedem execução de módulos e mascaram erros lógicos subsequentes.",
            )
        )
        return findings

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = None
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr

            if func_name in DANGEROUS_CALLS:
                sev, msg = DANGEROUS_CALLS[func_name]
                findings.append(
                    BugFinding(
                        file_path=file_path,
                        line=getattr(node, "lineno", 1),
                        bug_type="security/code-execution",
                        severity=sev,
                        description=msg,
                        debug_steps=[
                            "Rastreie a origem dos dados de entrada usados na chamada.",
                            "Substitua por parser seguro ou tabela de dispatch explícita.",
                            "Adicione validações estritas e testes de input malicioso.",
                        ],
                        combined_debug_note="Consolide auditoria de entradas não confiáveis em todos os módulos antes de liberar patch final.",
                    )
                )

        if isinstance(node, ast.Assert):
            findings.append(
                BugFinding(
                    file_path=file_path,
                    line=getattr(node, "lineno", 1),
                    bug_type="reliability/assert-in-production",
                    severity="medium",
                    description="Uso de assert para validação de regra de negócio (pode ser removido com -O).",
                    debug_steps=[
                        "Verifique se a condição é crítica de negócio.",
                        "Substitua por validação explícita com exceção dedicada.",
                        "Cubra com teste unitário.",
                    ],
                    combined_debug_note="Converta asserts críticos primeiro, depois reavalie fluxos de erro globalmente.",
                )
            )

    lines = code.splitlines()
    for idx, line in enumerate(lines, start=1):
        if SUBPROCESS_SHELL_PATTERN.search(line):
            findings.append(
                BugFinding(
                    file_path=file_path,
                    line=idx,
                    bug_type="security/command-injection",
                    severity="high",
                    description="Uso de subprocess com shell=True aumenta risco de command injection.",
                    debug_steps=[
                        "Inspecione origem dos argumentos passados ao subprocess.",
                        "Troque para lista de argumentos e shell=False.",
                        "Sanitize input e adicione testes com payloads maliciosos.",
                    ],
                    combined_debug_note="Padronize execução de comandos externos em um wrapper seguro único.",
                )
            )

    return findings


def detect_todo_hack(file_path: Path, lines: list[str]) -> list[BugFinding]:
    findings: list[BugFinding] = []
    pattern = re.compile(r"\b(TODO|FIXME|HACK)\b", re.IGNORECASE)
    for idx, line in enumerate(lines, start=1):
        if pattern.search(line):
            findings.append(
                BugFinding(
                    file_path=file_path,
                    line=idx,
                    bug_type="maintainability/pending-work",
                    severity="low",
                    description="Comentário de dívida técnica encontrado (TODO/FIXME/HACK).",
                    debug_steps=[
                        "Avalie se o comentário representa bug conhecido.",
                        "Converta em issue rastreável com contexto.",
                        "Defina prioridade com base no impacto real.",
                    ],
                    combined_debug_note="Agrupe pendências por componente para planejar saneamento sem quebrar estabilidade.",
                )
            )
    return findings
