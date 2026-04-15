from __future__ import annotations

import ast
import io
from pathlib import Path
import re
import tokenize

from .models import BugFinding


TEXT_EXTENSIONS = {
    ".py", ".pyi", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".java", ".go", ".rs", ".c", ".cpp", ".h", ".hpp", ".cs", ".php", ".rb", ".kt", ".kts", ".swift", ".scala", ".sc", ".sql", ".sh",
    ".bash", ".zsh", ".ps1", ".lua", ".dart", ".r", ".jl", ".ex", ".exs", ".erl", ".hrl", ".clj", ".groovy", ".m", ".mm", ".vb", ".f90", ".nim", ".zig", ".sol", ".proto", ".graphql", ".yml", ".yaml",
    ".json", ".json5", ".toml", ".ini", ".cfg", ".conf", ".xml",
}

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Possível chave AWS hardcoded", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Possível token privado hardcoded", re.compile(r"(?i)(api[_-]?key|token|secret)\s*[:=]\s*['\"][^'\"]{12,}['\"]")),
    ("Senha hardcoded", re.compile(r"(?i)password\s*[:=]\s*['\"][^'\"]{6,}['\"]")),
]

SUBPROCESS_SHELL_PATTERN = re.compile(r"subprocess\.(run|Popen|call)\(.*shell\s*=\s*True")


def is_scannable(file_path: Path) -> bool:
    return file_path.suffix.lower() in TEXT_EXTENSIONS


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


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


def detect_python_comment_markers(file_path: Path, code: str) -> list[BugFinding]:
    findings: list[BugFinding] = []
    tokens = tokenize.generate_tokens(io.StringIO(code).readline)
    marker = re.compile(r"\b(TODO|FIXME|HACK)\b", re.IGNORECASE)
    for tk in tokens:
        if tk.type == tokenize.COMMENT and marker.search(tk.string):
            findings.append(
                BugFinding(
                    file_path=file_path,
                    line=tk.start[0],
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


def detect_python_semantic_issues(file_path: Path, code: str, rules: dict) -> list[BugFinding]:
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
                    "Rode formatter/linter e execute novamente.",
                ],
                combined_debug_note="Erros de sintaxe impedem execução de módulos e mascaram erros lógicos subsequentes.",
            )
        )
        return findings

    dangerous = set(rules.get("dangerous_calls", []))
    taint_sources = set(rules.get("taint_sources", []))
    taint_sinks = set(rules.get("taint_sinks", []))
    sanitizers = set(rules.get("sanitizers", []))

    tainted_vars: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            call = _call_name(node.value.func)
            if call in taint_sources:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        tainted_vars.add(target.id)

        if isinstance(node, ast.Call):
            call = _call_name(node.func)
            if call in dangerous:
                findings.append(
                    BugFinding(
                        file_path=file_path,
                        line=getattr(node, "lineno", 1),
                        bug_type="security/code-execution",
                        severity="high",
                        description=f"Uso de {call} pode executar código arbitrário.",
                        debug_steps=[
                            "Rastreie origem dos dados usados na chamada.",
                            "Substitua por parser seguro/tabela de dispatch.",
                            "Adicione testes para inputs maliciosos.",
                        ],
                        combined_debug_note="Consolide auditoria de entradas não confiáveis em todos os módulos antes de liberar patch final.",
                    )
                )

            if call in taint_sinks:
                if _call_uses_tainted(node, tainted_vars, sanitizers):
                    findings.append(
                        BugFinding(
                            file_path=file_path,
                            line=getattr(node, "lineno", 1),
                            bug_type="security/taint-to-sink",
                            severity="critical",
                            description=f"Fluxo contaminado alcança sink perigoso ({call}) sem sanitização.",
                            debug_steps=[
                                "Mapeie source -> variáveis intermediárias -> sink.",
                                "Aplique sanitização/validação antes do sink.",
                                "Crie teste negativo com payload malicioso.",
                            ],
                            combined_debug_note="Mitigue fluxos críticos primeiro e revalide caminhos dependentes.",
                        )
                    )

        if isinstance(node, ast.Assert):
            findings.append(
                BugFinding(
                    file_path=file_path,
                    line=getattr(node, "lineno", 1),
                    bug_type="reliability/assert-in-production",
                    severity="medium",
                    description="Uso de assert para regra de negócio (pode ser removido com -O).",
                    debug_steps=[
                        "Verifique se a condição é crítica.",
                        "Substitua por validação explícita com exceção.",
                        "Cubra com teste unitário.",
                    ],
                    combined_debug_note="Converta asserts críticos primeiro, depois reavalie fluxos de erro globalmente.",
                )
            )

    findings.extend(_detect_use_before_assign(file_path, tree))

    for idx, line in enumerate(code.splitlines(), start=1):
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


def _call_uses_tainted(node: ast.Call, tainted_vars: set[str], sanitizers: set[str]) -> bool:
    for arg in node.args:
        if isinstance(arg, ast.Name) and arg.id in tainted_vars:
            return True
        if isinstance(arg, ast.Call):
            nested = _call_name(arg.func)
            if nested in sanitizers:
                continue
            if any(isinstance(a, ast.Name) and a.id in tainted_vars for a in arg.args):
                return True
    return False


def _detect_use_before_assign(file_path: Path, tree: ast.AST) -> list[BugFinding]:
    findings: list[BugFinding] = []

    class _UseBeforeAssign(ast.NodeVisitor):
        def __init__(self) -> None:
            self.assigned: set[str] = set()
            self.errors: list[tuple[int, str]] = []

        def visit_Name(self, node: ast.Name) -> None:
            if isinstance(node.ctx, ast.Load):
                if node.id not in self.assigned and node.id not in dir(__builtins__):
                    self.errors.append((getattr(node, "lineno", 1), node.id))
            elif isinstance(node.ctx, ast.Store):
                self.assigned.add(node.id)

    for n in ast.walk(tree):
        if isinstance(n, ast.FunctionDef):
            checker = _UseBeforeAssign()
            for arg in n.args.args:
                checker.assigned.add(arg.arg)
            for stmt in n.body:
                checker.visit(stmt)
            for line, name in checker.errors:
                findings.append(
                    BugFinding(
                        file_path=file_path,
                        line=line,
                        bug_type="reliability/use-before-assign",
                        severity="medium",
                        description=f"Variável '{name}' usada antes de atribuição no escopo da função.",
                        debug_steps=[
                            "Confirme ordem de inicialização da variável.",
                            "Mova atribuição para antes do primeiro uso.",
                            "Adicione teste cobrindo o caminho de execução.",
                        ],
                        combined_debug_note="Corrija ordem de inicialização antes de tratar falhas derivadas.",
                    )
                )
    return findings
