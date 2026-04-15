from __future__ import annotations

import argparse
import json
from pathlib import Path

from .autofix import cascade_autofix
from .engine import run_analysis
from .gui import launch_gui
from .sarif_writer import write_sarif


def interactive_mode() -> None:
    print("=== NablaTester v2 ===")
    folder = input("Informe a pasta do projeto para analisar: ").strip()
    project = Path(folder).expanduser().resolve()

    if not project.exists() or not project.is_dir():
        raise SystemExit(f"Pasta inválida: {project}")

    confirm = input("Digite START para iniciar a análise: ").strip().upper()
    if confirm != "START":
        raise SystemExit("Análise cancelada pelo usuário.")

    output_pdf = project / "nablatester_report.pdf"
    summary = run_analysis(project, output_pdf)

    print("\nAnálise concluída.")
    print(f"Arquivos escaneados: {summary.scanned_files}")
    print(f"Bugs encontrados: {len(summary.findings)}")
    print(f"PDF gerado em: {output_pdf}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nablatester",
        description="Analisa um projeto e gera relatório PDF de bugs com orientação de debug.",
    )
    parser.add_argument("project", nargs="?", help="Pasta do projeto para análise")
    parser.add_argument("--output", "-o", help="Arquivo PDF de saída")
    parser.add_argument("--no-interactive", action="store_true", help="Executa sem prompt interativo")
    parser.add_argument("--gui", action="store_true", help="Abre interface gráfica para selecionar a pasta e iniciar")
    parser.add_argument("--autofix", action="store_true", help="Copia o projeto e aplica correções determinísticas em cascata")
    parser.add_argument("--autofix-target", help="Diretório de saída para projeto corrigido em cascata")
    parser.add_argument("--stream-report", help="Arquivo JSONL para eventos em tempo real da execução em cascata")
    parser.add_argument("--max-iterations", type=int, default=8, help="Máximo de iterações de correção em cascata")
    parser.add_argument("--strict-gate", action="store_true", help="Ativa quality gate e rollback automático por iteração")
    parser.add_argument("--gate-cmd", action="append", help="Comando de quality gate (pode repetir)")
    parser.add_argument("--no-rollback-on-gate-fail", action="store_true", help="Não reverte alterações quando quality gate falhar")
    parser.add_argument("--workers", type=int, default=1, help="Número de workers paralelos para análise")
    parser.add_argument("--sarif-output", help="Gera relatório SARIF no caminho indicado")
    parser.add_argument("--json-output", help="Gera relatório JSON estruturado no caminho indicado")
    parser.add_argument("--baseline-in", help="Arquivo JSON com fingerprints para ignorar")
    parser.add_argument("--baseline-out", help="Arquivo JSON para salvar fingerprints encontrados")
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.gui:
        launch_gui()
        return

    if not args.no_interactive and not args.project:
        try:
            launch_gui()
            return
        except SystemExit:
            interactive_mode()
            return

    if not args.project:
        raise SystemExit("Informe a pasta de projeto (ou rode sem --no-interactive).")

    project = Path(args.project).expanduser().resolve()
    if not project.exists() or not project.is_dir():
        raise SystemExit(f"Pasta inválida: {project}")

    if args.autofix:
        target = Path(args.autofix_target).expanduser().resolve() if args.autofix_target else project.parent / f"{project.name}_nablatester_fixed"
        stream = Path(args.stream_report).expanduser().resolve() if args.stream_report else target / "cascade_stream.jsonl"
        fixed_path, summary, actions = cascade_autofix(
            project_path=project,
            target_path=target,
            report_stream_path=stream,
            max_iterations=args.max_iterations,
            strict_gate=args.strict_gate,
            gate_commands=args.gate_cmd,
            rollback_on_gate_fail=not args.no_rollback_on_gate_fail,
        )
        print(
            f"Autofix concluído. Projeto corrigido: {fixed_path} | "
            f"Ações aplicadas={len(actions)} | Findings restantes={len(summary.findings)} | PDF={fixed_path / 'nablatester_report.pdf'}"
        )
        return

    output = Path(args.output).expanduser().resolve() if args.output else (project / "nablatester_report.pdf")
    ignore_fingerprints: set[str] | None = None
    if args.baseline_in:
        baseline_path = Path(args.baseline_in).expanduser().resolve()
        data = json.loads(baseline_path.read_text(encoding="utf-8"))
        ignore_fingerprints = set(data.get("fingerprints", [])) if isinstance(data, dict) else set()

    summary = run_analysis(project, output, workers=max(1, args.workers), ignore_fingerprints=ignore_fingerprints)
    if args.sarif_output:
        write_sarif(summary, Path(args.sarif_output).expanduser().resolve())
    if args.json_output:
        Path(args.json_output).expanduser().resolve().write_text(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    if args.baseline_out:
        payload = {"fingerprints": sorted({f.fingerprint for f in summary.findings})}
        Path(args.baseline_out).expanduser().resolve().write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Concluído. Bugs={len(summary.findings)} PDF={output}")


if __name__ == "__main__":
    main()
