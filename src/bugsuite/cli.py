from __future__ import annotations

import argparse
from pathlib import Path

from .autofix import cascade_autofix
from .engine import run_analysis
from .gui import launch_gui


def interactive_mode() -> None:
    print("=== BugSuite Analyzer v2 ===")
    folder = input("Informe a pasta do projeto para analisar: ").strip()
    project = Path(folder).expanduser().resolve()

    if not project.exists() or not project.is_dir():
        raise SystemExit(f"Pasta inválida: {project}")

    confirm = input("Digite START para iniciar a análise: ").strip().upper()
    if confirm != "START":
        raise SystemExit("Análise cancelada pelo usuário.")

    output_pdf = project / "bugsuite_report.pdf"
    summary = run_analysis(project, output_pdf)

    print("\nAnálise concluída.")
    print(f"Arquivos escaneados: {summary.scanned_files}")
    print(f"Bugs encontrados: {len(summary.findings)}")
    print(f"PDF gerado em: {output_pdf}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bugsuite",
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
        target = Path(args.autofix_target).expanduser().resolve() if args.autofix_target else project.parent / f"{project.name}_bugsuite_fixed"
        stream = Path(args.stream_report).expanduser().resolve() if args.stream_report else target / "cascade_stream.jsonl"
        fixed_path, summary, actions = cascade_autofix(
            project_path=project,
            target_path=target,
            report_stream_path=stream,
            max_iterations=args.max_iterations,
        )
        print(
            f"Autofix concluído. Projeto corrigido: {fixed_path} | "
            f"Ações aplicadas={len(actions)} | Findings restantes={len(summary.findings)} | PDF={fixed_path / 'bugsuite_report.pdf'}"
        )
        return

    output = Path(args.output).expanduser().resolve() if args.output else (project / "bugsuite_report.pdf")
    summary = run_analysis(project, output)
    print(f"Concluído. Bugs={len(summary.findings)} PDF={output}")


if __name__ == "__main__":
    main()
