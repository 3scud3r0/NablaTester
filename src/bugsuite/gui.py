from __future__ import annotations

from pathlib import Path

from .autofix import cascade_autofix
from .engine import run_analysis


def launch_gui() -> None:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox
    except Exception as exc:
        raise SystemExit(f"GUI indisponível neste ambiente: {exc}")

    root = tk.Tk()
    root.title("BugSuite Analyzer v2")
    root.geometry("720x300")
    root.resizable(False, False)

    selected_path = tk.StringVar(value="Nenhuma pasta selecionada")
    status_text = tk.StringVar(value="Selecione a pasta do código de teste e clique em Start")
    autofix_mode = tk.BooleanVar(value=False)

    def choose_folder() -> None:
        folder = filedialog.askdirectory(title="Selecione a pasta do projeto")
        if folder:
            selected_path.set(folder)
            status_text.set("Pasta selecionada. Clique em Start para executar a análise.")

    def start_analysis() -> None:
        raw = selected_path.get()
        if raw == "Nenhuma pasta selecionada":
            messagebox.showerror("Erro", "Selecione uma pasta antes de iniciar.")
            return

        project = Path(raw).expanduser().resolve()
        if not project.exists() or not project.is_dir():
            messagebox.showerror("Erro", f"Pasta inválida: {project}")
            return

        status_text.set("Analisando projeto... aguarde.")
        root.update_idletasks()

        try:
            if autofix_mode.get():
                target = project.parent / f"{project.name}_bugsuite_fixed"
                stream = target / "cascade_stream.jsonl"
                fixed_path, summary, actions = cascade_autofix(project, target, stream)
                output_pdf = fixed_path / "bugsuite_report.pdf"
                extra = f"\nAções aplicadas: {len(actions)}\nProjeto corrigido: {fixed_path}"
            else:
                output_pdf = project / "bugsuite_report.pdf"
                summary = run_analysis(project, output_pdf)
                extra = ""
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Falha na análise", str(exc))
            status_text.set("Falha na execução. Veja detalhes no erro.")
            return

        messagebox.showinfo(
            "Análise finalizada",
            f"Arquivos escaneados: {summary.scanned_files}\n"
            f"Bugs encontrados: {len(summary.findings)}\n"
            f"PDF: {output_pdf}{extra}",
        )
        status_text.set("Análise concluída com sucesso.")

    title = tk.Label(root, text="BugSuite Analyzer v2", font=("Arial", 18, "bold"))
    title.pack(pady=12)

    chooser_row = tk.Frame(root)
    chooser_row.pack(fill="x", padx=20, pady=8)

    path_label = tk.Label(chooser_row, textvariable=selected_path, anchor="w")
    path_label.pack(side="left", fill="x", expand=True)

    choose_btn = tk.Button(chooser_row, text="Selecionar pasta", command=choose_folder)
    choose_btn.pack(side="right", padx=8)

    start_btn = tk.Button(root, text="Start", width=20, height=2, command=start_analysis)
    start_btn.pack(pady=18)

    autofix_check = tk.Checkbutton(root, text="Ativar correção determinística em cascata", variable=autofix_mode)
    autofix_check.pack(pady=4)

    status = tk.Label(root, textvariable=status_text, fg="#333")
    status.pack(pady=4)

    root.mainloop()
