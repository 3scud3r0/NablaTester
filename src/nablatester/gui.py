from __future__ import annotations

from pathlib import Path

from .autofix import cascade_autofix
from .engine import run_analysis


def launch_gui() -> None:
    try:
        import tkinter as tk
        from tkinter import ttk
        from tkinter import filedialog, messagebox
    except Exception as exc:
        raise SystemExit(f"GUI indisponível neste ambiente: {exc}")

    root = tk.Tk()
    root.title("NablaTester v2")
    root.geometry("980x640")
    root.resizable(False, False)

    selected_path = tk.StringVar(value="Nenhuma pasta selecionada")
    status_text = tk.StringVar(value="Selecione a pasta do código de teste e clique em Start")
    eta_text = tk.StringVar(value="ETA: --")
    autofix_mode = tk.BooleanVar(value=False)
    strict_gate_mode = tk.BooleanVar(value=False)
    progress_pct_text = tk.StringVar(value="0.0%")
    workers_var = tk.IntVar(value=1)

    def choose_folder() -> None:
        folder = filedialog.askdirectory(title="Selecione a pasta do projeto")
        if folder:
            selected_path.set(folder)
            status_text.set("Pasta selecionada. Clique em Start para executar a análise.")

    def start_analysis() -> None:
        start_btn.config(state="disabled")
        raw = selected_path.get()
        if raw == "Nenhuma pasta selecionada":
            messagebox.showerror("Erro", "Selecione uma pasta antes de iniciar.")
            start_btn.config(state="normal")
            return

        project = Path(raw).expanduser().resolve()
        if not project.exists() or not project.is_dir():
            messagebox.showerror("Erro", f"Pasta inválida: {project}")
            start_btn.config(state="normal")
            return

        status_text.set("Analisando projeto... aguarde.")
        root.update_idletasks()

        def on_progress(event: dict) -> None:
            total = max(1, int(event.get("total", 1)))
            processed = min(total, int(event.get("processed", 0)))
            percent = float(event.get("percent", 0.0))
            current = event.get("current_file", "")
            eta_seconds = event.get("eta_seconds")

            progress_bar["maximum"] = total
            progress_bar["value"] = processed
            progress_pct_text.set(f"{percent:.1f}%")
            status_text.set(
                f"Fase: {event.get('phase', 'analysis')} | {percent:.1f}% | Arquivo: {Path(current).name if current else '-'}"
            )
            if eta_seconds is None:
                eta_text.set("ETA: calculando...")
            else:
                minutes, seconds = divmod(int(max(0, eta_seconds)), 60)
                eta_text.set(f"ETA: {minutes:02d}:{seconds:02d}")
            root.update_idletasks()

        try:
            if autofix_mode.get():
                target = project.parent / f"{project.name}_nablatester_fixed"
                stream = target / "cascade_stream.jsonl"
                fixed_path, summary, actions = cascade_autofix(
                    project,
                    target,
                    stream,
                    progress_callback=on_progress,
                    strict_gate=strict_gate_mode.get(),
                )
                output_pdf = fixed_path / "nablatester_report.pdf"
                extra = f"\nAções aplicadas: {len(actions)}\nProjeto corrigido: {fixed_path}"
            else:
                output_pdf = project / "nablatester_report.pdf"
                summary = run_analysis(project, output_pdf, progress_callback=on_progress, workers=max(1, workers_var.get()))
                extra = ""
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Falha na análise", str(exc))
            status_text.set("Falha na execução. Veja detalhes no erro.")
            start_btn.config(state="normal")
            return

        messagebox.showinfo(
            "Análise finalizada",
            f"Arquivos escaneados: {summary.scanned_files}\n"
            f"Bugs encontrados: {len(summary.findings)}\n"
            f"PDF: {output_pdf}{extra}",
        )
        status_text.set("Análise concluída com sucesso.")
        start_btn.config(state="normal")

    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("TNotebook.Tab", padding=(12, 8))
    style.configure("Accent.Horizontal.TProgressbar", thickness=18)

    title = tk.Label(root, text="NablaTester v2", font=("Arial", 20, "bold"))
    title.pack(pady=12)

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=12, pady=8)

    tab_exec = ttk.Frame(notebook)
    tab_runtime = ttk.Frame(notebook)
    notebook.add(tab_exec, text="Execução")
    notebook.add(tab_runtime, text="Runtime")

    chooser_row = tk.Frame(tab_exec)
    chooser_row.pack(fill="x", padx=20, pady=8)

    path_label = tk.Label(chooser_row, textvariable=selected_path, anchor="w")
    path_label.pack(side="left", fill="x", expand=True)

    choose_btn = tk.Button(chooser_row, text="Selecionar pasta", command=choose_folder)
    choose_btn.pack(side="right", padx=8)

    start_btn = tk.Button(tab_exec, text="Start", width=20, height=2, command=start_analysis, bg="#1f6feb", fg="white")
    start_btn.pack(pady=18)

    autofix_check = tk.Checkbutton(tab_exec, text="Ativar correção determinística em cascata", variable=autofix_mode)
    autofix_check.pack(pady=4)

    strict_gate_check = tk.Checkbutton(tab_exec, text="Ativar quality gate estrito (rollback)", variable=strict_gate_mode)
    strict_gate_check.pack(pady=2)

    workers_row = tk.Frame(tab_exec)
    workers_row.pack(fill="x", padx=20, pady=2)
    workers_label = tk.Label(workers_row, text="Workers paralelos:")
    workers_label.pack(side="left")
    workers_spin = tk.Spinbox(workers_row, from_=1, to=32, textvariable=workers_var, width=5)
    workers_spin.pack(side="left", padx=8)

    progress_bar = ttk.Progressbar(tab_exec, orient="horizontal", mode="determinate", length=820, style="Accent.Horizontal.TProgressbar")
    progress_bar.pack(pady=6)

    metrics_row = tk.Frame(tab_exec)
    metrics_row.pack(fill="x", padx=18, pady=4)
    eta = tk.Label(metrics_row, textvariable=eta_text, fg="#2b2b2b")
    eta.pack(side="left")
    progress_pct = tk.Label(metrics_row, textvariable=progress_pct_text, fg="#2b2b2b")
    progress_pct.pack(side="right")

    status = tk.Label(tab_exec, textvariable=status_text, fg="#333", wraplength=900, justify="left")
    status.pack(pady=4)

    runtime_info = tk.Text(tab_runtime, height=24, width=120)
    runtime_info.pack(fill="both", expand=True, padx=12, pady=10)
    runtime_info.insert("end", "NablaTester Runtime Console\\n")
    runtime_info.insert("end", "- Progresso de execução e ETA aparecem na aba Execução.\\n")
    runtime_info.insert("end", "- Use Strict Gate para rollback transacional automático.\\n")
    runtime_info.configure(state="disabled")

    root.mainloop()
