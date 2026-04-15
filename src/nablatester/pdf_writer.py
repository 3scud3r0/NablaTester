from __future__ import annotations

from pathlib import Path

from .models import AnalysisSummary


class MinimalPdf:
    """Gera PDF textual sem dependências externas."""

    def __init__(self) -> None:
        self.objects: list[bytes] = []

    def _add_object(self, payload: bytes) -> int:
        self.objects.append(payload)
        return len(self.objects)

    @staticmethod
    def _escape_text(text: str) -> str:
        return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    def render(self, pages: list[list[str]], output: Path) -> None:
        page_ids: list[int] = []
        font_id = self._add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

        for lines in pages:
            content_stream = ["BT", "/F1 10 Tf", "50 780 Td", "14 TL"]
            for idx, line in enumerate(lines):
                prefix = "" if idx == 0 else "T* "
                content_stream.append(f"{prefix}({self._escape_text(line)}) Tj")
            content_stream.append("ET")
            raw = "\n".join(content_stream).encode("latin-1", errors="replace")
            content_id = self._add_object(f"<< /Length {len(raw)} >>\nstream\n".encode() + raw + b"\nendstream")
            page_id = self._add_object(
                f"<< /Type /Page /Parent 0 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>".encode()
            )
            page_ids.append(page_id)

        kids = " ".join(f"{x} 0 R" for x in page_ids)
        pages_id = self._add_object(f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode())
        catalog_id = self._add_object(f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode())

        fixed_objects: list[bytes] = []
        for payload in self.objects:
            fixed_objects.append(payload.replace(b"/Parent 0 0 R", f"/Parent {pages_id} 0 R".encode()))

        xref_positions: list[int] = [0]
        buffer = b"%PDF-1.4\n"
        for idx, obj in enumerate(fixed_objects, start=1):
            xref_positions.append(len(buffer))
            buffer += f"{idx} 0 obj\n".encode() + obj + b"\nendobj\n"

        xref_start = len(buffer)
        buffer += f"xref\n0 {len(fixed_objects)+1}\n".encode()
        buffer += b"0000000000 65535 f \n"
        for pos in xref_positions[1:]:
            buffer += f"{pos:010d} 00000 n \n".encode()

        buffer += (
            f"trailer\n<< /Size {len(fixed_objects)+1} /Root {catalog_id} 0 R >>\n"
            f"startxref\n{xref_start}\n%%EOF\n"
        ).encode()

        output.write_bytes(buffer)


def paginate_report(summary: AnalysisSummary, max_lines_per_page: int = 48) -> list[list[str]]:
    lines: list[str] = [
        "NablaTester - Relatorio Final",
        "",
        f"Projeto: {summary.project_path}",
        f"Inicio: {summary.started_at}",
        f"Fim: {summary.ended_at}",
        f"Arquivos analisados: {summary.scanned_files}",
        f"Findings: total={len(summary.findings)} critical={summary.critical_count} high={summary.high_count} medium={summary.medium_count} low={summary.low_count}",
        "",
        "Plano de debug conjunto (ordem sugerida):",
        "1) Corrigir Criticals; 2) Corrigir Highs de seguranca; 3) Corrigir bloqueadores de execucao; 4) Rodar regressao completa.",
        "",
        "Detalhamento por bug:",
    ]

    for idx, finding in enumerate(summary.findings, start=1):
        lines.extend(
            [
                "-" * 90,
                f"[{idx}] {finding.bug_type} | severidade={finding.severity}",
                f"Arquivo: {finding.file_path}:{finding.line}",
                f"Descricao: {finding.description}",
                "Como debuggar:",
            ]
        )
        lines.extend([f"  - {step}" for step in finding.debug_steps])
        lines.append(f"Debug conjunto: {finding.combined_debug_note}")

    if not summary.findings:
        lines.extend([
            "Nenhum bug detectado pelas regras atuais.",
            "Sugestao: habilitar testes dinamicos e ampliar regras por linguagem para aumentar cobertura.",
        ])

    pages: list[list[str]] = []
    for i in range(0, len(lines), max_lines_per_page):
        pages.append(lines[i:i + max_lines_per_page])
    return pages


def write_pdf_report(summary: AnalysisSummary, output: Path) -> None:
    pages = paginate_report(summary)
    pdf = MinimalPdf()
    pdf.render(pages, output)
