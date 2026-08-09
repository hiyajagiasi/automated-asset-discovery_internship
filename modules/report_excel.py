from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd
from openpyxl import load_workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter


EXCEL_CELL_LIMIT = 32767
EXCEL_TRUNCATION_MARKER = " ... [truncated; see detail sheet]"


def _truncate_for_excel(value: str) -> str:
    if len(value) <= EXCEL_CELL_LIMIT:
        return value
    return value[:EXCEL_CELL_LIMIT - len(EXCEL_TRUNCATION_MARKER)] + EXCEL_TRUNCATION_MARKER


def _apply_sheet_formatting(workbook_path: Path) -> None:
    workbook = load_workbook(workbook_path)
    header_fill = PatternFill("solid", fgColor="1F2937")
    header_font = Font(bold=True, color="FFFFFF")
    border = Border(
        left=Side(style="thin", color="D1D5DB"),
        right=Side(style="thin", color="D1D5DB"),
        top=Side(style="thin", color="D1D5DB"),
        bottom=Side(style="thin", color="D1D5DB"),
    )
    center_alignment = Alignment(horizontal="center", vertical="center")

    for sheet in workbook.worksheets:
        sheet.freeze_panes = "A2"
        sheet.auto_filter.ref = sheet.dimensions

        for row in sheet.iter_rows(min_row=1, max_row=sheet.max_row, min_col=1, max_col=sheet.max_column):
            for cell in row:
                cell.border = border
                if cell.row == 1:
                    cell.font = header_font
                    cell.fill = header_fill
                    cell.alignment = center_alignment
                else:
                    cell.alignment = Alignment(vertical="top")

                if isinstance(cell.value, str) and cell.value.startswith(("http://", "https://")):
                    cell.hyperlink = cell.value
                    cell.style = "Hyperlink"

        for column_cells in sheet.columns:
            column_letter = get_column_letter(column_cells[0].column)
            max_length = 0
            for cell in column_cells:
                if cell.value is None:
                    continue
                candidate = str(cell.value)
                max_length = max(max_length, len(candidate))
            sheet.column_dimensions[column_letter].width = min(max_length + 2, 60)

    workbook.save(workbook_path)


def generate_excel_report(
    base_dir: Path,
    target: str,
    subdomains: list[str],
    live_hosts: list[str],
    *args,
    config: dict[str, Any] | None = None,
) -> Path:
    dead_hosts: list[str] = []
    ports: list[dict[str, str]] = []
    technologies: list[dict[str, str]] = []

    if args:
        if len(args) >= 1 and isinstance(args[-1], dict):
            config = args[-1]
            args = args[:-1]

        if len(args) == 3:
            dead_hosts, ports, technologies = args
        elif len(args) == 2:
            ports, technologies = args
        elif len(args) == 1:
            first = args[0]
            if isinstance(first, list) and first and isinstance(first[0], dict):
                ports = first
            else:
                dead_hosts = first

    if config is None:
        config = {}

    report_cfg = config.get("reports", {}) if isinstance(config, dict) else {}
    output_path = Path(report_cfg.get("excel", "reports/report.xlsx"))
    output_path.parent.mkdir(parents=True, exist_ok=True)

    generated_at = pd.Timestamp.now(tz="UTC").strftime("%Y-%m-%d %H:%M:%S UTC")

    def _join_values(values: list[Any]) -> str:
        return "; ".join(str(value) for value in values if value is not None and str(value).strip())

    summary = pd.DataFrame(
        [
            {
                "target": target,
                "generated_at": generated_at,
                "subdomains": len(subdomains),
                "live_hosts": len(live_hosts),
                "dead_hosts": len(dead_hosts),
                "ports": len(ports),
                "technologies": len(technologies),
                "subdomains_detail": _truncate_for_excel(_join_values(subdomains)),
                "live_hosts_detail": _truncate_for_excel(_join_values(live_hosts)),
                "dead_hosts_detail": _truncate_for_excel(_join_values(dead_hosts)),
                "ports_detail": _truncate_for_excel(_join_values([
                    f"{item.get('host', 'unknown')}:{item.get('port', 'unknown')} ({item.get('service', 'unknown')})"
                    for item in ports if isinstance(item, dict)
                ])),
                "technologies_detail": _truncate_for_excel(_join_values([
                    f"{item.get('host', 'unknown')}: {item.get('technology', 'unknown')}"
                    for item in technologies if isinstance(item, dict)
                ])),
            }
        ]
    )

    normalized_ports = []
    for item in ports:
        if isinstance(item, dict):
            normalized_ports.append({
                "host": item.get("host", "unknown"),
                "port": item.get("port", "unknown"),
                "service": item.get("service", "unknown"),
            })

    normalized_technologies = []
    for item in technologies:
        if isinstance(item, dict):
            normalized_technologies.append({
                "host": item.get("host", "unknown"),
                "technology": item.get("technology", "unknown"),
            })

    subdomain_df = pd.DataFrame({"subdomain": subdomains}) if subdomains else pd.DataFrame(columns=["subdomain"])
    live_host_df = pd.DataFrame({"live_host": live_hosts}) if live_hosts else pd.DataFrame(columns=["live_host"])
    dead_host_df = pd.DataFrame({"dead_host": dead_hosts}) if dead_hosts else pd.DataFrame(columns=["dead_host"])
    port_df = pd.DataFrame(normalized_ports) if normalized_ports else pd.DataFrame(columns=["host", "port", "service"])
    technology_df = pd.DataFrame(normalized_technologies) if normalized_technologies else pd.DataFrame(columns=["host", "technology"])

    with pd.ExcelWriter(output_path) as writer:
        summary.to_excel(writer, sheet_name="Summary", index=False)
        subdomain_df.to_excel(writer, sheet_name="Subdomains", index=False)
        live_host_df.to_excel(writer, sheet_name="Live Hosts", index=False)
        dead_host_df.to_excel(writer, sheet_name="Dead Hosts", index=False)
        port_df.to_excel(writer, sheet_name="Ports", index=False)
        technology_df.to_excel(writer, sheet_name="Technologies", index=False)

    _apply_sheet_formatting(output_path)
    return output_path
