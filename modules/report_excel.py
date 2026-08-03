from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd


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
                "subdomains_count": len(subdomains),
                "live_hosts_count": len(live_hosts),
                "dead_hosts_count": len(dead_hosts),
                "ports_count": len(ports),
                "technologies_count": len(technologies),
                "subdomains": _join_values(subdomains),
                "live_hosts": _join_values(live_hosts),
                "dead_hosts": _join_values(dead_hosts),
                "ports": _join_values([
                    f"{item.get('host', 'unknown')}:{item.get('port', 'unknown')} ({item.get('service', 'unknown')})"
                    for item in ports if isinstance(item, dict)
                ]),
                "technologies": _join_values([
                    f"{item.get('host', 'unknown')}: {item.get('technology', 'unknown')}"
                    for item in technologies if isinstance(item, dict)
                ]),
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
    return output_path
