from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd


def generate_excel_report(base_dir: Path, target: str, subdomains: list[str], live_hosts: list[str], ports: list[dict[str, str]], technologies: list[dict[str, str]], config: dict[str, Any]) -> Path:
    output_path = Path(config.get("reports", {}).get("excel", "reports/report.xlsx"))
    output_path.parent.mkdir(parents=True, exist_ok=True)

    summary = pd.DataFrame(
        [
            {
                "target": target,
                "subdomains": len(subdomains),
                "live_hosts": len(live_hosts),
                "ports": len(ports),
                "technologies": len(technologies),
            }
        ]
    )

    subdomain_df = pd.DataFrame({"subdomain": subdomains}) if subdomains else pd.DataFrame(columns=["subdomain"])
    live_host_df = pd.DataFrame({"live_host": live_hosts}) if live_hosts else pd.DataFrame(columns=["live_host"])
    port_df = pd.DataFrame(ports) if ports else pd.DataFrame(columns=["host", "port", "service"])
    technology_df = pd.DataFrame(technologies) if technologies else pd.DataFrame(columns=["host", "technology"])

    with pd.ExcelWriter(output_path) as writer:
        summary.to_excel(writer, sheet_name="Summary", index=False)
        subdomain_df.to_excel(writer, sheet_name="Subdomains", index=False)
        live_host_df.to_excel(writer, sheet_name="Live Hosts", index=False)
        port_df.to_excel(writer, sheet_name="Ports", index=False)
        technology_df.to_excel(writer, sheet_name="Technologies", index=False)
    return output_path
