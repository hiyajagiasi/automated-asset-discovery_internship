from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd


def generate_excel_report(base_dir: Path, target: str, subdomains: list[str], live_hosts: list[str], ports: list[dict[str, str]], technologies: list[dict[str, str]], config: dict[str, Any]) -> Path:
    output_path = Path(config.get("reports", {}).get("excel", "reports/report.xlsx"))
    output_path.parent.mkdir(parents=True, exist_ok=True)

    summary = pd.DataFrame(
        [
            {"target": target, "subdomains": len(subdomains), "live_hosts": len(live_hosts), "ports": len(ports), "technologies": len(technologies)}
        ]
    )
    with pd.ExcelWriter(output_path) as writer:
        summary.to_excel(writer, sheet_name="Summary", index=False)
    return output_path
