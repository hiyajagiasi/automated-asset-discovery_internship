from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Dict

from modules.recon_service import ReconnaissanceService
from modules.utils import ensure_directories


def build_project_structure(base_dir: Path | str) -> Dict[str, Path]:
    base = Path(base_dir)
    directories = {
        "reports": base / "reports",
        "output": base / "output",
        "logs": base / "logs",
        "templates": base / "templates",
        "modules": base / "modules",
    }
    ensure_directories(directories.values())
    return directories


def run_scan(target: str, config_path: str | None = None) -> Dict[str, object]:
    base_dir = Path(__file__).resolve().parent
    build_project_structure(base_dir)
    service = ReconnaissanceService(base_dir=base_dir, target=target)
    return service.run()


def main() -> int:
    parser = argparse.ArgumentParser(description="Automated Asset Discovery and Reconnaissance Framework")
    parser.add_argument("target", nargs="?", default="example.com", help="Target domain to scan")
    parser.add_argument("--config", dest="config", default=None, help="Path to YAML configuration file")
    args = parser.parse_args()

    try:
        result = run_scan(args.target, args.config)
    except Exception as exc:  # pragma: no cover - CLI safety
        print(f"Scan failed: {exc}")
        return 1

    print(f"Scan completed for {result['target']}")
    print(f"Subdomains: {len(result['subdomains'])}")
    print(f"Live hosts: {len(result['live_hosts'])}")
    print(f"HTML report: {result['html_report']}")
    print(f"Excel report: {result['excel_report']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
