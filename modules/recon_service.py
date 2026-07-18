from __future__ import annotations

from pathlib import Path
from typing import Any

from modules.live_hosts import discover_live_hosts
from modules.port_scan import scan_ports
from modules.report_excel import generate_excel_report
from modules.report_html import generate_html_report
from modules.subdomain import discover_subdomains
from modules.technology import discover_technologies
from modules.utils import ensure_directories, get_logger, load_config, validate_domain


class ReconnaissanceService:
    def __init__(self, base_dir: str | Path | None = None, target: str = "example.com") -> None:
        self.base_dir = Path(base_dir or Path(__file__).resolve().parents[1])
        self.target = validate_domain(target)
        self.config = load_config(self.base_dir / "config.yaml")
        self.logger = get_logger(self.base_dir / self.config.get("logging", {}).get("file", "logs/scan.log"))

    def run(self) -> dict[str, Any]:
        validate_domain(self.target)
        ensure_directories([
            self.base_dir / "reports",
            self.base_dir / "output",
            self.base_dir / "logs",
        ])

        self.logger.info("Starting reconnaissance for %s", self.target)
        subdomains = discover_subdomains(self.target, self.config)
        live_hosts = discover_live_hosts(subdomains, self.config)
        ports = scan_ports(live_hosts, self.config)
        technologies = discover_technologies(live_hosts, self.config)

        html_report = generate_html_report(
            self.base_dir,
            self.target,
            subdomains,
            live_hosts,
            ports,
            technologies,
            self.config,
        )
        excel_report = generate_excel_report(
            self.base_dir,
            self.target,
            subdomains,
            live_hosts,
            ports,
            technologies,
            self.config,
        )

        self.logger.info("Completed reconnaissance for %s", self.target)
        return {
            "target": self.target,
            "subdomains": subdomains,
            "live_hosts": live_hosts,
            "ports": ports,
            "technologies": technologies,
            "html_report": html_report,
            "excel_report": excel_report,
        }
