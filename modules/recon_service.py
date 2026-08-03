from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from modules.live_hosts import discover_live_hosts
from modules.port_scan import scan_ports
from modules.report_excel import generate_excel_report
from modules.report_html import generate_html_report
from modules.subdomain import discover_subdomains
from modules.technology import discover_technologies
from modules.utils import ensure_directories, get_logger, load_config, load_hosts_from_output, validate_domain


class ReconnaissanceService:
    def __init__(self, base_dir: str | Path | None = None, target: str = "example.com", config_path: str | Path | None = None) -> None:
        self.base_dir = Path(base_dir or Path(__file__).resolve().parents[1])
        self.target = validate_domain(target)
        self.config = load_config(Path(config_path) if config_path else self.base_dir / "config.yaml")
        self.logger = get_logger(self.base_dir / self.config.get("logging", {}).get("file", "logs/scan.log"))

    def run(self) -> dict[str, Any]:
        validate_domain(self.target)
        ensure_directories([
            self.base_dir / "reports",
            self.base_dir / "output",
            self.base_dir / "logs",
        ])

        self.logger.info("Starting reconnaissance for %s", self.target)
        phase_started = time.monotonic()
        self.logger.info("Starting subdomain discovery")
        subdomains = discover_subdomains(self.target, self.config)
        self.logger.info(
            "Subdomain discovery completed in %.1f seconds (%d candidates)",
            time.monotonic() - phase_started,
            len(subdomains),
        )

        phase_started = time.monotonic()
        self.logger.info("Starting live-host probing")
        live_hosts = discover_live_hosts(subdomains, self.config)
        dead_hosts = load_hosts_from_output(self.config, "dead_hosts", "output/dead_host.txt")
        self.logger.info(
            "Live-host probing completed in %.1f seconds (%d live hosts, %d dead hosts)",
            time.monotonic() - phase_started,
            len(live_hosts),
            len(dead_hosts),
        )

        phase_started = time.monotonic()
        self.logger.info("Starting port discovery")
        ports = scan_ports(live_hosts, self.config)
        self.logger.info("Port discovery completed in %.1f seconds", time.monotonic() - phase_started)

        phase_started = time.monotonic()
        self.logger.info("Starting technology discovery")
        technologies = discover_technologies(live_hosts, self.config)
        self.logger.info("Technology discovery completed in %.1f seconds", time.monotonic() - phase_started)

        html_report = generate_html_report(
            self.base_dir,
            self.target,
            subdomains,
            live_hosts,
            dead_hosts,
            ports,
            technologies,
            self.config,
        )
        excel_report = generate_excel_report(
            self.base_dir,
            self.target,
            subdomains,
            live_hosts,
            dead_hosts,
            ports,
            technologies,
            self.config,
        )

        self.logger.info("Completed reconnaissance for %s", self.target)
        return {
            "target": self.target,
            "subdomains": subdomains,
            "live_hosts": live_hosts,
            "dead_hosts": dead_hosts,
            "ports": ports,
            "technologies": technologies,
            "html_report": html_report,
            "excel_report": excel_report,
        }
