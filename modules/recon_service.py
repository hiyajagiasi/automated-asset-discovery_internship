from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Callable

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

    def run(self, progress_callback: Callable[[dict[str, Any]], None] | None = None) -> dict[str, Any]:
        validate_domain(self.target)
        ensure_directories([
            self.base_dir / "reports",
            self.base_dir / "output",
            self.base_dir / "logs",
        ])

        def emit(event: dict[str, Any]) -> None:
            if progress_callback is not None:
                progress_callback(event)

        self.logger.info("Starting reconnaissance for %s", self.target)
        emit({"phase": "start", "message": f"Starting reconnaissance for {self.target}"})

        phase_started = time.monotonic()
        self.logger.info("Starting subdomain discovery")
        emit({"phase": "subdomains", "message": "Discovering subdomains"})
        subdomains = discover_subdomains(self.target, self.config)
        emit({"phase": "subdomains", "message": f"Discovered {len(subdomains)} subdomains", "count": len(subdomains), "items": subdomains[:20]})
        self.logger.info(
            "Subdomain discovery completed in %.1f seconds (%d candidates)",
            time.monotonic() - phase_started,
            len(subdomains),
        )

        phase_started = time.monotonic()
        self.logger.info("Starting live-host probing")
        emit({"phase": "live_hosts", "message": "Probing live hosts"})
        live_hosts = discover_live_hosts(subdomains, self.config)
        dead_hosts = load_hosts_from_output(self.config, "dead_hosts", "output/dead_host.txt")
        emit({"phase": "live_hosts", "message": f"Found {len(live_hosts)} live hosts and {len(dead_hosts)} dead hosts", "live_hosts": live_hosts[:20], "dead_hosts": dead_hosts[:20]})
        self.logger.info(
            "Live-host probing completed in %.1f seconds (%d live hosts, %d dead hosts)",
            time.monotonic() - phase_started,
            len(live_hosts),
            len(dead_hosts),
        )

        phase_started = time.monotonic()
        self.logger.info("Starting port discovery")
        emit({"phase": "ports", "message": "Scanning open ports"})
        ports = scan_ports(live_hosts, self.config)
        emit({"phase": "ports", "message": f"Discovered {len(ports)} open ports", "ports": ports[:20]})
        self.logger.info("Port discovery completed in %.1f seconds", time.monotonic() - phase_started)

        phase_started = time.monotonic()
        self.logger.info("Starting technology discovery")
        emit({"phase": "technologies", "message": "Detecting technologies"})
        technologies = discover_technologies(live_hosts, self.config)
        emit({"phase": "technologies", "message": f"Detected {len(technologies)} technologies", "technologies": technologies[:20]})
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

        emit({"phase": "complete", "message": "Report generation complete", "html_report": str(html_report), "excel_report": str(excel_report)})
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
