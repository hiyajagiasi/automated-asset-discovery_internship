from __future__ import annotations

import logging
import urllib.parse
from pathlib import Path
from typing import Any, Iterable

import yaml
import validators


def ensure_directories(paths: Iterable[Path | str]) -> None:
    for path in paths:
        Path(path).mkdir(parents=True, exist_ok=True)


def load_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path).resolve()
    if not config_path.exists():
        return {
            "tools": {
                "subfinder": "subfinder",
                "httpx": "httpx",
                "naabu": "naabu",
                "nmap": "nmap",
                "whatweb": "whatweb",
            },
            "output": {
                "subdomains": str((config_path.parent / "output" / "subdomains.txt").resolve()),
                "live_hosts": str((config_path.parent / "output" / "live_hosts.txt").resolve()),
                "ports": str((config_path.parent / "output" / "ports.txt").resolve()),
                "technologies": str((config_path.parent / "output" / "technologies.txt").resolve()),
            },
            "logging": {"file": str((config_path.parent / "logs" / "scan.log").resolve())},
            "reports": {
                "html": str((config_path.parent / "reports" / "report.html").resolve()),
                "excel": str((config_path.parent / "reports" / "report.xlsx").resolve()),
            },
            "timeouts": {"subfinder": 60, "httpx": 60, "naabu": 60, "nmap": 60, "whatweb": 60},
            "threads": 5,
            "httpx_options": {
                "threads": 100,
                "timeout": 10,
                "retries": 1,
                "rate_limit": 150,
                "stream": True,
                "response_size_to_read": 1024,
                "no_decode": True,
                "process_timeout": 0,
                "batch_size": 1000,
                "max_rounds": 20,
                "parallel_workers": 3,
                "max_total_threads": 300,
            },
        }

    with config_path.open("r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}

    for section in ("output", "reports", "logging"):
        if section in config:
            for key, value in list(config[section].items()):
                if isinstance(value, str) and not Path(value).is_absolute():
                    config[section][key] = str((config_path.parent / value).resolve())
    return config


def validate_domain(domain: str) -> str:
    parsed = urllib.parse.urlparse(domain)
    hostname = parsed.hostname if parsed.scheme else domain
    if hostname is None or not validators.domain(hostname):
        raise ValueError(f"Invalid domain: {domain}")
    return hostname


def get_logger(log_file: str | Path) -> logging.Logger:
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("asset_discovery")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    return logger
