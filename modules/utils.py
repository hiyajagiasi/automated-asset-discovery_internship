from __future__ import annotations

import logging
import urllib.parse
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable

import yaml
import validators


DEFAULT_CONFIG: dict[str, Any] = {
    "tools": {
        "subfinder": "subfinder",
        "httpx": "httpx",
        "naabu": "naabu",
        "nmap": "nmap",
        "whatweb": "whatweb",
        "dnsx": "dnsx",
        "webanalyze": "webanalyze",
    },
    "output": {
        "subdomains": "output/subdomains.txt",
        "live_hosts": "output/live_hosts.txt",
        "ports": "output/ports.txt",
        "technologies": "output/technologies.txt",
        "security": "output/security.txt",
    },
    "logging": {"file": "logs/scan.log"},
    "reports": {"html": "reports/report.html", "excel": "reports/report.xlsx"},
    "timeouts": {"subfinder": 60, "httpx": 15, "naabu": 60, "nmap": 60, "whatweb": 60, "webanalyze": 30},
    "threads": 5,
    "limits": {"subdomains": 50, "max_live_host_candidates": 0, "nmap_parallel_workers": 8},
    "httpx_options": {
        "threads": 100,
        "timeout": 15,
        "retries": 3,
        "rate_limit": 150,
        "stream": True,
        "response_size_to_read": 1024,
        "no_decode": True,
        "process_timeout": 0,
        "batch_size": 1000,
        "max_rounds": 20,
        "parallel_workers": 2,
        "max_total_threads": 200,
    },
    "dnsx_options": {"enabled": True, "threads": 500, "retries": 1, "timeout": 5, "rate_limit": 0},
    "batching": {"batch_size": 50, "workers": 4},
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = deepcopy(value)
    return merged


def ensure_directories(paths: Iterable[Path | str]) -> None:
    for path in paths:
        Path(path).mkdir(parents=True, exist_ok=True)


def load_hosts_from_output(config: dict[str, Any], output_key: str, default: str) -> list[str]:
    path = Path(config.get("output", {}).get(output_key, default))
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    return [line.strip() for line in text.splitlines() if line.strip()]


def load_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path).resolve()
    if not config_path.exists():
        default_config = deepcopy(DEFAULT_CONFIG)
        for section in ("output", "reports", "logging"):
            for key, value in list(default_config[section].items()):
                if isinstance(value, str) and not Path(value).is_absolute():
                    default_config[section][key] = str((config_path.parent / value).resolve())
        return default_config

    with config_path.open("r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}

    merged_config = _deep_merge(DEFAULT_CONFIG, config)

    for section in ("output", "reports", "logging"):
        if section in merged_config:
            for key, value in list(merged_config[section].items()):
                if isinstance(value, str) and not Path(value).is_absolute():
                    merged_config[section][key] = str((config_path.parent / value).resolve())
    return merged_config


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
