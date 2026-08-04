from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


def _normalize_port_records(ports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in ports:
        if not isinstance(item, dict):
            continue
        normalized.append({
            "host": item.get("host", "unknown"),
            "port": item.get("port", "unknown"),
            "service": item.get("service", "unknown"),
        })
    return normalized


def _normalize_technology_records(technologies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in technologies:
        if not isinstance(item, dict):
            continue
        normalized.append({
            "host": item.get("host", "unknown"),
            "technology": item.get("technology", "unknown"),
        })
    return normalized


def generate_csv_report(
    base_dir: Path,
    target: str,
    subdomains: list[str],
    live_hosts: list[str],
    *args,
    config: dict[str, Any] | None = None,
) -> Path:
    dead_hosts: list[str] = []
    ports: list[dict[str, Any]] = []
    technologies: list[dict[str, Any]] = []

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
    output_path = Path(report_cfg.get("csv", "reports/report.csv"))
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rows = [
        {"target": target, "category": "subdomain", "value": subdomain}
        for subdomain in subdomains
    ]
    rows.extend({"target": target, "category": "live_host", "value": host} for host in live_hosts)
    rows.extend({"target": target, "category": "dead_host", "value": host} for host in dead_hosts)
    rows.extend(
        {"target": target, "category": "port", "value": json.dumps(item, sort_keys=True)}
        for item in _normalize_port_records(ports)
    )
    rows.extend(
        {"target": target, "category": "technology", "value": json.dumps(item, sort_keys=True)}
        for item in _normalize_technology_records(technologies)
    )

    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["target", "category", "value"])
        writer.writeheader()
        writer.writerows(rows)

    return output_path


def generate_json_report(
    base_dir: Path,
    target: str,
    subdomains: list[str],
    live_hosts: list[str],
    *args,
    config: dict[str, Any] | None = None,
) -> Path:
    dead_hosts: list[str] = []
    ports: list[dict[str, Any]] = []
    technologies: list[dict[str, Any]] = []

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
    output_path = Path(report_cfg.get("json", "reports/report.json"))
    output_path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "target": target,
        "subdomains": subdomains,
        "live_hosts": live_hosts,
        "dead_hosts": dead_hosts,
        "ports": _normalize_port_records(ports),
        "technologies": _normalize_technology_records(technologies),
    }

    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return output_path
