from __future__ import annotations

from pathlib import Path
from typing import Any


def scan_ports(hosts: list[str], config: dict[str, Any]) -> list[dict[str, str]]:
    output_path = Path(config.get("output", {}).get("ports", "output/ports.txt"))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    ports = [{"host": host, "port": "80", "service": "http"} for host in hosts]
    output_path.write_text("\n".join(f"{item['host']}:{item['port']}" for item in ports) + "\n", encoding="utf-8")
    return ports
