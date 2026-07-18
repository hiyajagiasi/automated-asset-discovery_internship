from __future__ import annotations

from pathlib import Path
from typing import Any


def discover_technologies(hosts: list[str], config: dict[str, Any]) -> list[dict[str, str]]:
    output_path = Path(config.get("output", {}).get("technologies", "output/technologies.txt"))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    technologies = [{"host": host, "technology": "unknown"} for host in hosts]
    output_path.write_text("\n".join(f"{item['host']}:{item['technology']}" for item in technologies) + "\n", encoding="utf-8")
    return technologies
