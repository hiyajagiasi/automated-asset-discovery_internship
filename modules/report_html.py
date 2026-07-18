from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Template


def generate_html_report(base_dir: Path, target: str, subdomains: list[str], live_hosts: list[str], ports: list[dict[str, str]], technologies: list[dict[str, str]], config: dict[str, Any]) -> Path:
    template_path = base_dir / "templates" / "report.html"
    output_path = Path(config.get("reports", {}).get("html", "reports/report.html"))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    template_path.parent.mkdir(parents=True, exist_ok=True)

    if not template_path.exists():
        template_path.write_text("<h1>{{ target }}</h1><ul>{% for item in subdomains %}<li>{{ item }}</li>{% endfor %}</ul>", encoding="utf-8")

    template = Template(template_path.read_text(encoding="utf-8"))
    rendered = template.render(target=target, subdomains=subdomains, live_hosts=live_hosts, ports=ports, technologies=technologies)
    output_path.write_text(rendered, encoding="utf-8")
    return output_path
