from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Template


DEFAULT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ target }} Reconnaissance Report</title>
    <style>
        :root {
            --bg: #07111f;
            --bg-2: #0f172a;
            --panel: rgba(15, 23, 42, 0.78);
            --panel-strong: #111827;
            --panel-soft: #0b1220;
            --border: rgba(148, 163, 184, 0.28);
            --text: #e5eefc;
            --muted: #a9b9d1;
            --accent: #5eead4;
            --accent-2: #7dd3fc;
            --warn: #fbbf24;
            --danger: #f87171;
            --shadow: 0 18px 40px rgba(2, 6, 23, 0.45);
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: linear-gradient(180deg, var(--bg) 0%, var(--bg-2) 100%);
            color: var(--text);
        }
        .container {
            max-width: 1500px;
            margin: 24px auto;
            padding: 0 20px 40px;
        }
        .header {
            background: linear-gradient(135deg, rgba(15, 23, 42, 0.96), rgba(30, 41, 59, 0.9));
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 26px 28px;
            box-shadow: var(--shadow);
            margin-bottom: 24px;
        }
        .header-top {
            display: flex;
            justify-content: space-between;
            gap: 16px;
            align-items: center;
            flex-wrap: wrap;
        }
        .header-actions {
            display: flex;
            gap: 12px;
            align-items: center;
            flex-wrap: wrap;
        }
        .download-btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            background: linear-gradient(135deg, var(--accent), var(--accent-2));
            color: #06131e;
            border: none;
            border-radius: 10px;
            padding: 10px 16px;
            font-size: 0.88rem;
            font-weight: 700;
            cursor: pointer;
            box-shadow: 0 8px 18px rgba(94, 234, 212, 0.22);
        }
        .download-btn:hover {
            filter: brightness(1.06);
        }
        .header h1 {
            margin: 0;
            font-size: clamp(2rem, 3vw, 3rem);
            line-height: 1.2;
            letter-spacing: -0.04em;
        }
        .badge {
            background: rgba(94, 234, 212, 0.14);
            border: 1px solid rgba(94, 234, 212, 0.4);
            color: var(--accent);
            padding: 8px 12px;
            border-radius: 999px;
            font-size: 0.78rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.06em;
        }
        .subtitle {
            margin-top: 12px;
            color: var(--muted);
            font-size: 0.98rem;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin: 24px 0 28px;
        }
        .stat {
            background: linear-gradient(180deg, rgba(15, 23, 42, 0.92), rgba(15, 23, 42, 0.75));
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 18px 18px;
            box-shadow: var(--shadow);
        }
        .stat .label {
            display: block;
            font-size: 0.75rem;
            color: var(--muted);
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin-bottom: 10px;
        }
        .stat .value {
            font-size: clamp(1.7rem, 2vw, 2.4rem);
            font-weight: 800;
            letter-spacing: -0.05em;
            color: white;
        }
        .section {
            background: rgba(15, 23, 42, 0.8);
            border: 1px solid var(--border);
            border-radius: 18px;
            padding: 22px 20px 12px;
            margin-bottom: 24px;
            box-shadow: var(--shadow);
        }
        .section h2 {
            margin: 0 0 8px;
            font-size: 1.5rem;
            color: white;
        }
        .section-meta {
            color: var(--muted);
            margin: 0 0 14px;
            font-size: 0.92rem;
        }
        ul {
            list-style: none;
            margin: 0;
            padding: 0;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 8px;
        }
        li {
            background: rgba(15, 23, 42, 0.9);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 10px 12px;
            color: var(--text);
            word-break: break-word;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background: rgba(15, 23, 42, 0.75);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
        }
        th, td {
            text-align: left;
            padding: 12px 14px;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }
        th {
            background: rgba(30, 41, 59, 0.9);
            color: var(--muted);
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }
        tr:last-child td { border-bottom: none; }
        .empty {
            color: var(--muted);
            background: rgba(15, 23, 42, 0.9);
            border: 1px dashed var(--border);
            border-radius: 10px;
            padding: 18px;
        }
    </style>
</head>
<body>
    {% set sub_preview = subdomains %}
    {% set live_preview = live_hosts %}
    {% set dead_preview = dead_hosts %}
    {% set port_preview = ports %}
    {% set tech_preview = technologies %}

    <div class="container">
        <div class="header">
            <div class="header-top">
                <h1>Reconnaissance Report for {{ target }}</h1>
                <div class="header-actions">
                    <span class="badge">Executive Summary</span>
                    <button class="download-btn" id="downloadReportBtn" type="button">Download HTML</button>
                </div>
            </div>
            <div class="subtitle">Asset discovery summary and findings</div>
        </div>

        <div class="stats">
            <div class="stat"><span class="label">Subdomains</span><span class="value">{{ subdomains|length }}</span></div>
            <div class="stat"><span class="label">Live Hosts</span><span class="value">{{ live_hosts|length }}</span></div>
            <div class="stat"><span class="label">Dead Hosts</span><span class="value">{{ dead_hosts|length }}</span></div>
            <div class="stat"><span class="label">Open Ports</span><span class="value">{{ ports|length }}</span></div>
            <div class="stat"><span class="label">Technologies</span><span class="value">{{ technologies|length }}</span></div>
        </div>

        <div class="section">
            <h2>Subdomains</h2>
            {% if subdomains %}
                <p class="section-meta">Showing all {{ sub_preview|length }} discovered entries.</p>
                <ul>
                    {% for item in sub_preview %}
                        <li>{{ item }}</li>
                    {% endfor %}
                </ul>
            {% else %}
                <div class="empty">No subdomains discovered.</div>
            {% endif %}
        </div>

        <div class="section">
            <h2>Live Hosts</h2>
            {% if live_hosts %}
                <p class="section-meta">Showing all {{ live_preview|length }} detected entries.</p>
                <ul>
                    {% for item in live_preview %}
                        <li>{{ item }}</li>
                    {% endfor %}
                </ul>
            {% else %}
                <div class="empty">No live hosts detected.</div>
            {% endif %}
        </div>

        <div class="section">
            <h2>Dead Hosts</h2>
            {% if dead_hosts %}
                <p class="section-meta">Showing all {{ dead_preview|length }} dead targets.</p>
                <ul>
                    {% for item in dead_preview %}
                        <li>{{ item }}</li>
                    {% endfor %}
                </ul>
            {% else %}
                <div class="empty">No dead hosts recorded.</div>
            {% endif %}
        </div>

        <div class="section">
            <h2>Open Ports</h2>
            {% if ports %}
                <p class="section-meta">Showing all {{ port_preview|length }} port entries.</p>
                <table>
                    <thead>
                        <tr><th>Host</th><th>Port</th><th>Service</th></tr>
                    </thead>
                    <tbody>
                        {% for item in port_preview %}
                            <tr>
                                <td>{{ item.get('host', 'unknown') }}</td>
                                <td>{{ item.get('port', 'unknown') }}</td>
                                <td>{{ item.get('service', 'unknown') }}</td>
                            </tr>
                        {% endfor %}
                    </tbody>
                </table>
            {% else %}
                <div class="empty">No open ports found.</div>
            {% endif %}
        </div>

        <div class="section">
            <h2>Technologies</h2>
            {% if technologies %}
                <p class="section-meta">Showing all {{ tech_preview|length }} technology fingerprints.</p>
                <table>
                    <thead>
                        <tr><th>Host</th><th>Technology</th></tr>
                    </thead>
                    <tbody>
                        {% for item in tech_preview %}
                            <tr>
                                <td>{{ item.get('host', 'unknown') }}</td>
                                <td>{{ item.get('technology', 'unknown') }}</td>
                            </tr>
                        {% endfor %}
                    </tbody>
                </table>
            {% else %}
                <div class="empty">No technology fingerprints detected.</div>
            {% endif %}
        </div>
    </div>
    <script>
        function buildExecutiveSummaryExport() {
            const subdomains = {{ subdomains|tojson }};
            const liveHosts = {{ live_hosts|tojson }};
            const deadHosts = {{ dead_hosts|tojson }};
            const ports = {{ ports|tojson }};
            const technologies = {{ technologies|tojson }};

            const renderList = (items, title) => {
                if (!items || !items.length) {
                    return '<div style="padding:14px;border:1px dashed #334155;border-radius:10px;color:#a9b9d1;">No ' + title.toLowerCase() + ' recorded.</div>';
                }
                return '<ul style="list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px;">'
                    + items.slice(0, 30).map((item) => '<li style="background:rgba(15,23,42,0.9);border:1px solid rgba(148,163,184,0.28);border-radius:10px;padding:10px 12px;color:#e5eefc;word-break:break-word;">' + item + '</li>').join('')
                    + '</ul>';
            };

            const renderPortTable = () => {
                if (!ports || !ports.length) {
                    return '<div style="padding:14px;border:1px dashed #334155;border-radius:10px;color:#a9b9d1;">No open ports found.</div>';
                }
                return '<table style="width:100%;border-collapse:collapse;background:rgba(15,23,42,0.75);border:1px solid rgba(148,163,184,0.28);">'
                    + '<thead><tr><th style="text-align:left;padding:12px 14px;border-bottom:1px solid rgba(148,163,184,0.28);color:#a9b9d1;text-transform:uppercase;letter-spacing:0.08em;">Host</th><th style="text-align:left;padding:12px 14px;border-bottom:1px solid rgba(148,163,184,0.28);color:#a9b9d1;text-transform:uppercase;letter-spacing:0.08em;">Port</th><th style="text-align:left;padding:12px 14px;border-bottom:1px solid rgba(148,163,184,0.28);color:#a9b9d1;text-transform:uppercase;letter-spacing:0.08em;">Service</th></tr></thead>'
                    + '<tbody>'
                    + ports.slice(0, 30).map((item) => '<tr><td style="padding:12px 14px;border-bottom:1px solid rgba(148,163,184,0.28);color:#e5eefc;">' + (item.host || 'unknown') + '</td><td style="padding:12px 14px;border-bottom:1px solid rgba(148,163,184,0.28);color:#e5eefc;">' + (item.port || 'unknown') + '</td><td style="padding:12px 14px;border-bottom:1px solid rgba(148,163,184,0.28);color:#e5eefc;">' + (item.service || 'unknown') + '</td></tr>').join('')
                    + '</tbody></table>';
            };

            const renderTechnologyTable = () => {
                if (!technologies || !technologies.length) {
                    return '<div style="padding:14px;border:1px dashed #334155;border-radius:10px;color:#a9b9d1;">No technology fingerprints detected.</div>';
                }
                return '<table style="width:100%;border-collapse:collapse;background:rgba(15,23,42,0.75);border:1px solid rgba(148,163,184,0.28);">'
                    + '<thead><tr><th style="text-align:left;padding:12px 14px;border-bottom:1px solid rgba(148,163,184,0.28);color:#a9b9d1;text-transform:uppercase;letter-spacing:0.08em;">Host</th><th style="text-align:left;padding:12px 14px;border-bottom:1px solid rgba(148,163,184,0.28);color:#a9b9d1;text-transform:uppercase;letter-spacing:0.08em;">Technology</th></tr></thead>'
                    + '<tbody>'
                    + technologies.slice(0, 30).map((item) => '<tr><td style="padding:12px 14px;border-bottom:1px solid rgba(148,163,184,0.28);color:#e5eefc;">' + (item.host || 'unknown') + '</td><td style="padding:12px 14px;border-bottom:1px solid rgba(148,163,184,0.28);color:#e5eefc;">' + (item.technology || 'unknown') + '</td></tr>').join('')
                    + '</tbody></table>';
            };

            return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{ target }} Executive Summary</title>
  <style>
    body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: linear-gradient(180deg, #07111f 0%, #0f172a 100%); color: #e5eefc; }
    .container { max-width: 1200px; margin: 32px auto; padding: 0 20px 40px; }
    .header { background: linear-gradient(135deg, rgba(15,23,42,0.96), rgba(30,41,59,0.9)); border:1px solid rgba(148,163,184,0.28); border-radius:20px; padding:24px 28px; box-shadow: 0 18px 40px rgba(2,6,23,0.45); }
    .title { margin: 0; font-size: clamp(2rem, 3vw, 2.5rem); letter-spacing: -0.04em; }
    .badge { display:inline-block; margin-top:16px; background: rgba(94,234,212,0.14); border:1px solid rgba(94,234,212,0.4); color:#5eead4; padding:8px 12px; border-radius:999px; font-size:0.78rem; text-transform:uppercase; letter-spacing:0.06em; font-weight:700; }
    .stats { display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-top: 24px; }
    .stat { background: rgba(15,23,42,0.8); border:1px solid rgba(148,163,184,0.28); border-radius:16px; padding:18px; }
    .label { display:block; font-size:0.7rem; color:#a9b9d1; text-transform:uppercase; letter-spacing:0.08em; margin-bottom:10px; }
    .value { font-size: clamp(1.7rem, 2vw, 2.4rem); font-weight:800; }
    .section { background: rgba(15,23,42,0.8); border:1px solid rgba(148,163,184,0.28); border-radius:18px; padding:20px; margin-top:24px; box-shadow: 0 18px 40px rgba(2,6,23,0.45); }
    h2 { margin:0 0 12px; font-size:1.35rem; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1 class="title">{{ target }} Executive Summary</h1>
      <div class="badge">Asset Discovery Overview</div>
    </div>

    <div class="stats">
      <div class="stat"><span class="label">Subdomains</span><span class="value">` + subdomains.length + `</span></div>
      <div class="stat"><span class="label">Live Hosts</span><span class="value">` + liveHosts.length + `</span></div>
      <div class="stat"><span class="label">Dead Hosts</span><span class="value">` + deadHosts.length + `</span></div>
      <div class="stat"><span class="label">Open Ports</span><span class="value">` + ports.length + `</span></div>
      <div class="stat"><span class="label">Technologies</span><span class="value">` + technologies.length + `</span></div>
    </div>

    <div class="section">
      <h2>Subdomains</h2>
      ` + renderList(subdomains, 'Subdomains') + `
    </div>

    <div class="section">
      <h2>Live Hosts</h2>
      ` + renderList(liveHosts, 'Live Hosts') + `
    </div>

    <div class="section">
      <h2>Dead Hosts</h2>
      ` + renderList(deadHosts, 'Dead Hosts') + `
    </div>

    <div class="section">
      <h2>Open Ports</h2>
      ` + renderPortTable() + `
    </div>

    <div class="section">
      <h2>Technologies</h2>
      ` + renderTechnologyTable() + `
    </div>
  </div>
</body>
</html>`;
        }

        const downloadBtn = document.getElementById('downloadReportBtn');
        if (downloadBtn) {
            downloadBtn.addEventListener('click', function () {
                const html = buildExecutiveSummaryExport();
                const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
                const url = URL.createObjectURL(blob);
                const anchor = document.createElement('a');
                anchor.href = url;
                anchor.download = '{{ target }}-executive-summary.html';
                document.body.appendChild(anchor);
                anchor.click();
                anchor.remove();
                URL.revokeObjectURL(url);
            });
        }
    </script>
</body>
</html>
"""


def generate_html_report(
    base_dir: Path,
    target: str,
    subdomains: list[str],
    live_hosts: list[str],
    *args,
    config: dict[str, Any] | None = None,
) -> Path:
    dead_hosts: list[str] = []
    ports: list[dict[str, str]] = []
    technologies: list[dict[str, str]] = []

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

    template_path = base_dir / "templates" / "report.html"
    output_path = Path(config.get("reports", {}).get("html", "reports/report.html"))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    template_path.parent.mkdir(parents=True, exist_ok=True)

    template_text = template_path.read_text(encoding="utf-8") if template_path.exists() else ""
    if not template_text.strip():
        template_path.write_text(DEFAULT_TEMPLATE, encoding="utf-8")
        template_text = DEFAULT_TEMPLATE

    template = Template(template_text)
    rendered = template.render(
        target=target,
        subdomains=subdomains,
        live_hosts=live_hosts,
        dead_hosts=dead_hosts,
        ports=ports,
        technologies=technologies,
    )
    output_path.write_text(rendered, encoding="utf-8")
    return output_path
