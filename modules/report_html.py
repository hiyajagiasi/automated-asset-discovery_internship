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
            --bg: #f3f7fb;
            --bg-strong: #eaf2ff;
            --surface: rgba(255, 255, 255, 0.92);
            --surface-alt: #f8fbff;
            --line: #dfeaf7;
            --line-strong: #bfd4ef;
            --text: #12263f;
            --muted: #5e738d;
            --accent: #1e7ae8;
            --accent-soft: #eaf4ff;
            --accent-strong: #0d5ec9;
            --shadow: 0 14px 32px rgba(15, 23, 42, 0.08);
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: linear-gradient(180deg, var(--bg) 0%, var(--bg-strong) 100%);
            color: var(--text);
        }
        .container {
            max-width: 1280px;
            margin: 32px auto;
            padding: 0 20px 40px;
        }
        .header {
            background: rgba(255, 255, 255, 0.95);
            border: 1px solid var(--line);
            border-radius: 22px;
            padding: 28px 28px 20px;
            box-shadow: var(--shadow);
            margin-bottom: 24px;
        }
        .header-top {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 18px;
            flex-wrap: wrap;
        }
        .header h1 {
            margin: 0;
            font-size: clamp(2rem, 3vw, 3rem);
            line-height: 1.2;
            letter-spacing: -0.05em;
        }
        .kicker {
            display: inline-flex;
            align-items: center;
            margin-bottom: 12px;
            padding: 7px 12px;
            border: 1px solid var(--line-strong);
            border-radius: 999px;
            background: var(--accent-soft);
            color: var(--accent-strong);
            font-size: 0.74rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }
        .header-actions {
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
            position: relative;
        }
        .filter-wrap {
            position: relative;
        }
        .filter-btn, .download-btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            border-radius: 12px;
            border: 1px solid transparent;
            font-size: 0.88rem;
            font-weight: 700;
            cursor: pointer;
            transition: transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease;
        }
        .filter-btn {
            background: var(--surface-alt);
            border-color: var(--line);
            color: var(--text);
            padding: 11px 14px;
            box-shadow: inset 0 0 0 1px rgba(255,255,255,0.6);
        }
        .filter-btn svg {
            width: 16px;
            height: 16px;
            stroke: currentColor;
            fill: none;
            stroke-width: 2;
            stroke-linecap: round;
            stroke-linejoin: round;
        }
        .filter-btn:hover, .download-btn:hover {
            transform: translateY(-1px);
        }
        .download-btn {
            background: linear-gradient(135deg, var(--accent), var(--accent-strong));
            color: #ffffff;
            padding: 11px 16px;
            box-shadow: 0 12px 24px rgba(30, 122, 232, 0.18);
        }
        .subtitle {
            margin-top: 12px;
            color: var(--muted);
            font-size: 0.96rem;
        }
        .filter-menu {
            position: absolute;
            top: calc(100% + 8px);
            right: 0;
            min-width: 180px;
            background: rgba(255,255,255,0.98);
            border: 1px solid var(--line);
            border-radius: 14px;
            box-shadow: var(--shadow);
            padding: 8px;
            display: flex;
            flex-direction: column;
            gap: 6px;
            z-index: 20;
        }
        .filter-menu.hidden {
            display: none;
        }
        .filter-option {
            background: transparent;
            border: 1px solid transparent;
            border-radius: 10px;
            color: var(--text);
            text-align: left;
            padding: 10px 12px;
            font-size: 0.88rem;
            font-weight: 600;
            cursor: pointer;
        }
        .filter-option.active {
            background: var(--accent-soft);
            border-color: var(--line-strong);
            color: var(--accent-strong);
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin: 24px 0 28px;
        }
        .stat {
            background: rgba(255, 255, 255, 0.96);
            border: 1px solid var(--line);
            border-radius: 18px;
            padding: 18px 18px 16px;
            box-shadow: var(--shadow);
        }
        .stat .label {
            display: block;
            font-size: 0.74rem;
            color: var(--muted);
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin-bottom: 10px;
        }
        .stat .value {
            font-size: clamp(1.7rem, 2vw, 2.3rem);
            font-weight: 800;
            letter-spacing: -0.05em;
            color: var(--text);
        }
        .section {
            background: rgba(255, 255, 255, 0.96);
            border: 1px solid var(--line);
            border-radius: 20px;
            padding: 22px 20px 18px;
            margin-bottom: 24px;
            box-shadow: var(--shadow);
            transition: opacity 0.2s ease, transform 0.2s ease;
        }
        .section.hidden-section {
            display: none;
        }
        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
            margin-bottom: 12px;
            flex-wrap: wrap;
        }
        .section h2 {
            margin: 0;
            font-size: 1.35rem;
            color: var(--text);
        }
        .pill {
            display: inline-flex;
            align-items: center;
            background: var(--accent-soft);
            color: var(--accent-strong);
            border: 1px solid var(--line-strong);
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 0.72rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.06em;
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
            gap: 10px;
        }
        li {
            background: linear-gradient(180deg, var(--surface-alt), rgba(255,255,255,0.88));
            border: 1px solid var(--line);
            border-left: 4px solid var(--accent);
            border-radius: 12px;
            padding: 12px 14px;
            color: var(--text);
            word-break: break-word;
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.7);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background: rgba(255,255,255,0.96);
            border: 1px solid var(--line);
            border-radius: 12px;
            overflow: hidden;
        }
        th, td {
            text-align: left;
            padding: 12px 14px;
            border-bottom: 1px solid var(--line);
            vertical-align: top;
        }
        th {
            background: linear-gradient(180deg, #f5f9ff, #edf5ff);
            color: var(--muted);
            font-size: 0.76rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }
        tr:last-child td { border-bottom: none; }
        .empty {
            color: var(--muted);
            background: var(--surface-alt);
            border: 1px dashed var(--line-strong);
            border-radius: 12px;
            padding: 18px;
        }
        .page {
            display: none;
        }
        .page.active {
            display: block;
        }
        .pagination {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 16px;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--line);
        }
        .pagination-nav {
            display: flex;
            gap: 12px;
        }
        .nav-btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
            border-radius: 10px;
            border: 1px solid var(--line);
            background: var(--surface-alt);
            color: var(--text);
            padding: 10px 14px;
            font-size: 0.88rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .nav-btn:hover:not(:disabled) {
            background: rgba(30, 122, 232, 0.1);
            border-color: var(--accent);
            color: var(--accent);
            transform: translateY(-1px);
        }
        .nav-btn:disabled {
            opacity: 0.4;
            cursor: not-allowed;
        }
        .page-indicator {
            color: var(--muted);
            font-size: 0.88rem;
            font-weight: 600;
            text-align: center;
            min-width: 120px;
        }
        @media (max-width: 640px) {
            .container { padding: 0 12px 30px; }
            .header { padding: 22px 18px 18px; }
            .header-top { align-items: stretch; }
            .header-actions { width: 100%; justify-content: space-between; }
            .filter-btn, .download-btn { flex: 1; }
            .pagination { flex-direction: column; gap: 12px; }
            .pagination-nav { width: 100%; }
            .nav-btn { flex: 1; }
            .page-indicator { order: -1; }
        }
    </style>
</head>
<body>
    {% set sub_preview = subdomains %}
    {% set live_preview = live_hosts %}
    {% set dead_preview = dead_hosts %}
    {% set port_preview = ports %}
    {% set tech_preview = technologies %}
    <div id="report-data"
         data-subdomains='{{ subdomains|tojson|safe }}'
         data-live-hosts='{{ live_hosts|tojson|safe }}'
         data-dead-hosts='{{ dead_hosts|tojson|safe }}'
         data-ports='{{ ports|tojson|safe }}'
         data-technologies='{{ technologies|tojson|safe }}'
         data-dmarc='{{ dmarc|tojson|safe }}'
         style="display:none;"></div>
    <div class="container">
        <div class="header">
            <div class="header-top">
                <div>
                    <span class="kicker">Asset Discovery</span>
                    <h1>Reconnaissance Report for {{ target }}</h1>
                </div>
                <div class="header-actions">
                    <div class="filter-wrap">
                        <button class="filter-btn" id="filterToggleBtn" type="button" aria-expanded="false" aria-controls="filterMenu">
                            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 6h16M7 12h10M10 18h4"/></svg>
                            <span>Filter</span>
                        </button>
                        <div class="filter-menu hidden" id="filterMenu" role="menu" aria-label="Report filters">
                            <button class="filter-option active" data-filter="all" type="button">All sections</button>
                            <button class="filter-option" data-filter="subdomains" type="button">Subdomains</button>
                            <button class="filter-option" data-filter="live-hosts" type="button">Live Hosts</button>
                            <button class="filter-option" data-filter="dead-hosts" type="button">Dead Hosts</button>
                            <button class="filter-option" data-filter="open-ports" type="button">Open Ports</button>
                            <button class="filter-option" data-filter="technologies" type="button">Technologies</button>
                            <button class="filter-option" data-filter="dmarc" type="button">DMARC</button>
                        </div>
                    </div>
                    <button class="download-btn" id="downloadReportBtn" type="button">Download HTML</button>
                </div>
            </div>
            <div class="subtitle">Executive overview of discovered assets, reachable endpoints, and technology exposure.</div>
        </div>

        <!-- Pagination Controls -->
        <div class="pagination">
            <div class="pagination-nav">
                <button class="nav-btn" id="prevBtn" type="button">
                    <span>← Previous</span>
                </button>
                <button class="nav-btn" id="nextBtn" type="button">
                    <span>Next →</span>
                </button>
            </div>
            <div class="page-indicator">
                <span id="pageNumber">1</span> of <span id="pageTotal">7</span>
            </div>
        </div>

        <!-- Page 1: Summary -->
        <div class="page active" data-page="0" data-section="summary">
            <div class="stats">
                <div class="stat"><span class="label">Subdomains</span><span class="value">{{ subdomains|length }}</span></div>
                <div class="stat"><span class="label">Live Hosts</span><span class="value">{{ live_hosts|length }}</span></div>
                <div class="stat"><span class="label">Dead Hosts</span><span class="value">{{ dead_hosts|length }}</span></div>
                <div class="stat"><span class="label">Open Ports</span><span class="value">{{ ports|length }}</span></div>
                <div class="stat"><span class="label">Technologies</span><span class="value">{{ technologies|length }}</span></div>
            </div>
        </div>

        <!-- Page 2: Subdomains -->
        <div class="page" data-page="1" data-section="subdomains">
            <div class="section">
                <div class="section-header">
                    <h2>Subdomains</h2>
                    <span class="pill">{{ subdomains|length }} entries</span>
                </div>
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
        </div>

        <!-- Page 3: Live Hosts -->
        <div class="page" data-page="2" data-section="live-hosts">
            <div class="section">
                <div class="section-header">
                    <h2>Live Hosts</h2>
                    <span class="pill">{{ live_hosts|length }} entries</span>
                </div>
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
        </div>

        <!-- Page 4: Dead Hosts -->
        <div class="page" data-page="3" data-section="dead-hosts">
            <div class="section">
                <div class="section-header">
                    <h2>Dead Hosts</h2>
                    <span class="pill">{{ dead_hosts|length }} entries</span>
                </div>
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
        </div>

        <!-- Page 5: Open Ports -->
        <div class="page" data-page="4" data-section="open-ports">
            <div class="section">
                <div class="section-header">
                    <h2>Open Ports</h2>
                    <span class="pill">{{ ports|length }} entries</span>
                </div>
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
        </div>

        <!-- Page 6: Technologies -->
        <div class="page" data-page="5" data-section="technologies">
            <div class="section">
                <div class="section-header">
                    <h2>Technologies</h2>
                    <span class="pill">{{ technologies|length }} entries</span>
                </div>
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

        <!-- Page 7: DMARC -->
        <div class="page" data-page="6" data-section="dmarc">
            <div class="section">
                <div class="section-header">
                    <h2>DMARC</h2>
                    <span class="pill">{{ dmarc|length }} entries</span>
                </div>
                {% if dmarc %}
                    <p class="section-meta">Showing DMARC findings for the discovered hosts.</p>
                    <table>
                        <thead>
                            <tr><th>Host</th><th>Status</th><th>Policy</th><th>Policy Type</th><th>Source</th><th>Source Type</th><th>Policy Source</th><th>Record</th></tr>
                        </thead>
                        <tbody>
                            {% for item in dmarc %}
                                <tr>
                                    <td>{{ item.get('host', 'unknown') }}</td>
                                    <td>{{ (item.get('status') or 'unknown')|upper }}</td>
                                    <td>{{ (item.get('policy') or 'none')|upper }}</td>
                                    <td>{{ ((item.get('policy') or 'none')|lower in ['quarantine','reject'] and 'ENFORCEMENT' or (item.get('policy') or 'none')|lower == 'none' and 'MONITORING' or 'UNKNOWN') }}</td>
                                    <td>{{ item.get('source_domain') or item.get('source') or 'NONE' }}</td>
                                    <td>{{ (item.get('source_type') or 'none')|upper }}</td>
                                    <td>{{ ((item.get('source_type') or 'none')|upper + ' ' + ((item.get('policy_source') or 'none')|upper)) if (item.get('source_type') or 'none') != 'none' and (item.get('policy_source') or 'none') != 'none' else 'NONE' }}</td>
                                    <td>{{ item.get('dmarc_record') or 'NONE' }}</td>
                                </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                {% else %}
                    <div class="empty">No DMARC findings recorded.</div>
                {% endif %}
            </div>
        </div>

    </div>
    <script>
        const reportData = document.getElementById('report-data');
        const subdomains = JSON.parse(reportData.dataset.subdomains || '[]');
        const liveHosts = JSON.parse(reportData.dataset.liveHosts || '[]');
        const deadHosts = JSON.parse(reportData.dataset.deadHosts || '[]');
        const ports = JSON.parse(reportData.dataset.ports || '[]');
        const technologies = JSON.parse(reportData.dataset.technologies || '[]');
        const dmarc = JSON.parse(reportData.dataset.dmarc || '[]');

        // Pagination state
        const totalPages = 7;
        let currentPage = 0;

        const prevBtn = document.getElementById('prevBtn');
        const nextBtn = document.getElementById('nextBtn');
        const pageNumberSpan = document.getElementById('pageNumber');
        const filterToggleBtn = document.getElementById('filterToggleBtn');
        const filterMenu = document.getElementById('filterMenu');
        const filterOptions = document.querySelectorAll('.filter-option');

        function showPage(pageNum) {
            // Hide all pages
            document.querySelectorAll('.page').forEach(page => {
                page.classList.remove('active');
            });
            
            // Show current page
            const currentPageEl = document.querySelector(`[data-page="${pageNum}"]`);
            if (currentPageEl) {
                currentPageEl.classList.add('active');
            }
            
            // Update page number
            pageNumberSpan.textContent = pageNum + 1;
            
            // Update button states
            prevBtn.disabled = pageNum === 0;
            nextBtn.disabled = pageNum === totalPages - 1;
            
            // Scroll to top
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }

        prevBtn.addEventListener('click', () => {
            if (currentPage > 0) {
                currentPage--;
                showPage(currentPage);
            }
        });

        nextBtn.addEventListener('click', () => {
            if (currentPage < totalPages - 1) {
                currentPage++;
                showPage(currentPage);
            }
        });

        // Keyboard navigation
        document.addEventListener('keydown', (e) => {
            if (e.key === 'ArrowLeft' && currentPage > 0) {
                currentPage--;
                showPage(currentPage);
            } else if (e.key === 'ArrowRight' && currentPage < totalPages - 1) {
                currentPage++;
                showPage(currentPage);
            }
        });

        // Filter menu functionality
        filterToggleBtn.addEventListener('click', function () {
            const isHidden = filterMenu.classList.toggle('hidden');
            filterToggleBtn.setAttribute('aria-expanded', String(!isHidden));
        });

        filterOptions.forEach((option) => {
            option.addEventListener('click', function () {
                const selectedFilter = this.dataset.filter;
                filterOptions.forEach((item) => item.classList.toggle('active', item === this));

                if (selectedFilter === 'all') {
                    document.querySelectorAll('.page').forEach((page) => {
                        page.classList.remove('hidden-section');
                    });
                    currentPage = 0;
                    showPage(currentPage);
                } else {
                    const targetPage = document.querySelector(`.page[data-section="${selectedFilter}"]`);
                    document.querySelectorAll('.page').forEach((page) => {
                        const shouldShow = page.dataset.section === selectedFilter;
                        page.classList.toggle('hidden-section', !shouldShow);
                    });
                    if (targetPage) {
                        currentPage = Number(targetPage.dataset.page);
                        showPage(currentPage);
                    }
                }

                filterMenu.classList.add('hidden');
                filterToggleBtn.setAttribute('aria-expanded', 'false');
            });
        });

        // Initialize
        showPage(0);

        function buildExecutiveSummaryExport() {

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
    body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: linear-gradient(180deg, #f3f7fb 0%, #eaf2ff 100%); color: #12263f; }
    .container { max-width: 1200px; margin: 32px auto; padding: 0 20px 40px; }
    .header { background: rgba(255,255,255,0.95); border:1px solid #dfeaf7; border-radius:20px; padding:24px 28px; box-shadow: 0 14px 32px rgba(15,23,42,0.08); }
    .title { margin: 0; font-size: clamp(2rem, 3vw, 2.5rem); letter-spacing: -0.04em; }
    .badge { display:inline-block; margin-top:16px; background: #eaf4ff; border:1px solid #bfd4ef; color:#0d5ec9; padding:8px 12px; border-radius:999px; font-size:0.78rem; text-transform:uppercase; letter-spacing:0.06em; font-weight:700; }
    .stats { display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-top: 24px; }
    .stat { background: rgba(255,255,255,0.96); border:1px solid #dfeaf7; border-radius:16px; padding:18px; }
    .label { display:block; font-size:0.7rem; color:#5e738d; text-transform:uppercase; letter-spacing:0.08em; margin-bottom:10px; }
    .value { font-size: clamp(1.7rem, 2vw, 2.4rem); font-weight:800; }
    .section { background: rgba(255,255,255,0.96); border:1px solid #dfeaf7; border-radius:18px; padding:20px; margin-top:24px; box-shadow: 0 14px 32px rgba(15,23,42,0.08); }
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
    dmarc: list[dict[str, str]] | None = None,
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

    if dmarc is None:
        dmarc = []

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
        dmarc=dmarc,
    )
    output_path.write_text(rendered, encoding="utf-8")
    return output_path
