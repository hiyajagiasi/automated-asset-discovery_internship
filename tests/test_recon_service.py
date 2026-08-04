from pathlib import Path
import sys
from unittest.mock import patch

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from modules.recon_service import ReconnaissanceService
from modules.report_excel import generate_excel_report
from modules.report_html import generate_html_report


def test_recon_service_normalizes_url_target(tmp_path):
    service = ReconnaissanceService(base_dir=tmp_path, target="https://google.com/")

    assert service.target == "google.com"


def test_recon_service_generates_reports(tmp_path):
    service = ReconnaissanceService(base_dir=tmp_path, target="example.com")
    result = service.run()

    assert result["target"] == "example.com"
    assert result["subdomains"]
    assert result["live_hosts"]
    assert result["ports"] is not None
    assert result["html_report"].exists()
    assert result["excel_report"].exists()


def test_recon_service_runs_reports_after_technology_detection(tmp_path):
    service = ReconnaissanceService(base_dir=tmp_path, target="example.com")

    order = []

    def fake_discover_subdomains(target, config):
        order.append("subdomains")
        return ["example.com"]

    def fake_discover_live_hosts(hosts, config):
        order.append("live_hosts")
        return ["example.com"]

    def fake_scan_ports(hosts, config):
        order.append("ports")
        return [{"host": "example.com", "port": "443", "service": "https"}]

    def fake_discover_technologies(hosts, config):
        order.append("technologies")
        return [{"host": "example.com", "technology": "HTTPX: HTML5"}]

    with patch("modules.recon_service.discover_subdomains", side_effect=fake_discover_subdomains), \
         patch("modules.recon_service.discover_live_hosts", side_effect=fake_discover_live_hosts), \
         patch("modules.recon_service.scan_ports", side_effect=fake_scan_ports), \
         patch("modules.recon_service.discover_technologies", side_effect=fake_discover_technologies), \
         patch("modules.recon_service.generate_html_report", return_value=tmp_path / "report.html"), \
         patch("modules.recon_service.generate_excel_report", return_value=tmp_path / "report.xlsx"):
        result = service.run()

    assert order == ["subdomains", "live_hosts", "ports", "technologies"]
    assert result["html_report"] == tmp_path / "report.html"
    assert result["excel_report"] == tmp_path / "report.xlsx"


def test_generate_html_report_contains_full_recon_summary(tmp_path):
    report_path = generate_html_report(
        tmp_path,
        "example.com",
        ["api.example.com", "www.example.com"],
        ["https://example.com", "https://api.example.com"],
        ["https://dead.example.com"],
        [{"host": "https://example.com", "port": "443", "service": "https"}],
        [{"host": "https://example.com", "technology": "HTTPX: HTML5 | Webanalyze: nginx"}],
        {"reports": {"html": str(tmp_path / "reports" / "report.html")}},
    )

    html = report_path.read_text(encoding="utf-8")
    assert "example.com" in html
    assert "Subdomains" in html
    assert "Live Hosts" in html
    assert "Dead Hosts" in html
    assert "Open Ports" in html
    assert "Technologies" in html
    assert "Security Findings" not in html
    assert "api.example.com" in html
    assert "dead.example.com" in html
    assert "buildExecutiveSummaryExport" in html


def test_generate_html_report_rebuilds_empty_template(tmp_path):
    template_path = tmp_path / "templates" / "report.html"
    template_path.parent.mkdir(parents=True, exist_ok=True)
    template_path.write_text("", encoding="utf-8")

    report_path = generate_html_report(
        tmp_path,
        "example.com",
        ["www.example.com"],
        ["https://example.com"],
        [{"host": "https://example.com", "port": "443", "service": "https"}],
        [{"host": "https://example.com", "technology": "HTTPX: HTML5"}],
        {"reports": {"html": str(tmp_path / "reports" / "report.html")}},
    )

    html = report_path.read_text(encoding="utf-8")
    assert "Reconnaissance Report for example.com" in html
    assert "{{" not in html
    assert "}}" not in html


def test_generate_excel_report_creates_multiple_sheets(tmp_path):
    report_path = generate_excel_report(
        tmp_path,
        "example.com",
        ["api.example.com", "www.example.com"],
        ["https://example.com", "https://api.example.com"],
        ["https://dead.example.com"],
        [{"host": "https://example.com", "port": "443", "service": "https"}],
        [{"host": "https://example.com", "technology": "HTTPX: HTML5 | Webanalyze: nginx"}],
        {"reports": {"excel": str(tmp_path / "reports" / "report.xlsx")}},
    )

    workbook = pd.ExcelFile(report_path)
    assert workbook.sheet_names == ["Summary", "Subdomains", "Live Hosts", "Open Ports", "Technologies"]

    summary = pd.read_excel(report_path, sheet_name="Summary")
    assert list(summary.columns) == ["Metric", "Count"]
    summary_text = summary.to_string(index=False)
    assert "Total Subdomains" in summary_text
    assert "Live Hosts" in summary_text
    assert "Dead Hosts" in summary_text
    assert "Open Ports" in summary_text
    assert "Technologies Detected" in summary_text
    assert "Scan Date" in summary_text
    assert summary.loc[0, "Count"] == 2
    assert summary.loc[1, "Count"] == 2
    assert summary.loc[2, "Count"] == 1
    assert summary.loc[3, "Count"] == 1
    assert summary.loc[4, "Count"] == 1

    subdomains = pd.read_excel(report_path, sheet_name="Subdomains")
    assert list(subdomains.columns) == ["Sr No", "Subdomain"]
    assert subdomains.loc[0, "Subdomain"] == "api.example.com"
    assert subdomains.loc[1, "Subdomain"] == "www.example.com"

    live_hosts = pd.read_excel(report_path, sheet_name="Live Hosts")
    assert list(live_hosts.columns) == ["Host", "Status Code", "IP", "Title"]
    assert "https://example.com" in live_hosts["Host"].astype(str).tolist()

    open_ports = pd.read_excel(report_path, sheet_name="Open Ports")
    assert list(open_ports.columns) == ["Host", "Port", "Protocol", "Service"]
    assert open_ports.loc[0, "Host"] == "https://example.com"
    assert open_ports.loc[0, "Port"] == 443
    assert open_ports.loc[0, "Service"] == "https"

    technologies = pd.read_excel(report_path, sheet_name="Technologies")
    assert list(technologies.columns) == ["Host", "Technology", "Version"]
    assert technologies.loc[0, "Host"] == "https://example.com"
    assert technologies.loc[0, "Technology"] == "HTTPX: HTML5"
