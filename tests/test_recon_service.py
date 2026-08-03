from pathlib import Path
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from modules.recon_service import ReconnaissanceService


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
