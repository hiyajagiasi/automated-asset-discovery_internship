from pathlib import Path
import sys

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
    assert result["ports"][0]["host"] in result["live_hosts"]
    assert result["html_report"].exists()
    assert result["excel_report"].exists()
