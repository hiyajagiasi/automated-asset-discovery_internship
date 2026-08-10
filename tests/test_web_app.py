from pathlib import Path
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import ACTIVE_SCANS, app
from modules.recon_service import ReconnaissanceService


def test_blank_or_placeholder_target_is_rejected():
    client = app.test_client()

    response = client.post('/scan', data={'target': 'Enter a URL or domain'})
    assert response.status_code == 400
    assert b'Please paste a target URL or domain' in response.data


def test_scan_status_returns_download_urls():
    client = app.test_client()
    scan_id = 'download-test'
    ACTIVE_SCANS[scan_id] = {
        'target': 'example.com',
        'events': [],
        'complete': True,
        'error': None,
        'html_report': '/Users/example/report.html',
        'excel_report': '/Users/example/report.xlsx',
    }

    response = client.get(f'/scan-status/{scan_id}')
    payload = response.get_json()

    assert payload['html_report'] == '/download/report.html'
    assert payload['excel_report'] == '/download/report.xlsx'
    assert 'csv_report' not in payload
    assert 'json_report' not in payload


def test_cancel_scan_marks_status_cancelled():
    client = app.test_client()
    scan_id = 'cancel-test'
    ACTIVE_SCANS[scan_id] = {
        'target': 'example.com',
        'events': [],
        'complete': False,
        'error': None,
        'cancel_requested': False,
        'cancelled': False,
        'html_report': None,
        'excel_report': None,
    }

    response = client.post(f'/cancel/{scan_id}')
    payload = response.get_json()

    assert response.status_code == 200
    assert payload['cancelled'] is True
    assert ACTIVE_SCANS[scan_id]['cancelled'] is True


def test_scan_submission_redirects_to_status_page():
    client = app.test_client()

    response = client.post('/scan', data={'target': 'https://github.com'})
    assert response.status_code == 302
    assert response.headers['Location'].startswith('/?scan_id=')

    follow_up = client.get(response.headers['Location'])
    assert response.status_code == 302
    assert b'Scan in progress' in follow_up.data
    assert b'github.com' in follow_up.data


def test_web_page_exposes_only_html_and_excel_download_links():
    client = app.test_client()

    response = client.post('/scan', data={'target': 'https://github.com'})
    assert response.status_code == 302
    assert response.headers['Location'].startswith('/?scan_id=')
    follow_up = client.get(response.headers['Location'])
    assert b'Open HTML report' in follow_up.data
    assert b'Open Excel report' in follow_up.data
    assert b'Open CSV export' not in follow_up.data
    assert b'Open JSON export' not in follow_up.data


def test_web_app_renders_form_and_creates_report():
    client = app.test_client()

    response = client.get('/')
    assert response.status_code == 200
    assert b'Asset Discovery' in response.data or b'Paste the target URL' in response.data

    target = 'https://github.com'
    scan_response = client.post('/scan', data={'target': target})
    assert scan_response.status_code == 302
    assert scan_response.headers['Location'].startswith('/?scan_id=')

    status_response = client.get(scan_response.headers['Location'])
    assert status_response.status_code == 200
    assert b'Scan in progress' in status_response.data
    assert b'github.com' in status_response.data

    report_path = Path('reports/report.html')
    assert report_path.exists(), 'Expected a generated HTML report in the reports folder.'
    assert 'github.com' in report_path.read_text(encoding='utf-8')
    assert not Path('reports/report.csv').exists()
    assert not Path('reports/report.json').exists()


def test_recon_service_emits_progress_events(tmp_path):
    service = ReconnaissanceService(base_dir=tmp_path, target='example.com')
    events = []

    def capture_event(event):
        events.append(event)

    with patch('modules.recon_service.discover_subdomains', return_value=['api.example.com']), \
         patch('modules.recon_service.discover_live_hosts', return_value=['https://example.com']), \
         patch('modules.recon_service.scan_ports', return_value=[{'host': 'https://example.com', 'port': '443', 'service': 'https'}]), \
         patch('modules.recon_service.discover_technologies', return_value=[{'host': 'https://example.com', 'technology': 'nginx'}]), \
         patch('modules.recon_service.generate_html_report', return_value=tmp_path / 'report.html'), \
         patch('modules.recon_service.generate_excel_report', return_value=tmp_path / 'report.xlsx'):
        service.run(progress_callback=capture_event)

    phases = [event['phase'] for event in events if 'phase' in event]
    assert 'subdomains' in phases
    assert 'live_hosts' in phases
    assert 'ports' in phases
    assert 'technologies' in phases
    assert any(event.get('message') for event in events)
