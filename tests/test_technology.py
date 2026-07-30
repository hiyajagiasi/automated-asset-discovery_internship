from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from modules.technology import discover_technologies


def test_discover_technologies_maps_headers_to_meaningful_technologies(tmp_path, monkeypatch):
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    config = {
        "output": {"technologies": str(output_dir / "technologies.txt")},
        "tools": {"httpx": "httpx", "webanalyze": "webanalyze", "nuclei": "nuclei"},
        "timeouts": {"httpx": 10, "webanalyze": 10, "nuclei": 10},
    }

    def fake_run(cmd, capture_output, text, timeout):
        if cmd[0] == "httpx":
            assert "-silent" in cmd
            assert "-json" in cmd
            assert "-tech-detect" in cmd
            assert cmd[-1] == "https://docs.google.com"
            payload = {
                "headers": {
                    "server": "ESF",
                    "alt-svc": 'h3=":443"',
                    "content-type": "text/html; charset=utf-8",
                    "x-frame-options": "DENY",
                }
            }
            return SimpleNamespace(stdout=json.dumps(payload), returncode=0)
        return SimpleNamespace(stdout='{}', returncode=0)

    monkeypatch.setattr("modules.technology.subprocess.run", fake_run)

    results = discover_technologies(["docs.google.com"], config)

    technology = results[0]["technology"]
    assert "Google Web Server (ESF)" in technology
    assert "HTTP/3" in technology
    assert "HTML5" in technology
    assert "X-Frame-Options" not in technology


def test_discover_technologies_parses_nested_wappalyzer_payload(tmp_path, monkeypatch):
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    config = {
        "output": {"technologies": str(output_dir / "technologies.txt")},
        "tools": {"httpx": "httpx", "webanalyze": "webanalyze"},
        "timeouts": {"httpx": 10, "webanalyze": 10},
    }

    def fake_run(cmd, capture_output, text, timeout, **kwargs):
        if cmd[0] == "httpx":
            return SimpleNamespace(stdout='{"headers": {"server": "nginx"}}', returncode=0)
        elif cmd[0] == "webanalyze":
            return SimpleNamespace(stdout='{"WordPress": {"version": "5.8", "categories": ["CMS"]}}\n', returncode=0)
        return SimpleNamespace(stdout='{}', returncode=0)

    monkeypatch.setattr("modules.technology.subprocess.run", fake_run)

    results = discover_technologies(["example.com"], config)

    assert "HTTPX:" in results[0]["technology"]
    assert "Webanalyze:" in results[0]["technology"]
    assert "WordPress" in results[0]["technology"]


def test_discover_technologies_uses_hostname_fallback_for_google_hosts(tmp_path, monkeypatch):
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    config = {
        "output": {"technologies": str(output_dir / "technologies.txt")},
        "tools": {"httpx": "httpx", "webanalyze": "webanalyze"},
        "timeouts": {"httpx": 10, "webanalyze": 10},
    }

    def fake_run(cmd, capture_output, text, timeout, **kwargs):
        # Return empty results for all tools to trigger fallback
        if cmd[0] == "httpx":
            return SimpleNamespace(stdout='{"headers": {}}', returncode=0)
        elif cmd[0] == "webanalyze":
            return SimpleNamespace(stdout='{}', returncode=0)
        return SimpleNamespace(stdout='{}', returncode=0)

    monkeypatch.setattr("modules.technology.subprocess.run", fake_run)
    
    # Mock urllib to prevent the fallback from fetching real headers
    def fake_urlopen(request, timeout=None):
        from io import BytesIO
        from http.client import HTTPMessage
        import email
        
        # Return a response with no headers
        fp = BytesIO(b"")
        headers = email.message_from_string("")
        resp = SimpleNamespace(
            headers=headers,
            read=lambda: b"",
            __enter__=lambda self: self,
            __exit__=lambda self, *args: None
        )
        return resp
    
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    results = discover_technologies(["docs.google.com"], config)

    assert "Google Docs" in results[0]["technology"]
    assert "HTTPX:" in results[0]["technology"]
    assert "Webanalyze:" in results[0]["technology"]


def test_discover_technologies_uses_clear_fallback_labels_when_nothing_matches(tmp_path, monkeypatch):
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    config = {
        "output": {"technologies": str(output_dir / "technologies.txt")},
        "tools": {"httpx": "httpx", "webanalyze": "webanalyze"},
        "timeouts": {"httpx": 10, "webanalyze": 10},
    }

    def fake_run(cmd, capture_output, text, timeout, **kwargs):
        if cmd[0] == "httpx":
            return SimpleNamespace(stdout='{"headers": {}}', returncode=0)
        if cmd[0] == "webanalyze":
            return SimpleNamespace(stdout='{}', returncode=0)
        return SimpleNamespace(stdout='{}', returncode=0)

    monkeypatch.setattr("modules.technology.subprocess.run", fake_run)

    results = discover_technologies(["example.com"], config)

    assert "HTTPX: unreachable" in results[0]["technology"]
    assert "Webanalyze: no fingerprint matched" in results[0]["technology"]


def test_discover_technologies_parses_webanalyze_matches_payload(tmp_path, monkeypatch):
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    config = {
        "output": {"technologies": str(output_dir / "technologies.txt")},
        "tools": {"httpx": "httpx", "webanalyze": "webanalyze"},
        "timeouts": {"httpx": 10, "webanalyze": 10},
    }

    def fake_run(cmd, capture_output, text, timeout, **kwargs):
        if cmd[0] == "httpx":
            return SimpleNamespace(stdout='{"headers": {}}', returncode=0)
        elif cmd[0] == "webanalyze":
            payload = {
                "hostname": "https://example.com",
                "matches": [
                    {"app_name": "HTTP/3", "version": ""},
                    {"app_name": "HSTS", "version": ""},
                    {"app_name": "WordPress", "version": "5.8", "app": {"category_names": ["CMS"]}},
                ],
            }
            return SimpleNamespace(stdout=json.dumps(payload), returncode=0)
        return SimpleNamespace(stdout='{}', returncode=0)

    monkeypatch.setattr("modules.technology.subprocess.run", fake_run)

    results = discover_technologies(["example.com"], config)

    technology = results[0]["technology"]
    assert "HTTP/3" in technology
    assert "HSTS" in technology
    assert "WordPress" in technology
    assert "hostname" not in technology
    assert "matches" not in technology


def test_discover_technologies_processes_hosts_in_parallel_batches(tmp_path, monkeypatch):
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    config = {
        "output": {"technologies": str(output_dir / "technologies.txt")},
        "tools": {"httpx": "httpx", "webanalyze": "webanalyze"},
        "timeouts": {"httpx": 10, "webanalyze": 10},
        "batching": {"batch_size": 2, "workers": 2},
    }

    seen = []

    def fake_discover_single(host, httpx_bin, webanalyze_bin, timeout, webanalyze_timeout):
        seen.append(host)
        return {"host": host, "technology": f"HTTPX: tech:{host} | Webanalyze: tech"}

    monkeypatch.setattr("modules.technology._discover_single_technology", fake_discover_single)

    results = discover_technologies(["one.com", "two.com", "three.com"], config)

    assert [item["host"] for item in results] == ["one.com", "two.com", "three.com"]
    assert len(seen) == 3
    assert set(seen) == {"one.com", "two.com", "three.com"}


def test_discover_technologies_combines_wappalyzer_categories(tmp_path, monkeypatch):
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    config = {
        "output": {"technologies": str(output_dir / "technologies.txt")},
        "tools": {"httpx": "httpx", "webanalyze": "webanalyze"},
        "timeouts": {"httpx": 10, "webanalyze": 10},
    }

    def fake_run(cmd, capture_output, text, timeout, **kwargs):
        if cmd[0] == "httpx":
            return SimpleNamespace(
                stdout='{"headers": {"server": "nginx"}}',
                returncode=0,
            )
        elif cmd[0] == "webanalyze":
            return SimpleNamespace(stdout='{"WordPress": {"version": "5.8"}}\n', returncode=0)
        return SimpleNamespace(stdout='{}', returncode=0)

    monkeypatch.setattr("modules.technology.subprocess.run", fake_run)

    results = discover_technologies(["example.com"], config)

    assert "Web Server: nginx" in results[0]["technology"]
    assert "WordPress" in results[0]["technology"]
    assert "HTTPX:" in results[0]["technology"]
    assert "Webanalyze:" in results[0]["technology"]
