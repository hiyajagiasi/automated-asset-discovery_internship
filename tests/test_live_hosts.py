import subprocess
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from modules.live_hosts import discover_live_hosts


def test_discover_live_hosts_falls_back_to_input_hosts(monkeypatch, tmp_path):
    config = {
        "output": {"live_hosts": str(tmp_path / "live_hosts.txt")},
        "tools": {"httpx": "httpx"},
        "timeouts": {"httpx": 10},
    }

    monkeypatch.setattr("modules.live_hosts.shutil.which", lambda *args, **kwargs: None)

    result = discover_live_hosts(["example.com"], config)

    assert result == ["https://example.com"]
    assert (tmp_path / "live_hosts.txt").exists()


def test_discover_live_hosts_uses_httpx_json_output(monkeypatch, tmp_path):
    config = {
        "output": {"live_hosts": str(tmp_path / "live_hosts.txt")},
        "tools": {"httpx": "httpx"},
        "timeouts": {"httpx": 10},
    }
    captured = {}

    def fake_run(*args, **kwargs):
        captured["args"] = args[0]
        captured["input"] = kwargs.get("input")
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout='{"url": "https://www.example.com", "status_code": 200, "failed": false}\n{"url": "https://api.example.com", "status_code": 200, "failed": false}\n',
            stderr="",
        )

    monkeypatch.setattr("modules.live_hosts.shutil.which", lambda *args, **kwargs: "/usr/bin/httpx")
    monkeypatch.setattr("modules.live_hosts.subprocess.run", fake_run)

    result = discover_live_hosts(["example.com", "api.example.com"], config)

    assert result == ["https://www.example.com", "https://api.example.com"]
    assert "-json" in captured["args"]
    assert "-method" in captured["args"]
    assert "GET" in captured["args"]


def test_discover_live_hosts_includes_live_hosts_with_error_status(monkeypatch, tmp_path):
    config = {
        "output": {"live_hosts": str(tmp_path / "live_hosts.txt")},
        "tools": {"httpx": "httpx"},
        "timeouts": {"httpx": 10},
    }

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout='{"url": "https://ok.example.com", "status_code": 200, "failed": false}\n{"url": "https://missing.example.com", "status_code": 404, "failed": false}\n',
            stderr="",
        )

    monkeypatch.setattr("modules.live_hosts.shutil.which", lambda *args, **kwargs: "/usr/bin/httpx")
    monkeypatch.setattr("modules.live_hosts.subprocess.run", fake_run)

    result = discover_live_hosts(["ok.example.com", "missing.example.com"], config)

    assert result == ["https://ok.example.com", "https://missing.example.com"]
