import subprocess
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from modules.live_hosts import _dnsx_resolve_candidates, discover_live_hosts
from modules.utils import load_config


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
    assert "-rate-limit" in captured["args"]
    assert "-stream" in captured["args"]
    assert "-response-size-to-read" in captured["args"]
    assert "-no-decode" in captured["args"]


def test_discover_live_hosts_uses_explicit_process_timeout(monkeypatch, tmp_path):
    config = {
        "output": {"live_hosts": str(tmp_path / "live_hosts.txt")},
        "tools": {"httpx": "httpx"},
        "timeouts": {"httpx": 10},
        "httpx_options": {"threads": 2, "timeout": 10, "retries": 1, "batch_size": 3, "process_timeout": 55},
    }
    captured = {}

    def fake_run(*args, **kwargs):
        captured["timeout"] = kwargs["timeout"]
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="", stderr="")

    monkeypatch.setattr("modules.live_hosts.shutil.which", lambda *args, **kwargs: "/usr/bin/httpx")
    monkeypatch.setattr("modules.live_hosts.subprocess.run", fake_run)

    discover_live_hosts(["one.example", "two.example", "three.example"], config)

    assert captured["timeout"] == 55


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


def test_dnsx_filters_http_probe_candidates(monkeypatch, tmp_path):
    config = {
        "tools": {"dnsx": "dnsx"},
        "dnsx_options": {"enabled": True, "threads": 10, "retries": 1, "timeout": 2},
    }
    captured = {}

    def fake_run(*args, **kwargs):
        captured["args"] = args[0]
        output_path = Path(args[0][args[0].index("-o") + 1])
        output_path.write_text("alive.example.com\n", encoding="utf-8")
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="", stderr="")

    monkeypatch.setattr("modules.live_hosts.shutil.which", lambda *args, **kwargs: "/usr/bin/dnsx")
    monkeypatch.setattr("modules.live_hosts.subprocess.run", fake_run)

    result = _dnsx_resolve_candidates(
        ["alive.example.com", "unresolved.example.com"],
        config,
        {},
        tmp_path / "live_hosts.txt",
        type("Logger", (), {"info": lambda *args: None, "warning": lambda *args: None})(),
    )

    assert result == ["alive.example.com"]
    assert "-stream" not in captured["args"]


def test_dnsx_falls_back_when_unavailable(monkeypatch, tmp_path):
    config = {"dnsx_options": {"enabled": True}}
    candidates = ["one.example.com"]
    monkeypatch.setattr("modules.live_hosts.shutil.which", lambda *args, **kwargs: None)

    result = _dnsx_resolve_candidates(
        candidates,
        config,
        {},
        tmp_path / "live_hosts.txt",
        type("Logger", (), {"info": lambda *args: None, "warning": lambda *args: None})(),
    )

    assert result == candidates


def test_load_config_uses_conservative_httpx_defaults(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("timeouts:\n  httpx: 15\n", encoding="utf-8")

    config = load_config(config_path)

    httpx_opts = config["httpx_options"]

    assert httpx_opts["threads"] == 100
    assert httpx_opts["timeout"] == 15
    assert httpx_opts["retries"] == 3
    assert httpx_opts["parallel_workers"] == 2
    assert httpx_opts["max_total_threads"] == 200
