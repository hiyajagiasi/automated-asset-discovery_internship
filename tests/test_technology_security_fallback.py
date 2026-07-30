from pathlib import Path
import sys
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from modules.security import discover_security_findings
from modules.technology import discover_technologies


def test_discover_technologies_falls_back_to_live_hosts_output(tmp_path, monkeypatch):
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    live_hosts_file = output_dir / "live_hosts.txt"
    live_hosts_file.write_text("example.com\napi.example.com\n", encoding="utf-8")

    config = {
        "output": {
            "technologies": str(output_dir / "technologies.txt"),
            "live_hosts": str(live_hosts_file),
        },
        "tools": {"httpx": "httpx", "webanalyze": "webanalyze"},
        "timeouts": {"httpx": 10, "webanalyze": 10},
    }

    calls = []

    def fake_run(cmd, capture_output, text, timeout, **kwargs):
        calls.append(cmd)
        if cmd[0] == "httpx":
            host = cmd[-1]
            return SimpleNamespace(stdout='{"headers": {"server": "nginx"}}', returncode=0)
        return SimpleNamespace(stdout='{}', returncode=0)

    monkeypatch.setattr("modules.technology.subprocess.run", fake_run)

    results = discover_technologies([], config)

    assert [item["host"] for item in results] == ["example.com", "api.example.com"]
    assert len(calls) == 4
    assert any("https://example.com" in cmd for cmd in calls if cmd[0] == "httpx")
    assert any("https://api.example.com" in cmd for cmd in calls if cmd[0] == "httpx")


def test_discover_security_findings_falls_back_to_live_hosts_output(tmp_path, monkeypatch):
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    live_hosts_file = output_dir / "live_hosts.txt"
    live_hosts_file.write_text("example.com\n", encoding="utf-8")

    config = {
        "output": {
            "security": str(output_dir / "security.txt"),
            "live_hosts": str(live_hosts_file),
        },
        "tools": {"nikto": "nikto"},
        "timeouts": {"nikto": 10},
    }

    def fake_which(*args, **kwargs):
        return "/usr/bin/nikto"

    def fake_run(cmd, capture_output, text, timeout, env=None, **kwargs):
        assert cmd[13] == "-host"
        assert cmd[14] == "https://example.com"
        return SimpleNamespace(stdout="+ 1234 Test finding\n", returncode=0, stderr="")

    monkeypatch.setattr("modules.security.shutil.which", fake_which)
    monkeypatch.setattr("modules.security.subprocess.run", fake_run)

    findings = discover_security_findings([], config)

    assert len(findings) == 1
    assert findings[0]["host"] == "example.com"
