from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from modules.security import discover_security_findings


def test_discover_security_findings_parses_nuclei_jsonl_output(tmp_path, monkeypatch):
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    config = {
        "output": {"security": str(output_dir / "security.txt")},
        "tools": {"nuclei": "nuclei"},
        "timeouts": {"nuclei": 15},
    }

    def fake_run(cmd, capture_output, text, timeout, **kwargs):
        assert cmd[0].endswith("nuclei")
        assert cmd[1] == "-list"
        assert "-jsonl" in cmd
        assert "-tags" in cmd and "ssl,dns,http,misconfig,exposure" in cmd
        assert "-severity" in cmd and "info,low,medium" in cmd
        assert "-timeout" in cmd and "10" in cmd
        assert "-c" in cmd and "25" in cmd
        assert "-bulk-size" in cmd and "10" in cmd
        assert "-rate-limit" in cmd and "100" in cmd
        assert timeout == 900
        assert Path(cmd[2]).exists()
        return SimpleNamespace(
            stdout='{"template-id":"cve-test","info":{"name":"Test finding","severity":"high","description":"desc","tags":["cve"]},"matched-at":"https://example.com","extracted-results":["/login"]}\n',
            returncode=0,
            stderr="",
        )

    monkeypatch.setattr("modules.security.shutil.which", lambda *args, **kwargs: "/usr/bin/nuclei")
    monkeypatch.setattr("modules.security.subprocess.run", fake_run)

    findings = discover_security_findings(["example.com"], config)

    assert len(findings) == 1
    assert findings[0]["host"] == "example.com"
    assert findings[0]["severity"] == "high"
    assert findings[0]["name"] == "Test finding"
    assert findings[0]["template_id"] == "cve-test"
    assert (output_dir / "security.txt").exists()


def test_discover_security_findings_sets_writable_nuclei_home(tmp_path, monkeypatch):
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    config = {
        "output": {"security": str(output_dir / "security.txt")},
        "tools": {"nuclei": "nuclei"},
        "timeouts": {"nuclei": 10},
    }

    def fake_run(cmd, capture_output, text, timeout, env=None, **kwargs):
        assert env["HOME"].startswith(str(output_dir))
        assert env["XDG_CONFIG_HOME"].startswith(str(output_dir))
        output_flag_index = cmd.index("-o")
        output_file = Path(cmd[output_flag_index + 1])
        output_file.write_text('{"template-id":"test","info":{"name":"Test","severity":"info"},"host":"example.com"}\n', encoding='utf-8')
        return SimpleNamespace(stdout="", returncode=0, stderr="")

    monkeypatch.setattr("modules.security.shutil.which", lambda *args, **kwargs: "/usr/bin/nuclei")
    monkeypatch.setattr("modules.security.subprocess.run", fake_run)

    findings = discover_security_findings(["example.com"], config)

    assert len(findings) == 1
    assert findings[0]["host"] == "example.com"
    assert (output_dir / "security.txt").exists()


def test_discover_security_findings_returns_empty_when_tool_is_unavailable(tmp_path, monkeypatch):
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    config = {
        "output": {"security": str(output_dir / "security.txt")},
        "tools": {"nuclei": "nuclei"},
        "timeouts": {"nuclei": 10},
    }

    monkeypatch.setattr("modules.security.shutil.which", lambda *args, **kwargs: None)

    findings = discover_security_findings(["example.com"], config)

    assert findings == []
    assert (output_dir / "security.txt").exists()
