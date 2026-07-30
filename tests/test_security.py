from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from modules.security import discover_security_findings


def test_discover_security_findings_parses_nikto_text_output(tmp_path, monkeypatch):
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    config = {
        "output": {"security": str(output_dir / "security.txt")},
        "tools": {"nikto": "nikto"},
        "timeouts": {"nikto": 15},
    }

    def fake_run(cmd, capture_output, text, timeout, **kwargs):
        assert cmd[0].endswith("nikto")
        assert cmd[1] == "-nointeractive"
        assert cmd[2] == "-nocheck"
        assert cmd[3] == "-maxtime"
        assert cmd[4] == "8s"
        assert cmd[5] == "-Tuning"
        assert cmd[6] == "3,4,5"
        assert cmd[7] == "-Plugins"
        assert cmd[8] == "httpmethods,headers,serverinfo"
        assert cmd[9] == "-Format"
        assert cmd[10] == "txt"
        assert cmd[11] == "-output"
        assert cmd[12].endswith(".txt")
        assert cmd[13] == "-host"
        assert cmd[14] == "https://example.com"
        assert timeout == 15
        output_file = Path(cmd[12])
        output_file.write_text("+ 1234 Test finding\n", encoding="utf-8")
        return SimpleNamespace(stdout="", returncode=0, stderr="")

    monkeypatch.setattr("modules.security.shutil.which", lambda *args, **kwargs: "/usr/bin/nikto")
    monkeypatch.setattr("modules.security.subprocess.run", fake_run)

    findings = discover_security_findings(["example.com"], config)

    assert len(findings) == 1
    assert findings[0]["host"] == "example.com"
    assert findings[0]["severity"] == "medium"
    assert findings[0]["name"] == "Test finding"
    assert findings[0]["template_id"] == "nikto-1234"
    assert (output_dir / "security.txt").exists()


def test_discover_security_findings_skips_nikto_summary_lines(tmp_path, monkeypatch):
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    config = {
        "output": {"security": str(output_dir / "security.txt")},
        "tools": {"nikto": "nikto"},
        "timeouts": {"nikto": 10},
    }

    def fake_run(cmd, capture_output, text, timeout, env=None, **kwargs):
        output_file = Path(cmd[cmd.index("-output") + 1])
        output_file.write_text(
            "+ Target IP:          1.2.3.4\n"
            "+ 11 requests: 0 errors and 0 items reported on the remote host\n"
            "+ 1 host(s) tested\n"
            "+ [9999] Real issue detected\n",
            encoding="utf-8",
        )
        return SimpleNamespace(stdout="", returncode=0, stderr="")

    monkeypatch.setattr("modules.security.shutil.which", lambda *args, **kwargs: "/usr/bin/nikto")
    monkeypatch.setattr("modules.security.subprocess.run", fake_run)

    findings = discover_security_findings(["example.com"], config)

    assert len(findings) == 1
    assert findings[0]["template_id"] == "nikto-9999"
    assert findings[0]["name"] == "Real issue detected"


def test_discover_security_findings_deduplicates_duplicate_findings(tmp_path, monkeypatch):
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    config = {
        "output": {"security": str(output_dir / "security.txt")},
        "tools": {"nikto": "nikto"},
        "timeouts": {"nikto": 10},
    }

    def fake_run(cmd, capture_output, text, timeout, env=None, **kwargs):
        output_file = Path(cmd[cmd.index("-output") + 1])
        output_file.write_text(
            "+ 1234 Duplicate finding\n"
            "+ 1234 Duplicate finding\n",
            encoding="utf-8",
        )
        return SimpleNamespace(stdout="", returncode=0, stderr="")

    monkeypatch.setattr("modules.security.shutil.which", lambda *args, **kwargs: "/usr/bin/nikto")
    monkeypatch.setattr("modules.security.subprocess.run", fake_run)

    findings = discover_security_findings(["example.com"], config)

    assert len(findings) == 1


def test_discover_security_findings_uses_nikto_output_file(tmp_path, monkeypatch):
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    config = {
        "output": {"security": str(output_dir / "security.txt")},
        "tools": {"nikto": "nikto"},
        "timeouts": {"nikto": 10},
    }

    def fake_run(cmd, capture_output, text, timeout, env=None, **kwargs):
        output_file = Path(cmd[cmd.index("-output") + 1])
        output_file.write_text("+ 9999 Test\n", encoding="utf-8")
        return SimpleNamespace(stdout="", returncode=0, stderr="")

    monkeypatch.setattr("modules.security.shutil.which", lambda *args, **kwargs: "/usr/bin/nikto")
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
        "tools": {"nikto": "nikto"},
        "timeouts": {"nikto": 10},
    }

    monkeypatch.setattr("modules.security.shutil.which", lambda *args, **kwargs: None)

    findings = discover_security_findings(["example.com"], config)

    assert findings == []
    assert (output_dir / "security.txt").exists()
