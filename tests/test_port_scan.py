from __future__ import annotations

import subprocess
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from modules.port_scan import scan_ports


def test_scan_ports_uses_naabu_and_nmap_output(monkeypatch, tmp_path):
    config = {
        "output": {"ports": str(tmp_path / "ports.txt")},
        "tools": {"naabu": "naabu", "nmap": "nmap"},
        "timeouts": {"naabu": 10, "nmap": 10},
    }

    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        if "naabu" in cmd[0]:
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=0,
                stdout='[{"host":"example.com","port":443,"service":"https"}]\n',
                stderr="",
            )
        if "nmap" in cmd[0]:
            assert "-sC" in cmd
            assert "--version-all" in cmd
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=0,
                stdout='Nmap scan report for example.com\n443/tcp open  https\n',
                stderr="",
            )
        raise AssertionError(f"unexpected command {cmd}")

    monkeypatch.setattr("modules.port_scan.shutil.which", lambda *args, **kwargs: "/usr/bin/naabu")
    monkeypatch.setattr("modules.port_scan.subprocess.run", fake_run)

    result = scan_ports(["https://example.com"], config)

    assert result == [
        {"host": "example.com", "port": "443", "service": "https"}
    ]
    assert (tmp_path / "ports.txt").exists()
    assert "example.com:443" in (tmp_path / "ports.txt").read_text(encoding="utf-8")


def test_scan_ports_chunks_large_host_lists_for_naabu(monkeypatch, tmp_path):
    config = {
        "output": {"ports": str(tmp_path / "ports.txt")},
        "tools": {"naabu": "naabu", "nmap": "nmap"},
        "timeouts": {"naabu": 10, "nmap": 10},
    }

    seen_inputs = []

    def fake_run(cmd, **kwargs):
        if "naabu" in cmd[0]:
            seen_inputs.append(cmd[2])
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=0,
                stdout='[{"host":"example.com","port":443,"service":"https"}]\n',
                stderr="",
            )
        if "nmap" in cmd[0]:
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=0,
                stdout='Nmap scan report for example.com\n443/tcp open  https\n',
                stderr="",
            )
        raise AssertionError(f"unexpected command {cmd}")

    monkeypatch.setattr("modules.port_scan.shutil.which", lambda *args, **kwargs: "/usr/bin/naabu")
    monkeypatch.setattr("modules.port_scan.subprocess.run", fake_run)

    hosts = [f"host{i}.example.com" for i in range(250)]
    scan_ports(hosts, config)

    assert len(seen_inputs) > 1
    assert all(len(seen_input.splitlines()) <= 100 for seen_input in seen_inputs)


def test_scan_ports_falls_back_to_service_names_when_nmap_fails(monkeypatch, tmp_path):
    config = {
        "output": {"ports": str(tmp_path / "ports.txt")},
        "tools": {"naabu": "naabu", "nmap": "nmap"},
        "timeouts": {"naabu": 10, "nmap": 10},
    }

    def fake_run(cmd, **kwargs):
        if "naabu" in cmd[0]:
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=0,
                stdout='[{"host":"example.com","port":443,"service":"https"}]\n',
                stderr="",
            )
        if "nmap" in cmd[0]:
            return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="")
        raise AssertionError(f"unexpected command {cmd}")

    monkeypatch.setattr("modules.port_scan.shutil.which", lambda *args, **kwargs: "/usr/bin/naabu")
    monkeypatch.setattr("modules.port_scan.subprocess.run", fake_run)

    result = scan_ports(["https://example.com"], config)

    assert result == [{"host": "example.com", "port": "443", "service": "https"}]


def test_scan_ports_includes_nmap_script_and_host_info(monkeypatch, tmp_path):
    config = {
        "output": {"ports": str(tmp_path / "ports.txt")},
        "tools": {"naabu": "naabu", "nmap": "nmap"},
        "timeouts": {"naabu": 10, "nmap": 10},
    }

    def fake_run(cmd, **kwargs):
        if "naabu" in cmd[0]:
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=0,
                stdout='[{"host":"example.com","port":443,"service":"https"}]\n',
                stderr="",
            )
        if "nmap" in cmd[0]:
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=0,
                stdout=(
                    'Nmap scan report for example.com\n'
                    '443/tcp open  https\n'
                    '| ssl-cert: Subject: commonName=example.com\n'
                    'Service Info: OS: Linux\n'
                ),
                stderr="",
            )
        raise AssertionError(f"unexpected command {cmd}")

    monkeypatch.setattr("modules.port_scan.shutil.which", lambda *args, **kwargs: "/usr/bin/naabu")
    monkeypatch.setattr("modules.port_scan.subprocess.run", fake_run)

    result = scan_ports(["https://example.com"], config)

    assert result == [
        {
            "host": "example.com",
            "port": "443",
            "service": "https; ssl-cert: Subject: commonName=example.com; OS: Linux",
        }
    ]
