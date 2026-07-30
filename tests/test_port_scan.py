from __future__ import annotations

import subprocess
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from modules.port_scan import _build_service_summary, scan_ports


def assert_port_result(result, host, port, service):
    assert len(result) == 1
    assert result[0]["host"] == host
    assert result[0]["port"] == port
    assert result[0]["service"] == service


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

    assert_port_result(result, "example.com", "443", "https")
    assert (tmp_path / "ports.txt").exists()
    assert (tmp_path / "ports.txt").read_text(encoding="utf-8").strip() == "example.com:443 (https)"


def test_scan_ports_retries_transient_naabu_failures(monkeypatch, tmp_path):
    config = {
        "output": {"ports": str(tmp_path / "ports.txt")},
        "tools": {"naabu": "naabu", "nmap": "nmap"},
        "timeouts": {"naabu": 10, "nmap": 10},
    }

    attempts = {"naabu": 0}

    def fake_run(cmd, **kwargs):
        if cmd[0] == "naabu":
            attempts["naabu"] += 1
            if attempts["naabu"] == 1:
                raise subprocess.TimeoutExpired(cmd, timeout=10)
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=0,
                stdout='[{"host":"example.com","port":443,"service":"https"}]\n',
                stderr="",
            )
        if cmd[0] == "nmap":
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=0,
                stdout='Nmap scan report for example.com\n443/tcp open  https\n',
                stderr="",
            )
        raise AssertionError(f"unexpected command {cmd}")

    monkeypatch.setattr("modules.port_scan.shutil.which", lambda *args, **kwargs: "/usr/bin/naabu")
    monkeypatch.setattr("modules.port_scan.subprocess.run", fake_run)
    monkeypatch.setattr("modules.port_scan.time.sleep", lambda *_args, **_kwargs: None)

    result = scan_ports(["https://example.com"], config)

    assert_port_result(result, "example.com", "443", "https")
    assert attempts["naabu"] == 2


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


def test_scan_ports_uses_targeted_nmap_profile_for_live_hosts(monkeypatch, tmp_path):
    config = {
        "output": {"ports": str(tmp_path / "ports.txt")},
        "tools": {"naabu": "naabu", "nmap": "nmap"},
        "timeouts": {"naabu": 10, "nmap": 10},
    }
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        if "naabu" in cmd[0]:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout='[{"host":"example.com","port":443,"service":"https"}]\n', stderr="")
        if "nmap" in cmd[0]:
            assert "-A" not in cmd
            assert "-O" not in cmd
            assert "-sV" in cmd
            assert "-sC" in cmd
            assert "--version-all" in cmd
            assert cmd[cmd.index("--script") + 1] == "default,safe,version,discovery,ssl-cert,ssl-enum-ciphers,http-title,http-headers,http-server-header,http-enum"
            assert "-oX" in cmd
            assert cmd[cmd.index("-p") + 1] == "443"
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout='Nmap scan report for example.com\n443/tcp open  https\n', stderr="")
        raise AssertionError(f"unexpected command {cmd}")

    monkeypatch.setattr("modules.port_scan.shutil.which", lambda *args, **kwargs: "/usr/bin/naabu")
    monkeypatch.setattr("modules.port_scan.subprocess.run", fake_run)

    scan_ports(["https://example.com"], config)

    assert "-p-" not in captured["cmd"]


def test_scan_ports_uses_full_nmap_port_scan_by_default(monkeypatch, tmp_path):
    config = {
        "output": {"ports": str(tmp_path / "ports.txt")},
        "tools": {"naabu": "naabu", "nmap": "nmap"},
        "timeouts": {"naabu": 10, "nmap": 10},
    }
    captured = {}

    def fake_run(cmd, **kwargs):
        if cmd[0] == "naabu":
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout='[{"host":"example.com","port":443,"service":"https"}]\n', stderr="")
        if cmd[0] == "nmap":
            captured["cmd"] = cmd
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout='Nmap scan report for example.com\n443/tcp open  https\n', stderr="")
        raise AssertionError(f"unexpected command {cmd}")

    def fake_which(cmd, *args, **kwargs):
        if cmd == "naabu":
            return "/usr/bin/naabu"
        if cmd == "nmap":
            return "/usr/bin/nmap"
        return None

    monkeypatch.setattr("modules.port_scan.shutil.which", fake_which)
    monkeypatch.setattr("modules.port_scan.subprocess.run", fake_run)

    scan_ports(["https://example.com"], config)

    assert "-p-" not in captured["cmd"]
    assert "-O" not in captured["cmd"]
    assert "-p" in captured["cmd"]
    assert captured["cmd"][captured["cmd"].index("-p") + 1] == "443"


def test_scan_ports_parses_nmap_output_when_nmap_returns_partial_success(monkeypatch, tmp_path):
    config = {
        "output": {"ports": str(tmp_path / "ports.txt")},
        "tools": {"naabu": "naabu", "nmap": "nmap"},
        "timeouts": {"naabu": 10, "nmap": 10},
    }

    def fake_run(cmd, **kwargs):
        if "naabu" in cmd[0]:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout='[{"host":"example.com","port":443,"service":"https"}]\n', stderr="")
        if "nmap" in cmd[0]:
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=1,
                stdout='Nmap scan report for example.com\n443/tcp open  https\n| http-title: Example Domain\n',
                stderr="",
            )
        raise AssertionError(f"unexpected command {cmd}")

    monkeypatch.setattr("modules.port_scan.shutil.which", lambda *args, **kwargs: "/usr/bin/naabu")
    monkeypatch.setattr("modules.port_scan.subprocess.run", fake_run)

    result = scan_ports(["https://example.com"], config)

    assert_port_result(result, "example.com", "443", "https; http-title: Example Domain")


def test_scan_ports_enriches_web_ports_with_httpx_when_nmap_is_generic(monkeypatch, tmp_path):
    config = {
        "output": {"ports": str(tmp_path / "ports.txt")},
        "tools": {"naabu": "naabu", "nmap": "nmap", "httpx": "httpx"},
        "timeouts": {"naabu": 10, "nmap": 10, "httpx": 10},
    }

    def fake_run(cmd, **kwargs):
        if cmd[0] == "naabu":
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout='[{"host":"example.com","port":443,"service":"https"}]\n', stderr="")
        if cmd[0] == "nmap":
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout='Nmap scan report for example.com\n443/tcp open  ssl/https\n', stderr="")
        if cmd[0] == "httpx":
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout='{"title":"Example","server":"nginx","status_code":200}\n', stderr="")
        raise AssertionError(f"unexpected command {cmd}")

    monkeypatch.setattr("modules.port_scan.shutil.which", lambda *args, **kwargs: "/usr/bin/httpx")
    monkeypatch.setattr("modules.port_scan.subprocess.run", fake_run)

    result = scan_ports(["https://example.com"], config)

    assert_port_result(result, "example.com", "443", "ssl/https; title=Example; server=nginx; status=200")


def test_scan_ports_uses_http_fallback_for_unknown_web_ports(monkeypatch, tmp_path):
    config = {
        "output": {"ports": str(tmp_path / "ports.txt")},
        "tools": {"naabu": "naabu", "nmap": "nmap"},
        "timeouts": {"naabu": 10, "nmap": 10},
    }

    def fake_run(cmd, **kwargs):
        if cmd[0] == "naabu":
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout='[{"host":"example.com","port":80,"service":"unknown"}]\n', stderr="")
        if cmd[0] == "nmap":
            return subprocess.CompletedProcess(args=cmd, returncode=1, stdout='Nmap scan report for example.com\n80/tcp open  unknown\n', stderr="")
        if cmd[0] == "curl":
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout='HTTP/1.1 301 Moved Permanently\r\nServer: nginx\r\nLocation: https://example.com/\r\n', stderr="")
        raise AssertionError(f"unexpected command {cmd}")

    def fake_which(cmd, *args, **kwargs):
        if cmd == "curl":
            return "/usr/bin/curl"
        if cmd == "naabu":
            return "/usr/bin/naabu"
        return None

    monkeypatch.setattr("modules.port_scan.shutil.which", fake_which)
    monkeypatch.setattr("modules.port_scan.subprocess.run", fake_run)

    result = scan_ports(["https://example.com"], config)

    assert len(result) == 1
    assert result[0]["host"] == "example.com"
    assert result[0]["port"] == "80"
    assert result[0]["service"].startswith("http")
    assert "status=301" in result[0]["service"]
    assert "server=nginx" in result[0]["service"]
    assert "redirect=https://example.com/" in result[0]["service"]


def test_build_service_summary_includes_richer_nmap_details():
    item = {
        "service_name": "https",
        "title": "Example",
        "server": "nginx",
        "status": "200",
        "http_headers": {"Location": "https://example.com/"},
        "http_methods": ["GET", "HEAD"],
        "security_headers": {"Strict-Transport-Security": "max-age=31536000"},
        "robots": {"disallow": ["/admin"], "allow": [], "sitemap": ["https://example.com/sitemap.xml"]},
        "cpe": ["cpe:/a:nginx:nginx:1.23"],
        "rpc": {"program": "100000"},
    }

    summary = _build_service_summary(item)

    assert "title=Example" in summary
    assert "server=nginx" in summary
    assert "status=200" in summary
    assert "headers=Location: https://example.com/" in summary
    assert "methods=GET, HEAD" in summary
    assert "security_headers=Strict-Transport-Security: max-age=31536000" in summary
    assert "robots=disallow:/admin; sitemap:https://example.com/sitemap.xml" in summary
    assert "cpe=cpe:/a:nginx:nginx:1.23" in summary
    assert "rpc=program: 100000" in summary


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

    assert_port_result(result, "example.com", "443", "https; ssl-cert: Subject: commonName=example.com; OS: Linux")
