from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from modules.subdomain import discover_subdomains
from modules.utils import load_config, validate_domain


def _write_mock_subfinder_output(command, content):
    output_path = None
    for index, item in enumerate(command):
        if item == "-o" and index + 1 < len(command):
            output_path = command[index + 1]
            break
    if output_path is not None:
        Path(output_path).write_text(content, encoding="utf-8")


def test_validate_domain_accepts_url():
    assert validate_domain("https://google.com") == "google.com"
    assert validate_domain("http://linkedin.in/path") == "linkedin.in"


def test_discover_subdomains_prefers_subfinder_results(tmp_path, monkeypatch):
    config = {
        "output": {"subdomains": str(tmp_path / "subdomains.txt")},
        "tools": {"subfinder": "subfinder"},
        "timeouts": {"subfinder": 10},
    }

    def fake_run(*args, **kwargs):
        _write_mock_subfinder_output(args[0], "www.google.com\napi.google.com\n")
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="www.google.com\napi.google.com\n", stderr="")

    monkeypatch.setattr("modules.subdomain.shutil.which", lambda _: "/usr/bin/subfinder")
    monkeypatch.setattr("modules.subdomain.subprocess.run", fake_run)

    result = discover_subdomains("google.com", config)

    assert result == ["www.google.com", "api.google.com"]


def test_discover_subdomains_uses_reliable_subfinder_flags(monkeypatch, tmp_path):
    config = {
        "output": {"subdomains": str(tmp_path / "subdomains.txt")},
        "tools": {"subfinder": "subfinder"},
        "timeouts": {"subfinder": 10},
    }
    captured = {}

    def fake_run(*args, **kwargs):
        captured["args"] = args[0]
        _write_mock_subfinder_output(args[0], "www.google.com\n")
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="www.google.com\n", stderr="")

    monkeypatch.setattr("modules.subdomain.shutil.which", lambda _: "/usr/bin/subfinder")
    monkeypatch.setattr("modules.subdomain.subprocess.run", fake_run)

    result = discover_subdomains("google.com", config)

    assert result == ["www.google.com"]
    assert "-disable-update-check" in captured["args"]
    assert "-timeout" in captured["args"]
    assert "-all" in captured["args"]


def test_discover_subdomains_uses_subfinder_output_file(monkeypatch, tmp_path):
    config = {
        "output": {"subdomains": str(tmp_path / "subdomains.txt")},
        "tools": {"subfinder": "subfinder"},
        "timeouts": {"subfinder": 10},
    }
    captured = {}

    def fake_run(*args, **kwargs):
        command = args[0]
        _write_mock_subfinder_output(command, "www.google.com\napi.google.com\n")
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="www.google.com\napi.google.com\n", stderr="")

    monkeypatch.setattr("modules.subdomain.shutil.which", lambda _: "/usr/bin/subfinder")
    monkeypatch.setattr("modules.subdomain.subprocess.run", fake_run)

    result = discover_subdomains("google.com", config)

    assert result == ["www.google.com", "api.google.com"]


def test_discover_subdomains_falls_back_to_target(tmp_path):
    config = {
        "output": {"subdomains": str(tmp_path / "subdomains.txt")},
        "tools": {"subfinder": "subfinder"},
        "timeouts": {"subfinder": 10},
    }

    result = discover_subdomains("example.com", config)

    assert result
    assert any(item.endswith("example.com") for item in result)
    assert (tmp_path / "subdomains.txt").exists()


def test_discover_subdomains_uses_configured_timeout_without_retry(monkeypatch, tmp_path):
    config = {
        "output": {"subdomains": str(tmp_path / "subdomains.txt")},
        "tools": {"subfinder": "subfinder"},
        "timeouts": {"subfinder": 10},
    }
    calls = []

    def fake_run(*args, **kwargs):
        calls.append(kwargs["timeout"])
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

    monkeypatch.setattr("modules.subdomain.shutil.which", lambda _: "/usr/bin/subfinder")
    monkeypatch.setattr("modules.subdomain.subprocess.run", fake_run)

    result = discover_subdomains("example.com", config)

    assert calls == [30]
    assert "example.com" in result


def test_discover_subdomains_uses_partial_output_on_timeout(monkeypatch, tmp_path):
    config = {
        "output": {"subdomains": str(tmp_path / "subdomains.txt")},
        "tools": {"subfinder": "subfinder"},
        "timeouts": {"subfinder": 10},
    }

    def fake_run(*args, **kwargs):
        _write_mock_subfinder_output(args[0], "www.example.com\napi.example.com\n")
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"], output="www.example.com\napi.example.com\n")

    monkeypatch.setattr("modules.subdomain.shutil.which", lambda _: "/usr/bin/subfinder")
    monkeypatch.setattr("modules.subdomain.subprocess.run", fake_run)

    result = discover_subdomains("example.com", config)

    assert "www.example.com" in result
    assert "api.example.com" in result


def test_discover_subdomains_uses_stdout_on_timeout(monkeypatch, tmp_path):
    config = {
        "output": {"subdomains": str(tmp_path / "subdomains.txt")},
        "tools": {"subfinder": "subfinder"},
        "timeouts": {"subfinder": 10},
    }

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"], output="www.example.com\napi.example.com\n")

    monkeypatch.setattr("modules.subdomain.shutil.which", lambda _: "/usr/bin/subfinder")
    monkeypatch.setattr("modules.subdomain.subprocess.run", fake_run)

    result = discover_subdomains("example.com", config)

    assert "www.example.com" in result
    assert "api.example.com" in result


def test_load_config_resolves_output_paths_relative_to_config_file(tmp_path):
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    config_path = project_dir / "config.yaml"
    config_path.write_text("output:\n  subdomains: output/subdomains.txt\n", encoding="utf-8")

    config = load_config(config_path)

    resolved_output = Path(config["output"]["subdomains"])
    assert resolved_output.is_absolute()
    assert resolved_output == project_dir / "output" / "subdomains.txt"


def test_discover_subdomains_keeps_plain_subdomains(monkeypatch, tmp_path):
    config = {
        "output": {"subdomains": str(tmp_path / "subdomains.txt")},
        "tools": {"subfinder": "subfinder"},
        "timeouts": {"subfinder": 10},
    }

    def fake_run(*args, **kwargs):
        content = "\n".join([f"sub{i}.google.com" for i in range(3)])
        _write_mock_subfinder_output(args[0], content)
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout=content, stderr="")

    monkeypatch.setattr("modules.subdomain.shutil.which", lambda _: "/usr/bin/subfinder")
    monkeypatch.setattr("modules.subdomain.subprocess.run", fake_run)

    result = discover_subdomains("google.com", config)

    assert "sub0.google.com" in result
    assert "sub2.google.com" in result


def test_discover_subdomains_filters_noisy_random_hosts(monkeypatch, tmp_path):
    config = {
        "output": {"subdomains": str(tmp_path / "subdomains.txt")},
        "tools": {"subfinder": "subfinder"},
        "timeouts": {"subfinder": 10},
    }

    def fake_run(*args, **kwargs):
        content = "\n".join([
            "www.google.com",
            "api.google.com",
            "7vemu5qa3ozmoictkk4wd5m5tkv5ztmwqbf2wvte4pkvriklc66q.mx-verification.google.com",
        ])
        _write_mock_subfinder_output(args[0], content)
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout=content, stderr="")

    monkeypatch.setattr("modules.subdomain.shutil.which", lambda _: "/usr/bin/subfinder")
    monkeypatch.setattr("modules.subdomain.subprocess.run", fake_run)

    result = discover_subdomains("google.com", config)

    assert "www.google.com" in result
    assert "api.google.com" in result
    assert "7vemu5qa3ozmoictkk4wd5m5tkv5ztmwqbf2wvte4pkvriklc66q.mx-verification.google.com" not in result
