from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from modules.subdomain import discover_subdomains
from modules.utils import load_config, validate_domain


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
    assert "example.com" in result
    assert (tmp_path / "subdomains.txt").exists()


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
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="\n".join([f"sub{i}.google.com" for i in range(3)]), stderr="")

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
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout="\n".join([
                "www.google.com",
                "api.google.com",
                "7vemu5qa3ozmoictkk4wd5m5tkv5ztmwqbf2wvte4pkvriklc66q.mx-verification.google.com",
            ]),
            stderr="",
        )

    monkeypatch.setattr("modules.subdomain.shutil.which", lambda _: "/usr/bin/subfinder")
    monkeypatch.setattr("modules.subdomain.subprocess.run", fake_run)

    result = discover_subdomains("google.com", config)

    assert "www.google.com" in result
    assert "api.google.com" in result
    assert "7vemu5qa3ozmoictkk4wd5m5tkv5ztmwqbf2wvte4pkvriklc66q.mx-verification.google.com" not in result
