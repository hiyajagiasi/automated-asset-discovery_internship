from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from modules.technology import discover_technologies


def test_discover_technologies_uses_httpx_headers(tmp_path, monkeypatch):
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    config = {
        "output": {"technologies": str(output_dir / "technologies.txt")},
        "tools": {"httpx": "httpx"},
        "timeouts": {"httpx": 10},
    }

    def fake_run(cmd, capture_output, text, timeout):
        assert cmd[0] == "httpx"
        assert "-silent" in cmd
        assert "-json" in cmd
        assert "-tech-detect" in cmd
        assert cmd[-1] == "https://example.com"
        return SimpleNamespace(
            stdout='{"url": "https://example.com", "headers": {"server": "nginx", "x-powered-by": "PHP"}}',
            returncode=0,
        )

    monkeypatch.setattr("modules.technology.subprocess.run", fake_run)

    results = discover_technologies(["example.com"], config)

    assert results[0]["technology"] == "server: nginx | x-powered-by: PHP"
