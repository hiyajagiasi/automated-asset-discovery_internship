from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from modules.live_hosts import discover_live_hosts


def test_discover_live_hosts_falls_back_to_input_hosts(tmp_path):
    config = {
        "output": {"live_hosts": str(tmp_path / "live_hosts.txt")},
        "tools": {"httpx": "httpx"},
        "timeouts": {"httpx": 10},
    }

    result = discover_live_hosts(["example.com"], config)

    assert result == ["example.com"]
    assert (tmp_path / "live_hosts.txt").exists()
