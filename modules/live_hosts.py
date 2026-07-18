from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any


def discover_live_hosts(subdomains: list[str], config: dict[str, Any]) -> list[str]:
    output_path = Path(config.get("output", {}).get("live_hosts", "output/live_hosts.txt"))
    output_path.parent.mkdir(parents=True, exist_ok=True)

    httpx_bin = config.get("tools", {}).get("httpx", "httpx")
    timeout = int(config.get("timeouts", {}).get("httpx", 60))

    if shutil.which(httpx_bin):
        try:
            result = subprocess.run(
                [httpx_bin, "-l", "-json"] + subdomains,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            if result.returncode == 0:
                lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
                hosts = []
                for line in lines:
                    try:
                        import json

                        payload = json.loads(line)
                        host = payload.get("url") or payload.get("host")
                        if host:
                            hosts.append(host)
                    except json.JSONDecodeError:
                        if line.startswith("http"):
                            hosts.append(line)
                if hosts:
                    output_path.write_text("\n".join(hosts) + "\n", encoding="utf-8")
                    return hosts
        except (subprocess.TimeoutExpired, OSError):
            pass

    hosts = [subdomain for subdomain in subdomains if subdomain]
    output_path.write_text("\n".join(hosts) + "\n", encoding="utf-8")
    return hosts
