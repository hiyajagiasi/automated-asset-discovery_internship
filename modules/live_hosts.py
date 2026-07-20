from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any


def _parse_httpx_output(stdout: str, seen: set[str]) -> list[str]:
    hosts: list[str] = []
    for line in [entry.strip() for entry in stdout.splitlines() if entry.strip()]:
        try:
            import json

            payload = json.loads(line)
            if payload.get("failed") is True:
                continue
            status_code = payload.get("status_code")
            if isinstance(status_code, int) and status_code >= 400:
                continue
            host = payload.get("url") or payload.get("host")
            if host and host not in seen:
                seen.add(host)
                hosts.append(host)
        except json.JSONDecodeError:
            if line.startswith("http") and line not in seen:
                seen.add(line)
                hosts.append(line)
    return hosts


def discover_live_hosts(subdomains: list[str], config: dict[str, Any]) -> list[str]:
    output_path = Path(config.get("output", {}).get("live_hosts", "output/live_hosts.txt"))
    output_path.parent.mkdir(parents=True, exist_ok=True)

    httpx_bin = config.get("tools", {}).get("httpx", "httpx")
    timeout = int(config.get("timeouts", {}).get("httpx", 60))
    cleaned_subdomains = [subdomain.strip() for subdomain in subdomains if subdomain and subdomain.strip()]

    env = os.environ.copy()
    local_bin = Path(__file__).resolve().parents[1] / ".bin"
    env["PATH"] = str(local_bin) + os.pathsep + env.get("PATH", "")

    try:
        executable = shutil.which(httpx_bin, path=env.get("PATH", ""))
    except TypeError:
        executable = shutil.which(httpx_bin)

    probe_subdomains = cleaned_subdomains

    if executable and probe_subdomains:
        hosts: list[str] = []
        seen: set[str] = set()
        # Run all probe candidates in a single httpx invocation by default
        # to avoid sequential batching delays. Use the configured timeout
        # (with a sensible minimum) so subprocess timeout reflects user config.
        batch_size = 1000
        print(f"[DEBUG] Batch size: {batch_size}")
        per_batch_timeout = 10
        print(f"[DEBUG] Total subdomains: {len(cleaned_subdomains)}")
        print(f"[DEBUG] Probing: {len(probe_subdomains)}")
        print(f"[DEBUG] Batch size: {batch_size if 'batch_size' in locals() else 'Not set yet'}")
        for start in range(0, len(probe_subdomains), batch_size):
            batch = probe_subdomains[start:start + batch_size]
            print(
            f"[DEBUG] Processing batch {start // batch_size + 1} "
            f"({start + 1}-{min(start + batch_size, len(probe_subdomains))})"
            )
            try:
                result = subprocess.run(
                    [
        executable,
        "-json",
        "-silent",
        "-threads",
        "100",
        "-timeout",
        str(per_batch_timeout),
    ],
                    input="\n".join(batch) + "\n",
                    capture_output=True,
                    text=True,
                    timeout=per_batch_timeout + 5,
                    check=False,
                    env=env,
                )
                if result.returncode == 0:
                    print(f"[DEBUG] httpx returned {result.returncode}")
                    print(f"[DEBUG] stdout lines: {len(result.stdout.splitlines())}")
                    hosts.extend(_parse_httpx_output(result.stdout, seen))
                else:
                    hosts.extend(_parse_httpx_output(result.stderr, seen))
            except KeyboardInterrupt:
                break
            except subprocess.TimeoutExpired as exc:
                partial_stdout = getattr(exc, "stdout", None) or ""
                if isinstance(partial_stdout, bytes):
                    partial_stdout = partial_stdout.decode("utf-8", errors="ignore")
                hosts.extend(_parse_httpx_output(partial_stdout, seen))
            except OSError:
                continue

        if hosts:
            print(f"[DEBUG] Total live hosts found: {len(hosts)}")
            output_path.write_text("\n".join(hosts) + "\n", encoding="utf-8")
            return hosts

    hosts = [subdomain for subdomain in probe_subdomains if subdomain]
    output_path.write_text("\n".join(hosts) + "\n", encoding="utf-8")
    return hosts
