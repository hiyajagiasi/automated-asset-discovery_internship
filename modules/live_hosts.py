from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from modules.utils import get_logger


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

    # limit and batching
    probe_subdomains = cleaned_subdomains

    if executable and probe_subdomains:
        logger = get_logger(config.get("logging", {}).get("file", "logs/scan.log"))
        hosts: list[str] = []
        seen: set[str] = set()

        # Read httpx options from config with sensible fallbacks
        httpx_opts = config.get("httpx_options", {})
        threads = str(int(httpx_opts.get("threads", 100)))
        httpx_timeout_flag = str(int(httpx_opts.get("timeout", 10)))
        retries = str(int(httpx_opts.get("retries", 1)))
        batch_size = int(httpx_opts.get("batch_size", 5000))

        total = len(probe_subdomains)
        logger.debug("Starting httpx probe for %d candidates (batch_size=%d, threads=%s, timeout=%s)", total, batch_size, threads, httpx_timeout_flag)

        batch_no = 0
        for start in range(0, total, batch_size):
            batch_no += 1
            batch = probe_subdomains[start:start + batch_size]
            temp_input = output_path.with_suffix(f".httpx_input.{batch_no}.txt")
            temp_output = output_path.with_suffix(f".httpx_output.{batch_no}.json")
            temp_input.write_text("\n".join(batch) + "\n", encoding="utf-8")

            start_time = time.time()
            try:
                temp_input_content = "\n".join(batch) + "\n"
                with temp_output.open("w", encoding="utf-8") as outfd:
                    cmd = [
                        executable,
                        "-l",
                        str(temp_input),
                        "-json",
                        "-silent",
                        "-threads",
                        threads,
                        "-timeout",
                        httpx_timeout_flag,
                        "-retries",
                        retries,
                    ]
                    logger.debug("Running httpx batch %d: %s", batch_no, cmd)
                    result = subprocess.run(cmd, stdout=outfd, stderr=subprocess.PIPE, check=False, text=True, env=env)

                # prefer stdout from the subprocess (used by tests/mocks); fall back to file
                if getattr(result, "stdout", None):
                    content = result.stdout
                    hosts.extend(_parse_httpx_output(content, seen))
                elif temp_output.exists():
                    content = temp_output.read_text(encoding="utf-8")
                    logger.info(
                    "Batch %d: httpx returned %d lines",
                    batch_no,
                    len(content.splitlines()),
                    )
                    hosts.extend(_parse_httpx_output(content, seen))

                if result.returncode != 0:
                    stderr = result.stderr.decode("utf-8", errors="ignore") if isinstance(result.stderr, bytes) else str(result.stderr)
                    logger.debug("httpx batch %d exited %s: %s", batch_no, result.returncode, stderr)
            except KeyboardInterrupt:
                logger.info("KeyboardInterrupt during httpx probe")
                break
            except OSError as exc:
                logger.debug("OSError running httpx batch %d: %s", batch_no, exc)
                continue
            finally:
                temp_input.unlink(missing_ok=True)
                temp_output.unlink(missing_ok=True)
                logger.debug("httpx batch %d took %.2f seconds", batch_no, time.time() - start_time)

        if hosts:
            logger.info("Total live hosts found: %d", len(hosts))
            output_path.write_text("\n".join(hosts) + "\n", encoding="utf-8")
            return hosts

    hosts = [subdomain for subdomain in probe_subdomains if subdomain]
    output_path.write_text("\n".join(hosts) + "\n", encoding="utf-8")
    return hosts
