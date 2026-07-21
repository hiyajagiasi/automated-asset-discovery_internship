from __future__ import annotations

import os
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
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
            host = payload.get("url") or payload.get("host") or payload.get("input")
            if host and host not in seen:
                seen.add(host)
                hosts.append(host)
        except json.JSONDecodeError:
            if line.startswith("http") and line not in seen:
                seen.add(line)
                hosts.append(line)
    return hosts


def _process_batch(
    batch_no: int,
    batch: list[str],
    output_path: Path,
    executable: str,
    threads: str,
    timeout: str,
    retries: str,
    env: dict[str, str],
    logger: Any,
) -> tuple[int, list[str]]:
    """Process a single batch and return (batch_no, results)."""
    temp_input = output_path.with_suffix(f".httpx_input.{batch_no}.txt")
    temp_output = output_path.with_suffix(f".httpx_output.{batch_no}.json")
    temp_input.write_text("\n".join(batch) + "\n", encoding="utf-8")

    start_time = time.time()
    hosts: list[str] = []
    seen: set[str] = set()

    try:
        with temp_output.open("w", encoding="utf-8") as outfd:
            # Use GET for probe requests because many hosts do not respond reliably to HEAD.
            cmd = [
                executable,
                "-l",
                str(temp_input),
                "-json",
                "-silent",
                "-method",
                "GET",
                "-threads",
                threads,
                "-timeout",
                timeout,
                "-retries",
                retries,
            ]
            logger.debug("Running httpx batch %d: %s", batch_no, cmd)
            # Protect against the httpx process hanging by also enforcing a subprocess timeout
            proc_timeout = None
            try:
                proc_timeout = int(timeout) + 5
            except Exception:
                proc_timeout = None

            try:
                if proc_timeout:
                    result = subprocess.run(cmd, stdout=outfd, stderr=subprocess.PIPE, check=False, text=True, env=env, timeout=proc_timeout)
                else:
                    result = subprocess.run(cmd, stdout=outfd, stderr=subprocess.PIPE, check=False, text=True, env=env)
            except subprocess.TimeoutExpired as exc:
                logger.debug("httpx batch %d timed out after %s seconds: %s", batch_no, proc_timeout, exc)
                # Represent a timed-out process as a non-zero CompletedProcess so downstream logic can handle it
                result = subprocess.CompletedProcess(args=cmd, returncode=124, stdout="", stderr=str(exc))

        if getattr(result, "stdout", None):
            content = result.stdout
            logger.info("Batch %d: httpx returned %d lines", batch_no, len(content.splitlines()))
            hosts.extend(_parse_httpx_output(content, seen))
        elif temp_output.exists():
            content = temp_output.read_text(encoding="utf-8")
            logger.info("Batch %d: httpx returned %d lines", batch_no, len(content.splitlines()))
            hosts.extend(_parse_httpx_output(content, seen))

        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="ignore") if isinstance(result.stderr, bytes) else str(result.stderr)
            logger.debug("httpx batch %d exited %s: %s", batch_no, result.returncode, stderr)
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt during httpx probe batch %d", batch_no)
    except OSError as exc:
        logger.debug("OSError running httpx batch %d: %s", batch_no, exc)
    finally:
        temp_input.unlink(missing_ok=True)
        temp_output.unlink(missing_ok=True)
        logger.debug("httpx batch %d took %.2f seconds", batch_no, time.time() - start_time)

    return batch_no, hosts


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

    max_candidates = int(config.get("limits", {}).get("max_live_host_candidates", 0))
    if max_candidates > 0:
        probe_subdomains = cleaned_subdomains[:max_candidates]
    else:
        probe_subdomains = cleaned_subdomains

    if executable and probe_subdomains:
        logger = get_logger(config.get("logging", {}).get("file", "logs/scan.log"))
        seen: set[str] = set()

        httpx_opts = config.get("httpx_options", {})
        threads_int = int(httpx_opts.get("threads", 100))
        threads = str(threads_int)
        httpx_timeout_flag = str(int(httpx_opts.get("timeout", timeout)))
        retries = str(int(httpx_opts.get("retries", 1)))
        batch_size = int(httpx_opts.get("batch_size", 5000))
        max_rounds = int(httpx_opts.get("max_rounds", 25))
        effective_batch_size = min(batch_size, max(threads_int * max_rounds, 1000))
        parallel_workers = int(httpx_opts.get("parallel_workers", 3))
        max_total_threads = int(httpx_opts.get("max_total_threads", threads_int * parallel_workers))

        total = len(probe_subdomains)
        batches = []
        batch_no = 0
        for start in range(0, total, effective_batch_size):
            batch_no += 1
            batch = probe_subdomains[start : start + effective_batch_size]
            batches.append((batch_no, batch))

        total_batches = len(batches)
        if parallel_workers > total_batches:
            parallel_workers = total_batches

        if threads_int * parallel_workers > max_total_threads:
            allowed_workers = max_total_threads // threads_int
            parallel_workers = max(1, min(parallel_workers, allowed_workers))
            logger.debug(
                "Adjusted parallel_workers to %d because threads*workers exceeded max_total_threads (%d)",
                parallel_workers,
                max_total_threads,
            )

        logger.debug(
            "Starting httpx probe for %d candidates (requested_batch=%d, effective_batch=%d, threads=%s, timeout=%s, parallel_workers=%s, max_total_threads=%s)",
            total,
            batch_size,
            effective_batch_size,
            threads,
            httpx_timeout_flag,
            parallel_workers,
            max_total_threads,
        )

        all_hosts: list[str] = []
        output_path.unlink(missing_ok=True)
        with ThreadPoolExecutor(max_workers=parallel_workers) as executor:
            futures = [
                executor.submit(_process_batch, batch_no, batch, output_path, executable, threads, httpx_timeout_flag, retries, env, logger)
                for batch_no, batch in batches
            ]

            for future in as_completed(futures):
                try:
                    batch_no, hosts = future.result()
                    new_hosts: list[str] = []
                    for host in hosts:
                        if host not in seen:
                            seen.add(host)
                            all_hosts.append(host)
                            new_hosts.append(host)
                    if new_hosts:
                        # Normalize hosts to ensure scheme and remove accidental duplicates
                        normalized: list[str] = []
                        seen_local: set[str] = set()
                        for h in new_hosts:
                            h = h.strip()
                            if not h:
                                continue
                            if not (h.startswith("http://") or h.startswith("https://")):
                                h = f"https://{h}"
                            if h in seen_local:
                                continue
                            seen_local.add(h)
                            normalized.append(h)

                        if normalized:
                            # Ensure output file ends with a newline before appending
                            if output_path.exists():
                                try:
                                    with output_path.open("rb+") as f:
                                        f.seek(0, os.SEEK_END)
                                        if f.tell() > 0:
                                            f.seek(-1, os.SEEK_END)
                                            last = f.read(1)
                                            if last != b"\n":
                                                f.write(b"\n")
                                except OSError:
                                    # Fall back to simple append if binary mode fails
                                    pass

                            with output_path.open("a", encoding="utf-8") as outfd:
                                outfd.write("\n".join(normalized) + "\n")
                except Exception as exc:
                    logger.error("Error processing batch: %s", exc)

        if all_hosts:
            logger.info("Total live hosts found: %d", len(all_hosts))
            return all_hosts

    hosts = []
    seen_fallback: set[str] = set()
    for subdomain in probe_subdomains:
        if not subdomain:
            continue
        h = subdomain.strip()
        if not (h.startswith("http://") or h.startswith("https://")):
            h = f"https://{h}"
        if h in seen_fallback:
            continue
        seen_fallback.add(h)
        hosts.append(h)

    output_path.write_text("\n".join(hosts) + "\n", encoding="utf-8")
    return hosts
