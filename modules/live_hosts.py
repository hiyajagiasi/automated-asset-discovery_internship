from __future__ import annotations

import os
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from modules.utils import get_logger


def _dnsx_resolve_candidates(
    candidates: list[str],
    config: dict[str, Any],
    env: dict[str, str],
    output_path: Path,
    logger: Any,
) -> tuple[list[str], list[str]]:
    dnsx_options = config.get("dnsx_options", {})
    if not bool(dnsx_options.get("enabled", False)):
        return candidates, []

    dnsx_bin = config.get("tools", {}).get("dnsx", "dnsx")
    executable = shutil.which(dnsx_bin, path=env.get("PATH", ""))
    if not executable:
        logger.warning("dnsx is enabled but was not found; probing all candidates with httpx")
        return candidates, []

    input_path = output_path.with_suffix(".dnsx_input.txt")
    result_path = output_path.with_suffix(".dnsx_output.txt")
    input_path.write_text("\n".join(candidates) + "\n", encoding="utf-8")
    command = [
        executable, "-l", str(input_path), "-silent", "-no-color", "-a",
        "-threads", str(max(1, int(dnsx_options.get("threads", 500)))),
        "-retry", str(max(1, int(dnsx_options.get("retries", 1)))),
        "-timeout", str(max(1, int(dnsx_options.get("timeout", 2)))),
        "-o", str(result_path),
    ]
    rate_limit = int(dnsx_options.get("rate_limit", 0))
    if rate_limit > 0:
        command.extend(["-rate-limit", str(rate_limit)])

    try:
        logger.info("Starting dnsx resolution for %d candidates", len(candidates))
        result = subprocess.run(command, capture_output=True, text=True, check=False, env=env)
        content = result.stdout or ""
        if result_path.exists():
            content = result_path.read_text(encoding="utf-8")
        candidate_set = set(candidates)
        resolved: list[str] = []
        seen: set[str] = set()
        for line in content.splitlines():
            host = line.strip().split()[0] if line.strip() else ""
            if host in candidate_set and host not in seen:
                seen.add(host)
                resolved.append(host)
        if result.returncode != 0 or not resolved:
            diagnostics = (result.stderr or "").strip()
            logger.warning(
                "dnsx did not return usable results (returncode=%s, stderr=%s); probing all candidates with httpx",
                result.returncode,
                diagnostics or "none",
            )
            return candidates, []
        logger.info("dnsx resolution completed: %d/%d candidates resolved", len(resolved), len(candidates))
        unresolved = [candidate for candidate in candidates if candidate not in resolved]
        return resolved, unresolved
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("dnsx failed (%s); probing all candidates with httpx", exc)
        return candidates, []
    finally:
        input_path.unlink(missing_ok=True)
        result_path.unlink(missing_ok=True)


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


def _normalize_host(host: str) -> str:
    cleaned = host.strip()
    if not cleaned:
        return ""
    if not (cleaned.startswith("http://") or cleaned.startswith("https://")):
        cleaned = f"https://{cleaned}"
    return cleaned


def _write_hosts_file(path: Path, hosts: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()
    unique_hosts: list[str] = []
    for host in hosts:
        normalized = _normalize_host(host)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        unique_hosts.append(normalized)
    if unique_hosts:
        path.write_text("\n".join(unique_hosts) + "\n", encoding="utf-8")
    else:
        path.write_text("", encoding="utf-8")


def _process_batch(
    batch_no: int,
    batch: list[str],
    output_path: Path,
    executable: str,
    threads: str,
    timeout: str,
    retries: str,
    rate_limit: str | None,
    stream: bool,
    response_size_to_read: str | None,
    no_decode: bool,
    process_timeout: int | None,
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
                "-threads",
                threads,
                "-timeout",
                timeout,
                "-retries",
                retries,
            ]
            if rate_limit is not None:
                cmd.extend(["-rate-limit", rate_limit])
            if stream:
                # Avoid input sorting so httpx begins probing immediately.
                cmd.append("-stream")
            if response_size_to_read is not None:
                cmd.extend(["-response-size-to-read", response_size_to_read])
            if no_decode:
                cmd.append("-no-decode")
            logger.debug("Running httpx batch %d: %s", batch_no, cmd)
            try:
                if process_timeout is not None:
                    result = subprocess.run(cmd, stdout=outfd, stderr=subprocess.PIPE, check=False, text=True, env=env, timeout=process_timeout)
                else:
                    result = subprocess.run(cmd, stdout=outfd, stderr=subprocess.PIPE, check=False, text=True, env=env)
            except subprocess.TimeoutExpired as exc:
                logger.warning(
                    "httpx batch %d timed out after %s seconds; its results may be incomplete: %s",
                    batch_no,
                    process_timeout,
                    exc,
                )
                # Represent a timed-out process as a non-zero CompletedProcess so downstream logic can handle it
                result = subprocess.CompletedProcess(args=cmd, returncode=124, stdout="", stderr=str(exc))

        output_line_count = 0
        if getattr(result, "stdout", None):
            content = result.stdout
            output_line_count = len(content.splitlines())
            logger.info("Batch %d: httpx returned %d lines", batch_no, output_line_count)
            hosts.extend(_parse_httpx_output(content, seen))
        elif temp_output.exists():
            content = temp_output.read_text(encoding="utf-8")
            output_line_count = len(content.splitlines())
            logger.info("Batch %d: httpx returned %d lines", batch_no, output_line_count)
            hosts.extend(_parse_httpx_output(content, seen))

        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="ignore") if isinstance(result.stderr, bytes) else str(result.stderr)
            logger.warning("httpx batch %d exited %s: %s", batch_no, result.returncode, stderr.strip() or "no stderr")
        elif output_line_count == 0:
            stderr = result.stderr.decode("utf-8", errors="ignore") if isinstance(result.stderr, bytes) else str(result.stderr)
            logger.info(
                "Batch %d produced no HTTP responses from %d candidates%s",
                batch_no,
                len(batch),
                f"; diagnostic: {stderr.strip()}" if stderr.strip() else "",
            )
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
    dead_output_path = Path(config.get("output", {}).get("dead_hosts", output_path.with_name("dead_host.txt")))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    dead_output_path.parent.mkdir(parents=True, exist_ok=True)

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
        configured_rate_limit = int(httpx_opts.get("rate_limit", 150))
        rate_limit = str(configured_rate_limit) if configured_rate_limit > 0 else None
        stream = bool(httpx_opts.get("stream", True))
        configured_response_size = int(httpx_opts.get("response_size_to_read", 1024))
        response_size_to_read = str(configured_response_size) if configured_response_size >= 0 else None
        no_decode = bool(httpx_opts.get("no_decode", True))
        configured_process_timeout = int(httpx_opts.get("process_timeout", 0))
        process_timeout = configured_process_timeout if configured_process_timeout > 0 else None
        batch_size = int(httpx_opts.get("batch_size", 5000))
        max_rounds = int(httpx_opts.get("max_rounds", 25))
        effective_batch_size = min(batch_size, max(threads_int * max_rounds, 1000))
        parallel_workers = int(httpx_opts.get("parallel_workers", 3))
        max_total_threads = int(httpx_opts.get("max_total_threads", threads_int * parallel_workers))

        resolved_candidates, dnsx_dead_candidates = _dnsx_resolve_candidates(probe_subdomains, config, env, output_path, logger)
        probe_subdomains = resolved_candidates

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

        logger.info(
            "Starting httpx probe for %d candidates (requested_batch=%d, effective_batch=%d, threads=%s, timeout=%s, retries=%s, rate_limit=%s per worker, stream=%s, body_read_limit=%s, process_timeout=%s, parallel_workers=%s, max_total_threads=%s)",
            total,
            batch_size,
            effective_batch_size,
            threads,
            httpx_timeout_flag,
            retries,
            rate_limit if rate_limit is not None else "httpx-default",
            stream,
            response_size_to_read if response_size_to_read is not None else "httpx-default",
            process_timeout if process_timeout is not None else "disabled",
            parallel_workers,
            max_total_threads,
        )

        all_hosts: list[str] = []
        output_path.unlink(missing_ok=True)
        dead_output_path.unlink(missing_ok=True)
        with ThreadPoolExecutor(max_workers=parallel_workers) as executor:
            futures = [
                executor.submit(
                    _process_batch,
                    batch_no,
                    batch,
                    output_path,
                    executable,
                    threads,
                    httpx_timeout_flag,
                    retries,
                    rate_limit,
                    stream,
                    response_size_to_read,
                    no_decode,
                    process_timeout,
                    env,
                    logger,
                )
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
            normalized_live_hosts = [_normalize_host(host) for host in all_hosts if _normalize_host(host)]
            normalized_live_hosts = list(dict.fromkeys(normalized_live_hosts))
            normalized_probe_hosts = [_normalize_host(host) for host in probe_subdomains if _normalize_host(host)]
            normalized_probe_hosts = list(dict.fromkeys(normalized_probe_hosts))
            normalized_dnsx_dead_hosts = [_normalize_host(host) for host in dnsx_dead_candidates if _normalize_host(host)]
            normalized_dnsx_dead_hosts = list(dict.fromkeys(normalized_dnsx_dead_hosts))
            dead_hosts = [
                host for host in normalized_dnsx_dead_hosts + [host for host in normalized_probe_hosts if host not in set(normalized_live_hosts)]
                if host
            ]
            dead_hosts = list(dict.fromkeys(dead_hosts))
            _write_hosts_file(output_path, normalized_live_hosts)
            _write_hosts_file(dead_output_path, dead_hosts)
            logger.info("Total live hosts found: %d", len(normalized_live_hosts))
            logger.info("Total dead hosts found: %d", len(dead_hosts))
            return normalized_live_hosts

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

    _write_hosts_file(output_path, hosts)
    _write_hosts_file(dead_output_path, [])
    return hosts
