from __future__ import annotations

import ipaddress
import json
import random
import re
import shutil
import socket
import subprocess
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from modules.utils import get_logger


def _host(value: str) -> str:
    """Return a hostname/IP suitable for port-scanning from a live-host URL."""
    candidate = (value or "").strip()
    if not candidate:
        return ""
    if any(char.isspace() for char in candidate):
        return ""
    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        return ""
    if hostname.startswith(".") or hostname.endswith("."):
        return ""
    if any(char.isspace() for char in hostname):
        return ""
    if hostname in {"localhost"}:
        return ""
    if hostname.startswith("http"):
        return ""
    if hostname.count(".") < 1:
        return ""
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass
    if re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}", hostname, re.IGNORECASE):
        return hostname
    return ""


def _display_host(
    host: str,
    aliases: dict[str, str] | None = None,
    aggregate_results: list[dict[str, str]] | None = None,
    preserve_aliases: bool = False,
) -> str:
    """Return the host value used in port results, preserving the original input form when aggregating into the recon pipeline."""
    normalized = _host(host)
    if aggregate_results is not None:
        if aliases:
            alias = aliases.get(normalized)
            if alias:
                return alias
        raw_host = (host or "").strip()
        if not raw_host:
            return normalized or host
        if "://" in raw_host:
            return raw_host
        return f"https://{raw_host}"
    return normalized or host


def _parse_naabu(stdout: str) -> dict[str, set[str]]:
    discovered: dict[str, set[str]] = defaultdict(set)
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            host, separator, port = line.rpartition(":")
            if separator and host and port.isdigit():
                discovered[_host(host)].add(port)
            continue

        if isinstance(payload, list):
            for item in payload:
                if not isinstance(item, dict):
                    continue
                host = _host(str(item.get("host", "")))
                port = str(item.get("port", ""))
                if host and port.isdigit():
                    discovered[host].add(port)
            continue

        if isinstance(payload, dict):
            host = _host(str(payload.get("host", "")))
            port = str(payload.get("port", ""))
            if host and port.isdigit():
                discovered[host].add(port)
    return discovered


def _parse_nmap(
    stdout: str,
    default_host: str,
    aliases: dict[str, str] | None = None,
    aggregate_results: list[dict[str, str]] | None = None,
    preserve_aliases: bool = False,
) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    current_host = default_host
    last_result_index: int | None = None
    host_metadata: dict[str, list[str]] = defaultdict(list)
    report_pattern = re.compile(r"Nmap scan report for (?:.+ \()?([^ )]+)\)?$")
    port_pattern = re.compile(r"^(\d+)/(tcp|udp)\s+(open(?:\|filtered)?)\s+(\S+)(?:\s+(.+))?")
    script_pattern = re.compile(r"^\|_?\s*(.*)$")
    script_detail_pattern = re.compile(r"^(\S+):\s*(.+)$")
    service_info_pattern = re.compile(r"^Service Info:\s*(.+)$")
    host_info_pattern = re.compile(
        r"^(OS details|Aggressive OS guesses|Network Distance|Device type|Service detection performed|Service Info|CPE):\s*(.+)$"
    )

    def _append_detail(base: str, detail: str) -> str:
        if not base:
            return detail
        return f"{base}; {detail}"

    for line in stdout.splitlines():
        stripped = line.strip()
        report = report_pattern.match(stripped)
        if report:
            current_host = _host(report.group(1)) or default_host
            last_result_index = None
            continue

        match = port_pattern.match(stripped)
        if match:
            state = match.group(3)
            if "open" not in state:
                continue
            host_value = _display_host(current_host, aliases, aggregate_results, preserve_aliases)
            service_name = match.group(4)
            extra_info = (match.group(5) or "").strip()
            service_value = service_name if not extra_info else f"{service_name} {extra_info}"
            results.append({"host": host_value, "port": match.group(1), "service": service_value})
            last_result_index = len(results) - 1
            continue

        service_info = service_info_pattern.match(stripped)
        if service_info and last_result_index is not None:
            info = service_info.group(1).strip()
            if info:
                existing_service = results[last_result_index].get("service", "")
                results[last_result_index]["service"] = _append_detail(existing_service, info)
            continue

        script = script_pattern.match(stripped)
        if script and last_result_index is not None:
            script_info = script.group(1).strip()
            if script_info:
                detail_match = script_detail_pattern.match(script_info)
                if detail_match:
                    script_info = f"{detail_match.group(1)}: {detail_match.group(2)}"
                existing_service = results[last_result_index].get("service", "")
                results[last_result_index]["service"] = _append_detail(existing_service, script_info)
            continue

        host_info = host_info_pattern.match(stripped)
        if host_info:
            host_metadata[current_host].append(f"{host_info.group(1)}: {host_info.group(2)}")
            continue

    if host_metadata:
        for item in results:
            host_meta = host_metadata.get(_host(item["host"]), [])
            if host_meta:
                existing_service = item.get("service", "")
                item["service"] = _append_detail(existing_service, "; ".join(host_meta))

    return results


def _write_results(output_path: Path, ports: list[dict[str, str]]) -> None:
    lines = [
        f"{item['host']}:{item['port']} ({item['service']}) [subdomain={item['host']}]"
        for item in ports
    ]
    output_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def _fallback_service(port: str) -> str:
    try:
        return socket.getservbyport(int(port), "tcp")
    except (OSError, ValueError):
        return "unknown"


def _unknown_results(
    host: str,
    ports: list[str],
    aliases: dict[str, str] | None = None,
    aggregate_results: list[dict[str, str]] | None = None,
    preserve_aliases: bool = False,
) -> list[dict[str, str]]:
    return [
        {
            "host": _display_host(host, aliases, aggregate_results, preserve_aliases),
            "port": port,
            "service": _fallback_service(port),
        }
        for port in ports
    ]


def _scan_nmap_host(
    host: str,
    ports: list[str],
    nmap: str,
    timeout: int,
    aliases: dict[str, str] | None = None,
    aggregate_results: list[dict[str, str]] | None = None,
    preserve_aliases: bool = False,
) -> list[dict[str, str]]:
    try:
        script_list = "default,http-title,http-server-header,ssl-cert"
        cmd = [
            nmap,
            "-Pn",
            "-T4",
            "-sV",
            "-sC",
            "--version-all",
            "--open",
            "--script",
            script_list,
            "-p",
            ",".join(ports),
            host,
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return _unknown_results(host, ports, aliases, aggregate_results, preserve_aliases)

    parsed = _parse_nmap(result.stdout, host, aliases, aggregate_results, preserve_aliases)
    if result.returncode not in {0, 1}:
        return parsed or _unknown_results(host, ports, aliases, aggregate_results, preserve_aliases)

    def _is_minimal(s: str) -> bool:
        low = (s or "").lower()
        if not low or low == "unknown":
            return True
        if ";" not in low and "/" not in low and "title=" not in low and "server=" not in low:
            return True
        return False

    save_raw = False
    if not parsed:
        save_raw = True
    else:
        for item in parsed:
            if _is_minimal(item.get("service", "")):
                save_raw = True
                break

    if save_raw:
        try:
            raw_dir = Path("logs")
            raw_dir.mkdir(parents=True, exist_ok=True)
            safe_host = host.replace("/", "_").replace(":", "_").replace(".", "_")
            name = f"nmap_{safe_host}_{'_'.join(ports)}.txt"
            raw_path = raw_dir / name
            raw_path.write_text("STDOUT:\n" + (result.stdout or "") + "\n\nSTDERR:\n" + (result.stderr or ""), encoding="utf-8")
        except Exception:
            pass

    return parsed or _unknown_results(host, ports, aliases, aggregate_results, preserve_aliases)


def _notify_batch_callback(
    callback: Callable[[list[str], list[dict[str, str]]], None] | Callable[[list[str]], None] | None,
    batch: list[str],
    batch_results: list[dict[str, str]],
) -> None:
    if callback is None:
        return
    try:
        callback(batch, batch_results)
    except TypeError:
        try:
            callback(batch)
        except TypeError:
            callback(batch, batch_results=batch_results)


def _invoke_with_retries(
    action: Callable[[], Any],
    *,
    attempts: int = 3,
    initial_pause: float = 0.25,
    max_pause: float = 2.0,
    jitter: float = 0.1,
    logger: Any | None = None,
) -> Any:
    pause = initial_pause
    for attempt in range(1, attempts + 1):
        try:
            return action()
        except Exception as exc:
            if attempt >= attempts:
                raise
            sleep_for = min(max_pause, pause + random.uniform(0, jitter))
            if logger is not None:
                logger.warning("Transient command failure on attempt %d/%d: %s", attempt, attempts, exc)
            time.sleep(sleep_for)
            pause = min(max_pause, pause * 2)

    raise RuntimeError("No result produced")


def _run_naabu_batch(
    batch_index: int,
    batch_targets: list[str],
    naabu: str,
    timeout: int,
    output_path: Path,
    logger: Any,
) -> tuple[int, list[str], dict[str, set[str]]]:
    input_path = output_path.with_suffix(f".naabu_input_{batch_index}.txt")
    input_path.write_text("\n".join(batch_targets) + "\n", encoding="utf-8")
    try:
        naabu_result = _invoke_with_retries(
            lambda: subprocess.run(
                [naabu, "-list", str(input_path), "-json", "-silent"],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            ),
            attempts=3,
            initial_pause=0.25,
            max_pause=1.0,
            jitter=0.1,
            logger=logger,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("Naabu port discovery failed for batch %d: %s", batch_index, exc)
        return batch_index, batch_targets, {}
    finally:
        input_path.unlink(missing_ok=True)

    if naabu_result.returncode:
        logger.warning(
            "Naabu exited with %d for batch %d: %s",
            naabu_result.returncode,
            batch_index,
            naabu_result.stderr.strip(),
        )
    return batch_index, batch_targets, _parse_naabu(naabu_result.stdout)


def _service_is_richer(candidate: str, existing: str) -> bool:
    if not candidate or candidate == "unknown":
        return False
    if not existing or existing == "unknown":
        return True
    if existing.lower() == candidate.lower():
        return False
    if len(candidate) > len(existing):
        return True
    if ";" in candidate and ";" not in existing:
        return True
    if ":" in candidate and ":" not in existing:
        return True
    return False


def _needs_httpx_enrichment(service: str) -> bool:
    low = (service or "").lower().strip()
    if not low or low == "unknown":
        return True
    if low in {"http", "https", "ssl/http", "ssl/https"}:
        return True
    if ";" in low or "title=" in low or "server=" in low or "ssl-cert" in low or "fingerprint-strings" in low:
        return False
    if " " in low:
        return False
    if low.startswith(("http", "https", "ssl/http", "ssl/https")):
        return True
    return False


def _merge_results(existing: list[dict[str, str]], incoming: list[dict[str, str]]) -> list[dict[str, str]]:
    merged: dict[tuple[str, str], dict[str, str]] = {}
    for item in existing + incoming:
        key = (item["host"], item["port"])
        service = item["service"]
        if key not in merged:
            merged[key] = {"host": item["host"], "port": item["port"], "service": service}
            continue

        current_service = merged[key]["service"]
        if _service_is_richer(service, current_service):
            merged[key] = {"host": item["host"], "port": item["port"], "service": service}
        elif current_service == "unknown" and service != "unknown":
            merged[key] = {"host": item["host"], "port": item["port"], "service": service}
    return sorted(merged.values(), key=lambda item: (item["host"], int(item["port"])))


def _probe_httpx(host: str, port: str, httpx_bin: str, timeout: int) -> str:
    """Use httpx to probe a host:port and return a short detail string (title/server/status)."""
    if not shutil.which(httpx_bin):
        return ""
    scheme = "https" if port == "443" else "http"
    url = f"{scheme}://{host}:{port}"
    try:
        result = subprocess.run(
            [httpx_bin, "-silent", "-no-color", "-json", "-title", "-server", "-status-code", url],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        result = None

    parts: list[str] = []
    if result and result.stdout:
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except Exception:
                continue
            if isinstance(payload, list) and payload:
                payload = payload[0]
            if not isinstance(payload, dict):
                continue
            title = payload.get("title") or payload.get("title_raw") or ""
            server = payload.get("server") or ""
            status = payload.get("status_code") or payload.get("status-code") or payload.get("status") or ""
            if title:
                parts.append(f"title={title}")
            if server:
                parts.append(f"server={server}")
            if status:
                parts.append(f"status={status}")
            if parts:
                return "; ".join(parts)

    try:
        head = subprocess.run(
            ["curl", "-sS", "-k", "-I", "-m", str(timeout), url],
            capture_output=True,
            text=True,
            check=False,
        )
        if head and head.stdout:
            for hline in head.stdout.splitlines():
                if hline.lower().startswith("server:"):
                    parts.append(f"server={hline.split(':', 1)[1].strip()}")
                if hline.startswith("HTTP/"):
                    fields = hline.split()
                    if len(fields) >= 2:
                        parts.append(f"status={fields[1]}")
        body = subprocess.run(
            ["curl", "-sS", "-k", "-L", "-r", "0-8191", "-m", str(timeout), url],
            capture_output=True,
            text=True,
            check=False,
        )
        if body and body.stdout:
            match = re.search(r"<title[^>]*>(.*?)</title>", body.stdout, re.IGNORECASE | re.DOTALL)
            if match:
                title = match.group(1).strip()
                if title:
                    parts.insert(0, f"title={title}")
    except Exception:
        pass

    return "; ".join(parts)


def scan_ports(
    hosts: list[str],
    config: dict[str, Any],
    batch_callback: Callable[[list[str], list[dict[str, str]]], None] | Callable[[list[str]], None] | None = None,
    aggregate_results: list[dict[str, str]] | None = None,
    processed_hosts: set[str] | None = None,
    preserve_aliases: bool = False,
) -> list[dict[str, str]]:
    """Discover open TCP ports with Naabu, then identify services with Nmap."""
    output_path = Path(config.get("output", {}).get("ports", "output/ports.txt"))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    logger = get_logger(Path(config.get("logging", {}).get("file", "logs/scan.log")))
    processed_hosts = processed_hosts if processed_hosts is not None else set()
    targets = sorted({
        host for host in {_host(host) for host in hosts if _host(host)}
        if host and host not in processed_hosts
    })
    if not targets:
        if aggregate_results is not None:
            _write_results(output_path, aggregate_results)
            return aggregate_results
        _write_results(output_path, [])
        return []

    tools = config.get("tools", {})
    timeouts = config.get("timeouts", {})
    naabu = tools.get("naabu", "naabu")
    nmap = tools.get("nmap", "nmap")
    if not shutil.which(naabu):
        logger.warning("Naabu is unavailable; port scan skipped")
        processed_hosts.update(_host(host) for host in hosts if _host(host))
        if aggregate_results is not None:
            _write_results(output_path, aggregate_results)
            return aggregate_results
        _write_results(output_path, [])
        return []

    batch_size = max(1, int(config.get("limits", {}).get("naabu_batch_size", 100)))
    discovered: dict[str, set[str]] = defaultdict(set)
    host_aliases = {_host(host): host for host in hosts if _host(host)}

    batches: list[tuple[int, list[str]]] = []
    for batch_index, start in enumerate(range(0, len(targets), batch_size)):
        batch_targets = targets[start : start + batch_size]
        if batch_targets:
            batches.append((batch_index, batch_targets))

    naabu_parallel_workers = max(1, int(config.get("limits", {}).get("naabu_parallel_workers", 3)))
    with ThreadPoolExecutor(max_workers=min(naabu_parallel_workers, max(1, len(batches)))) as executor:
        futures = {
            executor.submit(
                _run_naabu_batch,
                batch_index,
                batch_targets,
                naabu,
                int(timeouts.get("naabu", 60)),
                output_path,
                logger,
            ): (batch_index, batch_targets)
            for batch_index, batch_targets in batches
        }

        for future in as_completed(futures):
            try:
                batch_index, batch_targets, batch_discovered = future.result()
            except Exception as exc:
                batch_index, batch_targets, batch_discovered = futures[future][0], futures[future][1], {}
                logger.warning("Naabu batch %d failed unexpectedly: %s", batch_index, exc)

            for host, ports in batch_discovered.items():
                discovered[host].update(ports)

            provisional_results = [
                {
                    "host": _display_host(host, host_aliases, aggregate_results, preserve_aliases),
                    "port": port,
                    "service": "unknown",
                }
                for host, host_ports in discovered.items()
                for port in sorted(host_ports, key=int)
            ]
            deduped_results = _merge_results([], provisional_results)
            if aggregate_results is None:
                _write_results(output_path, deduped_results)
            else:
                aggregate_results[:] = _merge_results(aggregate_results, deduped_results)
                _write_results(output_path, aggregate_results)
            _notify_batch_callback(batch_callback, batch_targets, deduped_results)

    if not discovered:
        _write_results(output_path, [])
        processed_hosts.update(targets)
        if aggregate_results is not None:
            return aggregate_results
        return []

    if not shutil.which(nmap):
        logger.warning("Nmap is unavailable; returning Naabu discoveries without service verification")
        results = [
            {
                "host": _display_host(host, host_aliases, aggregate_results, preserve_aliases),
                "port": port,
                "service": "unknown",
            }
            for host, host_ports in discovered.items()
            for port in sorted(host_ports, key=int)
        ]
        deduped_results = _merge_results([], results)
        if aggregate_results is not None:
            aggregate_results[:] = _merge_results(aggregate_results, deduped_results)
            _write_results(output_path, aggregate_results)
            logger.info("Identified %d open host-port combinations across %d hosts", len(aggregate_results), len(discovered))
            return aggregate_results
        _write_results(output_path, deduped_results)
        return deduped_results

    max_nmap_hosts = int(config.get("limits", {}).get("nmap_hosts", 0))
    if max_nmap_hosts <= 0:
        max_nmap_hosts = len(targets)
    nmap_timeout = max(10, int(timeouts.get("nmap", 60)))
    results: list[dict[str, str]] = []
    workers = max(1, int(config.get("limits", {}).get("nmap_parallel_workers", 8)))
    nmap_executor = ThreadPoolExecutor(max_workers=min(workers, max(1, max_nmap_hosts)))
    nmap_futures: dict = {}
    nmap_submitted = 0
    scanned_hosts: set[str] = set()
    scanned_ports: dict[str, set[str]] = {host: set() for host in targets}

    def submit_nmap_jobs(batch_targets: list[str], batch_discovered: dict[str, set[str]]) -> None:
        nonlocal nmap_submitted
        for candidate in batch_targets:
            host = _host(candidate)
            if not host or nmap_submitted >= max_nmap_hosts:
                continue
            ports = batch_discovered.get(host, set()) or set()
            new_ports = sorted(port for port in ports if port not in scanned_ports.get(host, set()))
            if not new_ports:
                continue
            if host not in scanned_hosts:
                scanned_hosts.add(host)
                nmap_submitted += 1
            scanned_ports[host].update(new_ports)
            future = nmap_executor.submit(
                _scan_nmap_host,
                host,
                new_ports,
                nmap,
                nmap_timeout,
                host_aliases,
                aggregate_results,
                preserve_aliases,
            )
            nmap_futures[future] = (host, new_ports)

    completed = 0
    for batch_index, batch_targets in batches:
        batch_discovered = {
            host: discovered.get(host, set())
            for host in (_host(candidate) for candidate in batch_targets)
            if host
        }
        submit_nmap_jobs(batch_targets, batch_discovered)

    if nmap_futures:
        for future in as_completed(nmap_futures):
            host, ports = nmap_futures[future]
            try:
                results.extend(future.result())
            except Exception as exc:
                logger.warning("Nmap service scan failed for %s: %s", host, exc)
                results.extend(
                    {
                        "host": _display_host(host, host_aliases, aggregate_results, preserve_aliases),
                        "port": port,
                        "service": "unknown",
                    }
                    for port in ports
                )
            completed += 1
            if completed % 25 == 0 or completed == nmap_submitted:
                logger.info("Nmap service progress: %d/%d hosts", completed, nmap_submitted)
    nmap_executor.shutdown(wait=True)

    httpx_bin = tools.get("httpx")
    httpx_timeout = max(5, int(timeouts.get("httpx", nmap_timeout)))
    if httpx_bin and shutil.which(httpx_bin):
        for item in list(results):
            try:
                if item.get("port") in {"80", "443"}:
                    existing_service = item.get("service", "")
                    if _needs_httpx_enrichment(existing_service):
                        detail = _probe_httpx(_host(item["host"]), item["port"], httpx_bin, httpx_timeout)
                        if detail:
                            item["service"] = existing_service + ("; " + detail if existing_service else detail)
            except Exception:
                continue

    final_results: list[dict[str, str]] = []
    for host, host_ports in discovered.items():
        if host_ports:
            for port in sorted(host_ports, key=int):
                final_results.append(
                    {
                        "host": _display_host(host, host_aliases, aggregate_results, preserve_aliases),
                        "port": port,
                        "service": "unknown",
                    }
                )

    if results:
        rich_results = [
            {
                "host": item["host"],
                "port": item["port"],
                "service": item["service"],
            }
            for item in results
        ]
        final_results = _merge_results(final_results, rich_results)
    else:
        final_results = _merge_results([], final_results)

    deduped_results = final_results
    processed_hosts.update(targets)
    if aggregate_results is not None:
        aggregate_results[:] = _merge_results(aggregate_results, deduped_results)
        _write_results(output_path, aggregate_results)
        logger.info("Identified %d open host-port combinations across %d hosts", len(aggregate_results), len(discovered))
        return aggregate_results
    _write_results(output_path, deduped_results)
    logger.info("Identified %d open host-port combinations across %d hosts", len(deduped_results), len(discovered))
    return deduped_results
