from __future__ import annotations

import json
import re
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from modules.utils import get_logger


def _host(value: str) -> str:
    """Return a hostname/IP suitable for port-scanning from a live-host URL."""
    candidate = value.strip()
    if not candidate:
        return ""
    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
    return (parsed.hostname or "").strip().lower()
def _display_host(
    host: str,
    aliases: dict[str, str] | None = None,
    aggregate_results: list[dict[str, str]] | None = None,
    preserve_aliases: bool = False,
) -> str:
    """Return the host value used in port results, preserving original input when aggregating."""
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
    port_pattern = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?")
    script_pattern = re.compile(r"^\|_?\s*(.*)$")
    host_info_pattern = re.compile(
        r"^(OS details|Aggressive OS guesses|Network Distance|Device type|Service detection performed):\s*(.+)$"
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
            host_value = _display_host(current_host, aliases, aggregate_results, preserve_aliases)
            service_name = match.group(3)
            extra_info = (match.group(4) or "").strip()
            service_value = service_name if not extra_info else f"{service_name} {extra_info}"
            results.append({"host": host_value, "port": match.group(1), "service": service_value})
            last_result_index = len(results) - 1
            continue

        if stripped.startswith("Service Info:") and last_result_index is not None:
            info = stripped[len("Service Info:"):].strip()
            if info:
                existing_service = results[last_result_index].get("service", "")
                results[last_result_index]["service"] = _append_detail(existing_service, info)
            continue

        script = script_pattern.match(stripped)
        if script and last_result_index is not None:
            script_info = script.group(1).strip()
            if script_info:
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


def _unknown_results(host: str, ports: list[str]) -> list[dict[str, str]]:
    return [
        {"host": host, "port": port, "service": _fallback_service(port)}
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
        result = subprocess.run(
            [
                nmap,
                "-Pn",
                "-T4",
                "-sV",
                "-sC",
                "--version-all",
                "--open",
                "-p",
                ",".join(ports),
                host,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return _unknown_results(host, ports, aliases, aggregate_results, preserve_aliases)
    if result.returncode:
        return _unknown_results(host, ports, aliases, aggregate_results, preserve_aliases)
    parsed = _parse_nmap(result.stdout, host, aliases, aggregate_results, preserve_aliases)
    return parsed or _unknown_results(host, ports, aliases, aggregate_results, preserve_aliases)


def scan_ports(hosts: list[str], config: dict[str, Any]) -> list[dict[str, str]]:
    """Discover open TCP ports with Naabu, then identify services with Nmap."""
    output_path = Path(config.get("output", {}).get("ports", "output/ports.txt"))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    logger = get_logger(Path(config.get("logging", {}).get("file", "logs/scan.log")))
    targets = sorted({_host(host) for host in hosts if _host(host)})
    if not targets:
        _write_results(output_path, [])
        return []

    tools = config.get("tools", {})
    timeouts = config.get("timeouts", {})
    naabu = tools.get("naabu", "naabu")
    nmap = tools.get("nmap", "nmap")
    if not shutil.which(naabu):
        logger.warning("Naabu is unavailable; port scan skipped")
        _write_results(output_path, [])
        return []

    batch_size = max(1, int(config.get("limits", {}).get("naabu_batch_size", 100)))
    discovered: dict[str, set[str]] = defaultdict(set)

    for batch_index, start in enumerate(range(0, len(targets), batch_size)):
        batch_targets = targets[start:start + batch_size]
        input_path = output_path.with_suffix(f".naabu_input_{batch_index}.txt")
        input_path.write_text("\n".join(batch_targets) + "\n", encoding="utf-8")
        try:
            naabu_result = subprocess.run(
                [naabu, "-list", str(input_path), "-json", "-silent"],
                capture_output=True,
                text=True,
                timeout=int(timeouts.get("naabu", 60)),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            logger.warning("Naabu port discovery failed for batch %d: %s", batch_index, exc)
            continue
        finally:
            input_path.unlink(missing_ok=True)

        batch_discovered = _parse_naabu(naabu_result.stdout)
        if naabu_result.returncode:
            logger.warning("Naabu exited with %d for batch %d: %s", naabu_result.returncode, batch_index, naabu_result.stderr.strip())
        for host, ports in batch_discovered.items():
            discovered[host].update(ports)

    if not discovered:
        _write_results(output_path, [])
        return []

    provisional_results = [
        {"host": host, "port": port, "service": "unknown"}
        for host, host_ports in discovered.items()
        for port in sorted(host_ports, key=int)
    ]
    _write_results(output_path, provisional_results)
    logger.info(
        "Naabu discovered %d open ports across %d live hosts; written to %s pending service verification",
        len(provisional_results),
        len(discovered),
        output_path,
    )

    if not shutil.which(nmap):
        logger.warning("Nmap is unavailable; returning Naabu discoveries without service verification")
        results = [
            {"host": host, "port": port, "service": "unknown"}
            for host, host_ports in discovered.items()
            for port in sorted(host_ports, key=int)
        ]
        _write_results(output_path, results)
        return results

    max_nmap_hosts = int(config.get("limits", {}).get("nmap_hosts", 0))
    if max_nmap_hosts <= 0:
        max_nmap_hosts = len(discovered)
    nmap_timeout = max(5, min(int(timeouts.get("nmap", 60)), 10))
    results: list[dict[str, str]] = []
    nmap_jobs: list[tuple[str, list[str]]] = []
    for index, (host, host_ports) in enumerate(discovered.items()):
        ports = sorted(host_ports, key=int)
        if index >= max_nmap_hosts:
            results.extend({"host": host, "port": port, "service": "unknown"} for port in ports)
            continue
        nmap_jobs.append((host, ports))

    workers = max(1, int(config.get("limits", {}).get("nmap_parallel_workers", 8)))
    completed = 0
    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(nmap_jobs)))) as executor:
        futures = {
            executor.submit(_scan_nmap_host, host, ports, nmap, nmap_timeout): (host, ports)
            for host, ports in nmap_jobs
        }
        for future in as_completed(futures):
            host, ports = futures[future]
            try:
                results.extend(future.result())
            except Exception as exc:
                logger.warning("Nmap service scan failed for %s: %s", host, exc)
                results.extend({"host": host, "port": port, "service": "unknown"} for port in ports)
            completed += 1
            if completed % 25 == 0 or completed == len(nmap_jobs):
                logger.info("Nmap service progress: %d/%d hosts", completed, len(nmap_jobs))

    results.sort(key=lambda item: (item["host"], int(item["port"])))
    _write_results(output_path, results)
    logger.info("Identified %d open ports across %d live hosts", len(results), len(discovered))
    return results
