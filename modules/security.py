from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from modules.utils import get_logger, load_hosts_from_output


def _normalize_nikto_finding(payload: Any, host: str) -> dict[str, Any]:
    if isinstance(payload, dict):
        description = (
            payload.get("message")
            or payload.get("description")
            or payload.get("msg")
            or payload.get("name")
            or payload.get("id")
            or "Nikto finding"
        )
        code = payload.get("id") or payload.get("code") or payload.get("template_id") or "unknown"
        return {
            "template_id": f"nikto-{code}",
            "name": str(description),
            "severity": "medium",
            "description": str(description),
            "tags": ["nikto", "web"],
            "matched_at": host,
            "host": host,
        }

    return {
        "template_id": "nikto-unknown",
        "name": str(payload),
        "severity": "medium",
        "description": str(payload),
        "tags": ["nikto", "web"],
        "matched_at": host,
        "host": host,
    }


def _parse_nikto_output(stdout: str, host: str = "") -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not stdout.strip():
        return findings

    try:
        payload = json.loads(stdout)
    except (TypeError, json.JSONDecodeError):
        payload = None

    if isinstance(payload, list):
        return [_normalize_nikto_finding(item, host) for item in payload if item is not None]
    if isinstance(payload, dict):
        return [_normalize_nikto_finding(payload, host)]

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        if line.startswith("+ Target") or line.startswith("+ Server") or line.startswith("+ SSL Info") or line.startswith("+ Platform"):
            continue

        if line.startswith("ERROR:") or line.startswith("- STATUS:") or line.startswith("- Scan terminated") or line.startswith("- End Time"):
            continue

        if line.startswith("+ "):
            content = line[2:].strip()
            if not content:
                continue
            if re.search(r"\b(host\(s\) tested|requests:|errors and|items reported|remote host)\b", content, re.IGNORECASE):
                continue

        match = re.match(r"^\+\s+\[(\d+)\]\s+(.+)$", line)
        if match:
            code, description = match.groups()
            findings.append(
                {
                    "template_id": f"nikto-{code}",
                    "name": description.strip(),
                    "severity": "medium",
                    "description": description.strip(),
                    "tags": ["nikto", "web"],
                    "matched_at": host,
                    "host": host,
                }
            )
            continue

        match = re.match(r"^\+\s+(\d+)\s+(.+)$", line)
        if match:
            code, description = match.groups()
            findings.append(
                {
                    "template_id": f"nikto-{code}",
                    "name": description.strip(),
                    "severity": "medium",
                    "description": description.strip(),
                    "tags": ["nikto", "web"],
                    "matched_at": host,
                    "host": host,
                }
            )
            continue

    return findings


def _run_nikto_command(cmd: list[str], env: dict[str, str], timeout: int) -> tuple[str, str, int, bool]:
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            env=env,
        )
        return completed.stdout or "", completed.stderr or "", completed.returncode or 0, False
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        return stdout, stderr, 124, True


def discover_security_findings(hosts: list[str], config: dict[str, Any]) -> list[dict[str, Any]]:
    output_path = Path(config.get("output", {}).get("security", "output/security.txt"))
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    nikto_bin = config.get("tools", {}).get("nikto", "nikto")

    env = os.environ.copy()
    local_bin = Path(__file__).resolve().parents[1] / ".bin"
    env["PATH"] = str(local_bin) + os.pathsep + env.get("PATH", "")

    try:
        executable = shutil.which(nikto_bin, path=env.get("PATH", ""))
    except TypeError:
        executable = shutil.which(nikto_bin)

    target_hosts = [host.strip() for host in hosts if host and host.strip()]
    if not target_hosts:
        target_hosts = load_hosts_from_output(config, "live_hosts", "output/live_hosts.txt")

    if not executable or not target_hosts:
        output_path.write_text("", encoding="utf-8")
        return []

    logger = get_logger(config.get("logging", {}).get("file", "logs/scan.log"))

    batch_size = max(1, int(config.get("batching", {}).get("batch_size", 10)))
    findings: list[dict[str, Any]] = []

    for start in range(0, len(target_hosts), batch_size):
        batch_hosts = target_hosts[start : start + batch_size]
        for host_index, host in enumerate(batch_hosts):
            normalized_host = host if host.startswith(("http://", "https://")) else f"https://{host}"
            output_file = output_path.with_suffix(f".nikto_{start}_{host_index}.txt")
            if output_file.exists():
                output_file.unlink()

            cmd = [
                executable,
                "-nointeractive",
                "-nocheck",
                "-maxtime",
                "8s",
                "-Tuning",
                "3,4,5",
                "-Plugins",
                "httpmethods,headers,serverinfo",
                "-Format",
                "txt",
                "-output",
                str(output_file),
                "-host",
                normalized_host,
            ]

            timeout_seconds = int(config.get("timeouts", {}).get("nikto", 60))
            try:
                stdout, stderr, returncode, timed_out = _run_nikto_command(cmd, env, timeout_seconds)
            except OSError as exc:
                logger.warning("Nikto batch %d failed to start: %s", start, exc)
                continue

            if timed_out:
                logger.warning("Nikto batch %d timed out after %s seconds", start, timeout_seconds)

            if returncode != 0 and not stdout.strip() and not output_file.exists():
                logger.warning(
                    "Nikto batch %d exited with code %s: %s",
                    start,
                    returncode,
                    (stderr or "").strip() or "no stderr",
                )

            report_text = ""
            if output_file.exists():
                report_text = output_file.read_text(encoding="utf-8", errors="ignore")
                output_file.unlink(missing_ok=True)
            else:
                report_text = stdout or ""

            if report_text.strip():
                findings.extend(_parse_nikto_output(report_text, host))
            elif stderr and stderr.strip():
                findings.extend(
                    [
                        {
                            "template_id": "nikto-warning",
                            "name": stderr.strip().splitlines()[0],
                            "severity": "info",
                            "description": stderr.strip(),
                            "tags": ["nikto", "warning"],
                            "matched_at": host,
                            "host": host,
                        }
                    ]
                )

    seen: set[tuple[str, str, str]] = set()
    unique_findings: list[dict[str, Any]] = []
    for finding in findings:
        key = (
            str(finding.get("host", "")),
            str(finding.get("template_id", "")),
            str(finding.get("matched_at", "")),
        )
        if key in seen:
            continue
        seen.add(key)
        unique_findings.append(finding)

    output_lines = []
    for finding in unique_findings:
        output_lines.append(json.dumps(finding, sort_keys=True))
    output_path.write_text("\n".join(output_lines) + ("\n" if output_lines else ""), encoding="utf-8")

    return unique_findings
