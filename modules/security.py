from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from modules.utils import get_logger


def _parse_nuclei_output(stdout: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = payload.get("info") or {}
        matched_at = payload.get("matched-at") or payload.get("matched_at") or ""
        host = payload.get("host") or matched_at or ""
        if host.startswith("http://") or host.startswith("https://"):
            host = host.replace("https://", "", 1).replace("http://", "", 1)
        match = {
            "template_id": payload.get("template-id") or payload.get("template_id") or "",
            "name": info.get("name") or "Unnamed finding",
            "severity": (info.get("severity") or "info").lower(),
            "description": info.get("description") or "",
            "tags": info.get("tags") or [],
            "matched_at": matched_at,
            "host": host,
        }
        findings.append(match)
    return findings


def discover_security_findings(hosts: list[str], config: dict[str, Any]) -> list[dict[str, Any]]:
    output_path = Path(config.get("output", {}).get("security", "output/security.txt"))
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    nuclei_bin = config.get("tools", {}).get("nuclei", "nuclei")
    timeout = int(config.get("timeouts", {}).get("nuclei", 60))

    env = os.environ.copy()
    local_bin = Path(__file__).resolve().parents[1] / ".bin"
    env["PATH"] = str(local_bin) + os.pathsep + env.get("PATH", "")

    writable_home = output_path.parent / ".nuclei-home"
    writable_home.mkdir(parents=True, exist_ok=True)
    env.setdefault("HOME", str(writable_home))
    env["HOME"] = str(writable_home)
    env.setdefault("XDG_CONFIG_HOME", str(writable_home / ".config"))
    env["XDG_CONFIG_HOME"] = str(writable_home / ".config")
    (Path(env["XDG_CONFIG_HOME"])).mkdir(parents=True, exist_ok=True)

    try:
        executable = shutil.which(nuclei_bin, path=env.get("PATH", ""))
    except TypeError:
        executable = shutil.which(nuclei_bin)

    if not executable or not hosts:
        output_path.write_text("", encoding="utf-8")
        return []

    logger = get_logger(config.get("logging", {}).get("file", "logs/scan.log"))
    target_hosts = [host.strip() for host in hosts if host and host.strip()]
    if not target_hosts:
        output_path.write_text("", encoding="utf-8")
        return []

    batch_size = max(1, int(config.get("batching", {}).get("batch_size", 10)))
    findings: list[dict[str, Any]] = []

    for start in range(0, len(target_hosts), batch_size):
        batch_hosts = target_hosts[start : start + batch_size]
        normalized_batch = []
        for host in batch_hosts:
            if host.startswith(("http://", "https://")):
                normalized_batch.append(host)
            else:
                normalized_batch.append(f"https://{host}")

        input_path = output_path.with_suffix(f".nuclei_input_{start}.txt")
        input_path.write_text("\n".join(normalized_batch) + "\n", encoding="utf-8")

        output_file = input_path.with_suffix(".jsonl")
        if output_file.exists():
            output_file.unlink()

        cmd = [
            executable,
            "-list",
            str(input_path),
            "-jsonl",
            "-silent",
            "-tags",
            "ssl,dns,http,misconfig,exposure",
            "-severity",
            "info,low,medium",
            "-timeout",
            "10",
            "-c",
            "25",
            "-bulk-size",
            "10",
            "-rate-limit",
            "100",
            "-o",
            str(output_file),
        ]

        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=900,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            logger.warning("Nuclei batch %d timed out after %s seconds", start, exc.timeout)
            input_path.unlink(missing_ok=True)
            continue
        except OSError as exc:
            logger.warning("Nuclei batch %d failed to start: %s", start, exc)
            input_path.unlink(missing_ok=True)
            continue
        finally:
            if input_path.exists():
                input_path.unlink(missing_ok=True)

        if completed.returncode != 0 and not completed.stdout.strip() and not output_file.exists():
            logger.warning(
                "Nuclei batch %d exited with code %s: %s",
                start,
                completed.returncode,
                (completed.stderr or "").strip() or "no stderr",
            )

        if output_file.exists():
            findings.extend(_parse_nuclei_output(output_file.read_text(encoding="utf-8")))
            output_file.unlink(missing_ok=True)
        else:
            findings.extend(_parse_nuclei_output(completed.stdout or ""))

    output_lines = []
    for finding in findings:
        output_lines.append(json.dumps(finding, sort_keys=True))
    output_path.write_text("\n".join(output_lines) + ("\n" if output_lines else ""), encoding="utf-8")

    return findings
