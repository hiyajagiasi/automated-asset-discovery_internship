from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any


def _dns_probe(target: str) -> list[str]:
    try:
        answers = socket.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return []
    return [target] if answers else []


def _stable_fallback_candidates(target: str) -> list[str]:
    labels = target.split(".")
    if len(labels) < 2:
        return [target]

    root = ".".join(labels[1:])
    return [target, f"www.{target}", f"mail.{target}", f"login.{target}", f"www.{root}"]


def _looks_like_real_subdomain(candidate: str, target: str) -> bool:
    cleaned = candidate.strip().lower()
    if not cleaned:
        return False

    if cleaned == target:
        return True

    if not cleaned.endswith("." + target):
        return False

    labels = cleaned[: -len(target) - 1].split(".")
    if not labels or len(labels) > 5:
        return False

    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if re.fullmatch(r"[a-z0-9-]+", label) is None:
            return False
        if re.fullmatch(r"[0-9a-f]{16,}", label):
            return False
        if label.isdigit() and len(label) >= 8:
            return False
        if len(label) >= 20 and all(ch.isalnum() for ch in label):
            return False

    return True


def discover_subdomains(target: str, config: dict[str, Any]) -> list[str]:
    output_path = Path(config.get("output", {}).get("subdomains", "output/subdomains.txt"))
    output_path.parent.mkdir(parents=True, exist_ok=True)

    subfinder_bin = config.get("tools", {}).get("subfinder", "subfinder")
    timeout = int(config.get("timeouts", {}).get("subfinder", 60))
    timeout = max(5, timeout)

    discovered: list[str] = []
    subfinder_results: list[str] = []
    temp_output: Path | None = None

    if shutil.which(subfinder_bin):
        try:
            temp_output = output_path.with_suffix(".subfinder.txt")
            temp_output.parent.mkdir(parents=True, exist_ok=True)
            if temp_output.exists():
                temp_output.unlink()

            env = os.environ.copy()
            env["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:" + env.get("PATH", "")
            command = [
                subfinder_bin,
                "-d",
                target,
                "-silent",
                "-all",
                "-disable-update-check",
                "-timeout",
                str(timeout),
            ]
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout + 20, check=False, env=env)
            print(f'[DEBUG] subfinder returncode={result.returncode} output_file={temp_output} timeout={timeout + 20}')
            if result.stdout:
                subfinder_results = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            elif temp_output.exists():
                file_contents = temp_output.read_text(encoding="utf-8")
                subfinder_results = [line.strip() for line in file_contents.splitlines() if line.strip()]
            if not subfinder_results and result.returncode == 0:
                print('[DEBUG] subfinder completed but produced no output file content')
            else:
                print(f'[DEBUG] subfinder produced {len(subfinder_results)} lines from stdout')
        except subprocess.TimeoutExpired as exc:
            partial_output: list[str] = []
            partial_text = getattr(exc, "stdout", None) or getattr(exc, "output", None) or ""
            if isinstance(partial_text, bytes):
                partial_text = partial_text.decode("utf-8", errors="ignore")
            if partial_text:
                partial_output = [line.strip() for line in partial_text.splitlines() if line.strip()]
            if not partial_output and temp_output and temp_output.exists():
                partial_output = [line.strip() for line in temp_output.read_text(encoding="utf-8").splitlines() if line.strip()]
            if partial_output:
                print(f'[DEBUG] subfinder timed out after {timeout} sec but returned {len(partial_output)} partial lines')
                subfinder_results = partial_output
            else:
                print(f'[DEBUG] subfinder timeout after {timeout} sec')
                subfinder_results = []
        except OSError as exc:
            print(f'[DEBUG] subfinder OSError {exc}')
            subfinder_results = []
        finally:
            if temp_output and temp_output.exists() and temp_output != output_path:
                temp_output.unlink(missing_ok=True)

    if subfinder_results:
        print(f'[DEBUG] using subfinder_results count={len(subfinder_results)}')
        discovered = subfinder_results
    else:
        print('[DEBUG] falling back to static candidates')
        discovered = _stable_fallback_candidates(target)
        dns_result = _dns_probe(target)
        if dns_result:
            discovered.extend(dns_result)

    unique_subdomains = []
    seen = set()
    for item in discovered:
        cleaned = item.strip().lower()
        if not cleaned or cleaned in seen:
            continue

        if _looks_like_real_subdomain(cleaned, target):
            unique_subdomains.append(cleaned)
            seen.add(cleaned)

    output_path.write_text("\n".join(unique_subdomains) + "\n", encoding="utf-8")
    return unique_subdomains
