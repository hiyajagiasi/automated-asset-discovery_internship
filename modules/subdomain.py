from __future__ import annotations

import os
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any
import re


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
    if not labels or len(labels) > 4:
        return False

    for label in labels:
        if not label or len(label) > 30:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if re.fullmatch(r"[a-z0-9-]+", label) is None:
            return False
        if re.fullmatch(r"[0-9a-f]{16,}", label):
            return False
        if label.isdigit():
            return False
        if len(label) >= 20 and not re.search(r"[a-z]", label):
            return False

    return True


def discover_subdomains(target: str, config: dict[str, Any]) -> list[str]:
    output_path = Path(config.get("output", {}).get("subdomains", "output/subdomains.txt"))
    output_path.parent.mkdir(parents=True, exist_ok=True)

    subfinder_bin = config.get("tools", {}).get("subfinder", "subfinder")
    timeout = int(config.get("timeouts", {}).get("subfinder", 60))

    discovered: list[str] = []
    subfinder_results: list[str] = []

    if shutil.which(subfinder_bin):
        try:
            result = subprocess.run(
                [subfinder_bin, "-d", target, "-silent", "-all"],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            print(f'[DEBUG] subfinder returncode={result.returncode} stdout_lines={len(result.stdout.splitlines())} stderr_len={len(result.stderr)} timeout={timeout}')
            if result.returncode == 0:
                subfinder_results = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        except subprocess.TimeoutExpired:
            if timeout < 120:
                retry_timeout = max(120, timeout * 2)
                print(f'[DEBUG] subfinder timed out after {timeout} sec, retrying with {retry_timeout} sec')
                try:
                    result = subprocess.run(
                        [subfinder_bin, "-d", target, "-silent", "-all"],
                        capture_output=True,
                        text=True,
                        timeout=retry_timeout,
                        check=False,
                    )
                    print(f'[DEBUG] retry returncode={result.returncode} stdout_lines={len(result.stdout.splitlines())} stderr_len={len(result.stderr)} timeout={retry_timeout}')
                    if result.returncode == 0:
                        subfinder_results = [line.strip() for line in result.stdout.splitlines() if line.strip()]
                except subprocess.TimeoutExpired:
                    print(f'[DEBUG] subfinder timeout after {retry_timeout} sec')
                    subfinder_results = []
                except OSError as exc:
                    print(f'[DEBUG] subfinder OSError on retry {exc}')
                    subfinder_results = []
            else:
                print(f'[DEBUG] subfinder timeout after {timeout} sec')
                subfinder_results = []
        except OSError as exc:
            print(f'[DEBUG] subfinder OSError {exc}')
            subfinder_results = []

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
