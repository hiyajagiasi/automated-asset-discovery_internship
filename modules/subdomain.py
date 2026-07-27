from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
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
    if not labels or len(labels) > 10:
        return False

    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if re.fullmatch(r"[a-z0-9-]+", label) is None:
            return False
        
        # Reject purely numeric labels (they're usually junk from fuzzing)
        # Exception: allow short numeric suffixes like "v2", "api2", etc
        if label.isdigit():
            # Only allow purely numeric if it's >= 10000 (like IP octets in special cases)
            if len(label) <= 3:
                return False
        
        # Reject hex-like strings (common in fuzzing artifacts)
        if re.fullmatch(r"[0-9a-f]{16,}", label):
            return False
        
        # Reject very long alphanumeric without hyphens (usually garbage)
        if len(label) >= 20 and all(ch.isalnum() for ch in label):
            return False
        
        # Reject labels that start with numbers followed by letters with no separator
        # (e.g., "13drive", "0ik" - these are fuzzing artifacts)
        if re.match(r"^\d{1,3}[a-z]+", label):
            return False

    return True


def _discover_subdomains_single(
    target: str,
    subfinder_bin: str,
    timeout: int,
    env: dict[str, str],
    output_path: Path,
) -> list[str]:
    """Discover subdomains for a single target using subfinder."""
    discovered: list[str] = []
    subfinder_results: list[str] = []
    temp_output: Path | None = None

    if shutil.which(subfinder_bin):
        try:
            temp_output = output_path.with_suffix(".subfinder.txt")
            temp_output.parent.mkdir(parents=True, exist_ok=True)
            if temp_output.exists():
                temp_output.unlink()

            command = [
                subfinder_bin,
                "-d",
                target,
                "-silent",
                "-o",
                str(temp_output),
                "-disable-update-check",
                "-timeout",
                str(timeout),
                "-all",
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
        print('[DEBUG] falling back to static candidates (no subfinder results)')
        discovered = _stable_fallback_candidates(target)
        dns_result = _dns_probe(target)
        if dns_result:
            discovered.extend(dns_result)

    raw_count = len(discovered)

    unique_subdomains = []
    seen = set()
    for item in discovered:
        cleaned = item.strip().lower()
        if not cleaned or cleaned in seen:
            continue

        if _looks_like_real_subdomain(cleaned, target):
            unique_subdomains.append(cleaned)
            seen.add(cleaned)

    # If subfinder returned results but all were filtered out, try fallback
    if subfinder_results and not unique_subdomains:
        print('[DEBUG] subfinder results were filtered out, falling back to static candidates')
        discovered = _stable_fallback_candidates(target)
        dns_result = _dns_probe(target)
        if dns_result:
            discovered.extend(dns_result)
        
        raw_count = len(discovered)
        unique_subdomains = []
        seen = set()
        for item in discovered:
            cleaned = item.strip().lower()
            if not cleaned or cleaned in seen:
                continue

            if _looks_like_real_subdomain(cleaned, target):
                unique_subdomains.append(cleaned)
                seen.add(cleaned)

    print(f'[DEBUG] subdomain filtering raw_count={raw_count} filtered_count={len(unique_subdomains)}')
    return unique_subdomains


def discover_subdomains(target: str | list[str], config: dict[str, Any]) -> list[str]:
    """Discover subdomains for one or more targets with parallel batch processing.
    
    Args:
        target: Single domain string or list of domains to discover subdomains for.
        config: Configuration dictionary with tools, timeouts, batching settings.
    
    Returns:
        List of unique discovered subdomains (combined from all targets if multiple).
    """
    # Handle both single target and list of targets
    targets = [target] if isinstance(target, str) else target
    
    output_path = Path(config.get("output", {}).get("subdomains", "output/subdomains.txt"))
    output_path.parent.mkdir(parents=True, exist_ok=True)

    subfinder_bin = config.get("tools", {}).get("subfinder", "subfinder")
    timeout = int(config.get("timeouts", {}).get("subfinder", 60))
    timeout = max(5, timeout)

    # Setup environment with PATH
    env = os.environ.copy()
    env["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:" + env.get("PATH", "")

    # Get batching configuration
    batching = config.get("batching", {})
    batch_size = max(1, int(batching.get("batch_size", 50)))
    workers = max(1, int(batching.get("workers", 4)))

    all_subdomains: list[str] = []
    
    # Process targets in batches with parallel workers
    for start in range(0, len(targets), batch_size):
        batch = targets[start : start + batch_size]
        
        if len(batch) == 1:
            # Single target in batch - process directly
            subdomains = _discover_subdomains_single(batch[0], subfinder_bin, timeout, env, output_path)
            all_subdomains.extend(subdomains)
            continue

        # Multiple targets in batch - process in parallel
        with ThreadPoolExecutor(max_workers=min(workers, len(batch))) as executor:
            futures = [
                executor.submit(_discover_subdomains_single, target_item, subfinder_bin, timeout, env, output_path)
                for target_item in batch
            ]
            for future in futures:
                subdomains = future.result()
                all_subdomains.extend(subdomains)

    # Deduplicate results
    unique_subdomains = []
    seen = set()
    for subdomain in all_subdomains:
        if subdomain not in seen:
            seen.add(subdomain)
            unique_subdomains.append(subdomain)

    print(f'[DEBUG] total discovered subdomains count={len(unique_subdomains)}')
    output_path.write_text("\n".join(unique_subdomains) + "\n", encoding="utf-8")
    return unique_subdomains

