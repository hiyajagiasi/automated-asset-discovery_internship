from __future__ import annotations

import json
import shutil
import subprocess
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any


CATEGORY_LABELS = {
    "web server": "Web Server",
    "programming language": "Programming Language",
    "framework": "Framework",
    "cms": "CMS",
    "cdn": "CDN",
    "waf": "WAF",
    "hosting": "Hosting",
    "javascript library": "JavaScript Library",
    "analytics": "Analytics",
    "security": "Security",
    "ssl/tls": "SSL/TLS",
}


def _find_tool(tool_name: str) -> str | None:
    """Locate a tool in PATH."""
    return shutil.which(tool_name)


def _normalize_target(host: str) -> str:
    host = host.strip()
    if not host:
        return ""
    if host.startswith(("http://", "https://")):
        return host
    return f"https://{host}"


def _map_httpx_header(key: str, value: str) -> str | None:
    header_key = key.lower().strip()
    header_value = str(value).strip()
    if not header_value:
        return None

    if header_key == "server":
        server_value = header_value.lower()
        if "esf" in server_value:
            return "Google Web Server (ESF)"
        if "nginx" in server_value:
            return "Web Server: nginx"
        if "apache" in server_value:
            return "Web Server: apache"
        if "cloudflare" in server_value:
            return "CDN: Cloudflare"
        return f"Web Server: {header_value}"

    if header_key == "x-powered-by":
        powered_value = header_value.lower()
        if "php" in powered_value:
            return "Programming Language: PHP"
        if "asp.net" in powered_value or "aspnet" in powered_value:
            return "Programming Language: ASP.NET"
        if "java" in powered_value:
            return "Programming Language: Java"
        if "node" in powered_value:
            return "Programming Language: Node.js"
        return f"Programming Language: {header_value}"

    if header_key == "alt-svc":
        if "h3" in header_value.lower() or "http/3" in header_value.lower():
            return "HTTP/3"
        return None

    if header_key == "content-type":
        if "text/html" in header_value.lower():
            return "HTML5"
        if "application/json" in header_value.lower():
            return "JSON"
        return None

    return None


def _parse_httpx_headers(headers: dict[str, Any]) -> list[str]:
    mapped_parts: list[str] = []
    for key, value in headers.items():
        mapped = _map_httpx_header(str(key), str(value))
        if mapped:
            mapped_parts.append(mapped)
    return mapped_parts


def _parse_httpx_technology(stdout: str) -> str:
    try:
        payload = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return "unknown"

    headers = payload.get("headers", {}) or {}
    mapped_parts = _parse_httpx_headers(headers)
    return " | ".join(mapped_parts) if mapped_parts else "unknown"


def _parse_wappalyzer_technology(stdout: str) -> str:
    try:
        payload = json.loads(stdout or "[]")
    except json.JSONDecodeError:
        return "unknown"

    items: list[dict[str, Any]] = []

    def collect(node: Any, parent_name: str | None = None) -> None:
        if isinstance(node, list):
            for item in node:
                collect(item, parent_name)
            return

        if isinstance(node, dict):
            if node.get("name") and isinstance(node.get("categories"), list):
                items.append({"name": node["name"], "categories": node.get("categories", [])})
                return

            if parent_name and isinstance(node.get("categories"), list):
                items.append({"name": parent_name, "categories": node.get("categories", [])})
                return

            for key, value in node.items():
                if key in {"name", "version", "confidence", "categories", "groups"}:
                    continue
                collect(value, parent_name=key)

    collect(payload)

    categorized: list[str] = []
    for item in items:
        name = item.get("name")
        categories = item.get("categories", []) or []
        if not name:
            continue

        category_names = []
        for category in categories:
            if isinstance(category, dict):
                category_name = category.get("name")
                if category_name:
                    category_names.append(category_name)
            elif isinstance(category, str):
                category_names.append(category)
        if category_names:
            category = category_names[0]
            label = CATEGORY_LABELS.get(category.lower(), category)
            categorized.append(f"{label}: {name}")
        else:
            categorized.append(name)

    return " | ".join(categorized) if categorized else "unknown"


def _parse_webanalyze_technology(stdout: str) -> str:
    """Parse webanalyze output handling multiple JSON response formats.
    
    Supports:
    - JSONL format (one JSON object per line)
    - Dict responses with 'matches' key
    - List responses with match objects
    - Dict responses where keys are app names (e.g., {"WordPress": {"version": "5.8"}})
    - Both 'app_name' and 'name' field names
    """
    try:
        if not stdout.strip():
            return "unknown"

        techs: list[str] = []

        # Handle JSONL format (one JSON object per line, from crawling multiple URLs)
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue

            matches = []

            # Handle dict response with 'matches' key
            if isinstance(payload, dict):
                matches = payload.get("matches", [])
                if isinstance(matches, list) and matches:
                    # Has matches key with content - use as-is
                    pass
                elif not matches:
                    # No matches key or empty matches list - try other formats
                    # Might be: {"app_name": {"version": "1.0"}, ...} format
                    for key, value in payload.items():
                        if key not in {"hostname", "url", "matches", "status"}:
                            if isinstance(value, dict) and ("version" in value or "categories" in value):
                                # This is {"WordPress": {"version": "5.8"}} format
                                version = value.get("version", "")
                                version_str = f" ({version})" if version else ""
                                tech_str = f"{key}{version_str}"
                                if tech_str not in techs:
                                    techs.append(tech_str)
                            elif isinstance(value, dict):
                                # Generic dict - might be a match object without explicit wrapper
                                matches.append(value)
                            elif isinstance(value, str):
                                # Simple string value = technology name
                                matches.append({"app_name": key, "name": value})

            # Handle list response (array of matches directly)
            elif isinstance(payload, list):
                matches = payload

            # Extract technologies from matches
            for match in matches:
                if not isinstance(match, dict):
                    if isinstance(match, str):
                        # Handle simple string entries
                        if match not in techs:
                            techs.append(match)
                    continue

                # Try multiple field names for app name
                app_name = (
                    match.get("app_name")
                    or match.get("name")
                    or match.get("technology")
                    or match.get("app")
                )

                if not app_name:
                    continue

                version = match.get("version") or ""
                version_str = f" ({version})" if version else ""
                tech_str = f"{app_name}{version_str}"

                # Avoid duplicates
                if tech_str not in techs:
                    techs.append(tech_str)

        return " | ".join(techs) if techs else "unknown"
    except Exception:
        return "unknown"


def _fetch_http_headers(target: str, timeout: int) -> dict[str, str]:
    try:
        request = urllib.request.Request(target, method="GET")
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return {key: value for key, value in response.headers.items()}
    except Exception:
        return {}


def _infer_host_fallback(host: str) -> str | None:
    host = host.lower().strip()
    if not host:
        return None

    if host.endswith(".google.com") or host.endswith(".googleusercontent.com"):
        if "docs" in host:
            return "Google Docs"
        if "drive" in host:
            return "Google Drive"
        if "sites" in host:
            return "Google Sites"
        if "cloud" in host:
            return "Google Cloud"
        if "spreadsheets" in host:
            return "Google Spreadsheets"
        if "corp.google.com" in host or "google.com" in host:
            return "Google Workspace"

    if "googleapis.com" in host:
        return "Google APIs"
    if "appengine.google.com" in host:
        return "Google App Engine"
    if "cloud.google.com" in host:
        return "Google Cloud"
    if host.endswith(".corp.google.com"):
        return "Google Internal Service"
    return None


def _discover_single_technology(
    host: str,
    httpx_bin: str,
    webanalyze_bin: str,
    timeout: int,
    webanalyze_timeout: int,
) -> dict[str, str]:
    target = _normalize_target(host)
    httpx_technology = "unknown"
    webanalyze_technology = "unknown"
    httpx_failed = False

    # HTTPX detection (required)
    command = [httpx_bin, "-silent", "-json", "-tech-detect", target]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        # Check if httpx found the host by looking at output
        if completed.returncode == 0 and completed.stdout.strip():
            httpx_technology = _parse_httpx_technology(completed.stdout)
        else:
            httpx_failed = True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        httpx_failed = True

    # Webanalyze detection (optional - requires technologies.json)
    if webanalyze_bin:
        command = [webanalyze_bin, "-host", target, "-output", "json", "-crawl", "0", "-silent"]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=webanalyze_timeout,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            webanalyze_technology = "unknown"
        else:
            stderr_msg = getattr(completed, "stderr", "")
            if completed.returncode == 0 and "can not open apps file" not in stderr_msg and completed.stdout.strip():
                webanalyze_technology = _parse_webanalyze_technology(completed.stdout)

    # Fallback to HTTP headers if httpx empty
    if httpx_technology == "unknown" and httpx_failed:
        headers = _fetch_http_headers(target, timeout)
        if headers:
            parsed_headers = _parse_httpx_headers(headers)
            httpx_technology = " | ".join(parsed_headers) if parsed_headers else "unknown"

    # Fallback to hostname inference if both empty
    if httpx_technology == "unknown" and webanalyze_technology == "unknown":
        host_fallback = _infer_host_fallback(host)
        if host_fallback:
            httpx_technology = host_fallback

    # Only show "unknown" if we actually tried and failed, not just as a default
    # For unreachable hosts, provide a minimal but honest report
    if httpx_technology == "unknown" and webanalyze_technology == "unknown":
        # Host likely doesn't exist or is unreachable
        httpx_technology = "unreachable"
    elif httpx_technology == "unknown":
        # Webanalyze found something but httpx didn't
        httpx_technology = "no fingerprint matched"
    elif webanalyze_technology == "unknown":
        # HTTPX found something but webanalyze didn't - this is normal for many sites
        webanalyze_technology = "no fingerprint matched"

    # Combine results - always show HTTPX and Webanalyze
    parts = [
        f"HTTPX: {httpx_technology}",
        f"Webanalyze: {webanalyze_technology}",
    ]
    technology = " | ".join(parts)
    return {"host": host, "technology": technology}


from modules.utils import load_hosts_from_output


def discover_technologies(hosts: list[str], config: dict[str, Any]) -> list[dict[str, str]]:
    """Discover technologies for hosts with true parallel batch processing.
    
    Args:
        hosts: List of hosts to scan for technologies
        config: Configuration dict with tools, timeouts, and batching settings
        
    Returns:
        List of dicts with 'host' and 'technology' keys, in original order
    """
    output_path = Path(config.get("output", {}).get("technologies", "output/technologies.txt"))
    output_path.parent.mkdir(parents=True, exist_ok=True)

    target_hosts = [host.strip() for host in hosts if host and host.strip()]
    if not target_hosts:
        target_hosts = load_hosts_from_output(config, "live_hosts", "output/live_hosts.txt")

    if not target_hosts:
        output_path.write_text("", encoding="utf-8")
        return []

    tools = config.get("tools", {})
    httpx_bin = tools.get("httpx", "httpx")
    webanalyze_bin = tools.get("webanalyze", "webanalyze")
    
    timeout = config.get("timeouts", {}).get("httpx", 30)
    webanalyze_timeout = config.get("timeouts", {}).get("webanalyze", timeout)
    
    batching = config.get("batching", {})
    batch_size = max(1, int(batching.get("batch_size", 50)))
    workers = max(1, int(batching.get("workers", 4)))

    # Calculate effective worker count: scale workers by batch groups
    num_batches = max(1, (len(target_hosts) + batch_size - 1) // batch_size)
    effective_workers = min(workers * num_batches, len(target_hosts))
    effective_workers = max(1, effective_workers)

    technologies_by_host = {}

    # Submit all hosts to thread pool at once for true parallelization
    # This allows the thread pool to process all hosts concurrently
    with ThreadPoolExecutor(max_workers=effective_workers) as executor:
        # Submit all tasks upfront - this is key to true parallelization
        futures = {
            executor.submit(
                _discover_single_technology,
                host,
                httpx_bin,
                webanalyze_bin,
                timeout,
                webanalyze_timeout,
            ): host
            for host in target_hosts
        }

        # Collect results as they complete
        for future in as_completed(futures):
            result = future.result()
            technologies_by_host[result["host"]] = result

    # Rebuild results in original host order
    technologies = [technologies_by_host[host] for host in target_hosts if host in technologies_by_host]

    output_path.write_text(
        "\n".join(f"{item['host']}:{item['technology']}" for item in technologies) + "\n",
        encoding="utf-8",
    )
    return technologies
