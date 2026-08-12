from __future__ import annotations

import ipaddress
import json
import random
import re
import shutil
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
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


def _extract_product_version(extra_info: str) -> tuple[str | None, str | None, str | None]:
    """Convert trailing service text like 'nginx 1.25.5' into product/version fields."""
    text = (extra_info or "").strip()
    if not text:
        return None, None, None

    match = re.match(r"^(?P<product>.+?)\s+(?P<version>v?\d[\w.+-]*)(?:\s+(?P<extra>.*))?$", text)
    if not match:
        return None, None, None

    product = (match.group("product") or "").strip()
    version = (match.group("version") or "").strip()
    extra = (match.group("extra") or "").strip()
    if not product or not version:
        return None, None, None
    return product, version, extra or None


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
    fingerprint_pattern = re.compile(r"^fingerprint-strings", re.IGNORECASE)
    response_header_pattern = re.compile(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", re.IGNORECASE)
    service_info_pattern = re.compile(r"^Service Info:\s*(.+)$")
    host_info_pattern = re.compile(
        r"^(OS details|Aggressive OS guesses|Network Distance|Device type|Service detection performed|Service Info|CPE):\s*(.+)$"
    )

    def _append_detail(base: str, detail: str) -> str:
        if not base:
            return detail
        return f"{base}; {detail}"

    skip_fingerprint = False
    for line in stdout.splitlines():
        stripped = line.strip()
        report = report_pattern.match(stripped)
        if report:
            current_host = _host(report.group(1)) or default_host
            last_result_index = None
            skip_fingerprint = False
            continue

        match = port_pattern.match(stripped)
        if match:
            skip_fingerprint = False
            state = match.group(3)
            if "open" not in state:
                continue
            host_value = _display_host(current_host, aliases, aggregate_results, preserve_aliases)
            service_name = match.group(4)
            extra_info = (match.group(5) or "").strip()
            product, version, trailing = _extract_product_version(extra_info)
            item: dict[str, Any] = {
                "host": host_value,
                "port": match.group(1),
                "service": service_name,
                "service_name": service_name,
            }
            if product:
                item["product"] = product
            if version:
                item["version"] = version
            if trailing:
                item["extrainfo"] = trailing
            if extra_info and not product and not version:
                item["service"] = f"{service_name} {extra_info}"
            else:
                item["service"] = _build_service_summary(item)
            results.append(item)
            last_result_index = len(results) - 1
            continue

        if line.startswith("|") and last_result_index is not None:
            script_text = line[1:]
            indent = len(script_text) - len(script_text.lstrip(" "))
            script_info = script_text.strip()
            if skip_fingerprint and indent > 0:
                continue
            if fingerprint_pattern.match(script_info):
                skip_fingerprint = True
                continue
            skip_fingerprint = False
            if response_header_pattern.match(script_info):
                response_match = response_header_pattern.match(script_info)
                if response_match:
                    existing_service = results[last_result_index].get("service", "")
                    results[last_result_index]["service"] = _append_detail(existing_service, f"status={response_match.group(1)}")
                continue
            detail_match = script_detail_pattern.match(script_info)
            if detail_match:
                key = detail_match.group(1).strip().lower()
                value = detail_match.group(2).strip()
                if key in {"http-title", "http-server-header", "server", "location", "ssl-cert", "tls-alpn"}:
                    safe_key = "server" if key == "http-server-header" else key
                    existing_service = results[last_result_index].get("service", "")
                    results[last_result_index]["service"] = _append_detail(existing_service, f"{safe_key}: {value}")
                continue
            continue

        service_info = service_info_pattern.match(stripped)
        if service_info and last_result_index is not None:
            info = service_info.group(1).strip()
            if info:
                existing_service = results[last_result_index].get("service", "")
                results[last_result_index]["service"] = _append_detail(existing_service, info)
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


def _format_nmap_script_element(element: ET.Element, prefix: str = "") -> list[str]:
    lines: list[str] = []
    if element.tag == "elem":
        key = element.get("key", "")
        text = (element.text or "").strip()
        if key and text:
            lines.append(f"{prefix}{key}: {text}")
        elif key:
            lines.append(f"{prefix}{key}")
        elif text:
            lines.append(f"{prefix}{text}")
    elif element.tag == "table":
        title = element.get("key", "")
        if title:
            lines.append(f"{prefix}{title}:")
        for child in element:
            lines.extend(_format_nmap_script_element(child, prefix + "  "))
    else:
        for child in element:
            lines.extend(_format_nmap_script_element(child, prefix))
    return lines


def _format_nmap_script(script: ET.Element) -> list[str]:
    lines: list[str] = []
    script_id = script.get("id", "")
    output = (script.get("output") or "").strip()
    if script_id and output:
        lines.append(f"{script_id}: {output}")
    elif script_id:
        lines.append(script_id)
    elif output:
        lines.extend(output.splitlines())
    for child in script:
        lines.extend(_format_nmap_script_element(child))
    return lines


def _format_nmap_script_element_structure(element: ET.Element) -> dict[str, Any]:
    result: dict[str, Any] = {
        "tag": element.tag,
        "key": element.get("key", ""),
        "text": (element.text or "").strip(),
        "attributes": element.attrib.copy(),
        "children": [],
    }
    for child in element:
        result["children"].append(_format_nmap_script_element_structure(child))
    return result


def _parse_nmap_script_data(script: ET.Element) -> dict[str, Any]:
    return {
        "id": script.get("id", ""),
        "category": script.get("category", ""),
        "output": (script.get("output") or "").strip(),
        "structure": [_format_nmap_script_element_structure(child) for child in script],
    }


def _parse_nmap_script_lines(
    lines: list[str],
    item: dict[str, Any],
    raw_fingerprint: list[str],
    script_id: str = "",
) -> None:
    skip_fingerprint = False
    for line in lines:
        if not line:
            continue
        if line.startswith(" "):
            if skip_fingerprint:
                raw_fingerprint.append(line.strip())
                continue
            line = line.strip()
        else:
            skip_fingerprint = False

        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if key.lower() == "fingerprint-strings":
            raw_fingerprint.append(line)
            skip_fingerprint = True
            continue
        if key == script_id and not value:
            continue
        if script_id == "http-headers":
            header_match = re.match(r"^([^:]+):\s*(.*)$", line)
            if header_match:
                headers = item.setdefault("http_headers", {})
                headers[header_match.group(1).strip()] = header_match.group(2).strip()
            continue
        if script_id == "http-methods":
            method = line.strip()
            if method:
                item.setdefault("http_methods", []).append(method)
            continue
        if script_id == "http-robots.txt":
            robots = item.setdefault("robots", {"disallow": [], "allow": [], "sitemap": []})
            robot_match = re.match(r"^(Disallow|Allow|Sitemap):\s*(.*)$", line, re.IGNORECASE)
            if robot_match:
                field = robot_match.group(1).strip().lower()
                value = robot_match.group(2).strip()
                if field == "disallow":
                    robots["disallow"].append(value)
                elif field == "allow":
                    robots["allow"].append(value)
                else:
                    robots["sitemap"].append(value)
            continue
        if script_id == "http-security-headers":
            header_match = re.match(r"^([^:]+):\s*(.*)$", line)
            if header_match:
                headers = item.setdefault("security_headers", {})
                headers[header_match.group(1).strip()] = header_match.group(2).strip()
            continue
        if script_id == "ssl-enum-ciphers":
            if line.endswith(":"):
                item.setdefault("ssl_ciphers", []).append({"protocol": line[:-1].strip(), "details": []})
                continue
            if item.get("ssl_ciphers"):
                cipher_block = item["ssl_ciphers"][-1]
                cipher_block.setdefault("details", []).append(line.strip())
            continue
        if script_id == "ssh-hostkey":
            hostkey = item.setdefault("ssh_hostkey", {})
            ssh_match = re.match(r"^([^:]+):\s*(.*)$", line)
            if ssh_match:
                hostkey[ssh_match.group(1).strip()] = ssh_match.group(2).strip()
            else:
                hostkey.setdefault("raw", []).append(line.strip())
            continue
        if script_id == "ssl-cert":
            cert = item.setdefault("ssl", {})
            if line.startswith("ssl-cert:"):
                raw = line.partition(":")[2].strip()
                cert.setdefault("summary", []).append(raw)
                continue
            cert_match = re.match(r"^([^:]+):\s*(.*)$", line)
            if cert_match:
                cert[cert_match.group(1).strip()] = cert_match.group(2).strip()
            else:
                cert.setdefault("other", []).append(line.strip())
            continue
        if key == "http-title":
            item.setdefault("title", value)
            continue
        if key == "http-server-header" or key.lower() == "server":
            item.setdefault("server", value)
            continue
        if key.lower() == "location":
            item.setdefault("redirect", value)
            continue
        if key.startswith("HTTP/"):
            parts = key.split()
            if len(parts) >= 2 and parts[1].isdigit():
                item.setdefault("status", parts[1])
            continue
        if key == "ssl-cert":
            item.setdefault("ssl", {})["ssl-cert"] = value
            continue
        if key == "tls-alpn":
            item.setdefault("ssl", {})["tls-alpn"] = value
            continue
        if key == "ssl-enum-ciphers":
            item.setdefault("ssl", {})["ssl-enum-ciphers"] = value
            continue
        if key and value:
            item.setdefault("scripts", {}).setdefault(key, []).append(value)
        elif key:
            item.setdefault("scripts", {}).setdefault(key, []).append("")


def _build_service_summary(item: dict[str, Any]) -> str:
    service_name = item.get("service_name") or item.get("service") or "unknown"
    if service_name == "unknown" and isinstance(item.get("port"), str):
        if item["port"] == "443":
            service_name = "https"
        elif item["port"] == "80":
            service_name = "http"

    parts: list[str] = [service_name] if service_name else []
    if item.get("product"):
        parts.append(item["product"])
    if item.get("version"):
        parts.append(item["version"])
    if item.get("extrainfo"):
        parts.append(f"Extra Info: {item['extrainfo']}")
    if item.get("title"):
        parts.append(f"title={item['title']}")
    if item.get("server"):
        parts.append(f"server={item['server']}")
    if item.get("status"):
        parts.append(f"status={item['status']}")
    if item.get("redirect"):
        parts.append(f"redirect={item['redirect']}")
    if item.get("confidence"):
        parts.append(f"confidence={item['confidence']}")

    headers = item.get("http_headers")
    if isinstance(headers, dict) and headers:
        header_parts = [f"{k}: {v}" for k, v in headers.items() if v]
        if header_parts:
            parts.append(f"headers={'; '.join(header_parts)}")

    methods = item.get("http_methods")
    if isinstance(methods, list) and methods:
        parts.append(f"methods={', '.join(methods)}")

    security_headers = item.get("security_headers")
    if isinstance(security_headers, dict) and security_headers:
        header_parts = [f"{k}: {v}" for k, v in security_headers.items() if v]
        if header_parts:
            parts.append(f"security_headers={'; '.join(header_parts)}")

    robots = item.get("robots")
    if isinstance(robots, dict):
        robot_bits: list[str] = []
        for key in ("disallow", "allow", "sitemap"):
            values = robots.get(key) or []
            if isinstance(values, list) and values:
                robot_bits.append(f"{key}:{';'.join(values)}")
        if robot_bits:
            parts.append(f"robots={'; '.join(robot_bits)}")

    cpe = item.get("cpe")
    if isinstance(cpe, list) and cpe:
        parts.append(f"cpe={';'.join(cpe)}")

    rpc = item.get("rpc")
    if isinstance(rpc, dict) and rpc:
        rpc_bits = [f"{k}: {v}" for k, v in rpc.items() if v]
        if rpc_bits:
            parts.append(f"rpc={'; '.join(rpc_bits)}")

    ssl = item.get("ssl")
    if isinstance(ssl, dict):
        for name, value in ssl.items():
            if not value:
                continue
            if name == "ssl-cert":
                parts.append(f"ssl-cert: {value}")
            elif name == "summary":
                parts.extend([f"ssl-cert: {line}" for line in value])
            elif isinstance(value, list):
                parts.append(f"{name}: {value}")
            else:
                parts.append(f"{name}: {value}")
    if item.get("service_notes"):
        parts.extend(item["service_notes"])
    return "; ".join(parts) if parts else "unknown"


def _parse_nmap_xml(
    xml_path: Path,
    default_host: str,
    aliases: dict[str, str] | None = None,
    aggregate_results: list[dict[str, str]] | None = None,
    preserve_aliases: bool = False,
) -> list[dict[str, str]]:
    try:
        tree = ET.parse(xml_path)
    except (ET.ParseError, OSError):
        return []

    root = tree.getroot()
    results: list[dict[str, str]] = []
    for host in root.findall("host"):
        host_candidate = default_host
        for hostname in host.findall("hostnames/hostname"):
            candidate = hostname.get("name", "")
            normalized = _host(candidate)
            if normalized:
                host_candidate = normalized
                break

        host_display = _display_host(host_candidate, aliases, aggregate_results, preserve_aliases)
        host_meta: list[str] = []
        distance = host.find("distance")
        if distance is not None and distance.get("value"):
            host_meta.append(f"Network Distance: {distance.get('value')}")

        os_node = host.find("os")
        if os_node is not None:
            osmatch = os_node.find("osmatch")
            if osmatch is not None and osmatch.get("name"):
                host_meta.append(f"OS: {osmatch.get('name')}")
            osclass = os_node.find("osclass")
            if osclass is not None:
                device_type = osclass.get("type")
                osfamily = osclass.get("osfamily")
                vendor = osclass.get("vendor")
                osgen = osclass.get("osgen")
                class_parts = [part for part in (vendor, osfamily, osgen) if part]
                if device_type:
                    host_meta.append(f"Device Type: {device_type}")
                if class_parts:
                    host_meta.append(" ".join(class_parts))

        mac_vendor = None
        for address in host.findall("address"):
            if address.get("addrtype") == "mac" and address.get("vendor"):
                mac_vendor = address.get("vendor")
                break
        if mac_vendor:
            host_meta.append(f"MAC Vendor: {mac_vendor}")

        host_status = host.find("status")
        if host_status is not None:
            status_state = host_status.get("state")
            if status_state:
                host_meta.append(f"Host status: {status_state}")
            status_reason = host_status.get("reason")
            if status_reason:
                host_meta.append(f"Host reason: {status_reason}")
            status_ttl = host_status.get("reason_ttl")
            if status_ttl:
                host_meta.append(f"Host reason ttl: {status_ttl}")

        uptime_node = host.find("uptime")
        if uptime_node is not None:
            uptime_seconds = uptime_node.get("seconds")
            lastboot = uptime_node.get("lastboot")
            if uptime_seconds:
                host_meta.append(f"Uptime seconds: {uptime_seconds}")
            if lastboot:
                host_meta.append(f"Uptime lastboot: {lastboot}")

        hostnames: list[str] = []
        for hostname in host.findall("hostnames/hostname"):
            name = hostname.get("name", "")
            if name:
                hostnames.append(name)

        ipv6_addresses: list[str] = []
        for address in host.findall("address"):
            if address.get("addrtype") == "ipv6" and address.get("addr"):
                ipv6_addresses.append(address.get("addr"))

        hostscript = host.find("hostscript")
        host_script_lines: list[str] = []
        if hostscript is not None:
            for script in hostscript.findall("script"):
                script_lines = _format_nmap_script(script)
                host_script_lines.extend(script_lines)

        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            port_id = port.get("portid", "")
            service_node = port.find("service")
            service_name = (service_node.get("name") if service_node is not None else None) or "unknown"
            confidence = service_node.get("conf") if service_node is not None else None
            tunnel = service_node.get("tunnel") if service_node is not None else None
            servicefp = service_node.get("servicefp") if service_node is not None else None
            if tunnel and service_name and not service_name.startswith(f"{tunnel}/"):
                service_name = f"{tunnel}/{service_name}"
            cpe_list: list[str] = []
            product = None
            version = None
            extrainfo = None
            if service_node is not None:
                product = service_node.get("product")
                version = service_node.get("version")
                extrainfo = service_node.get("extrainfo")
                for cpe in service_node.findall("cpe"):
                    cpe_text = (cpe.text or "").strip()
                    if cpe_text:
                        cpe_list.append(cpe_text)

            rpc_info: dict[str, str] = {}
            rpc_node = service_node.find("rpc") if service_node is not None else None
            if rpc_node is not None:
                rpc_info.update(rpc_node.attrib)
            else:
                for tag in ("rpcnum", "lowver", "highver"):
                    child = service_node.find(tag) if service_node is not None else None
                    if child is not None and (child.text or "").strip():
                        rpc_info[tag] = child.text.strip()

            item: dict[str, Any] = {
                "host": host_display,
                "hostnames": hostnames,
                "ipv6_addresses": ipv6_addresses,
                "port": port_id,
                "service_name": service_name,
                "product": product,
                "version": version,
                "extrainfo": extrainfo,
                "confidence": confidence,
                "tunnel": tunnel,
                "servicefp": servicefp,
                "rpc": rpc_info if rpc_info else None,
                "cpe": cpe_list,
                "reason": state.get("reason") if state is not None else None,
                "reason_ttl": state.get("reason_ttl") if state is not None else None,
                "port_state": state.get("state") if state is not None else None,
                "ssl": {},
                "scripts": {},
                "nse_scripts": [],
                "host_meta": host_meta.copy(),
                "host_scripts": host_script_lines.copy(),
                "raw_fingerprint": [],
            }
            if uptime_node is not None:
                item["uptime_seconds"] = uptime_seconds
                item["uptime_lastboot"] = lastboot
            if host_status is not None:
                item["host_status"] = host_status.get("state")
                item["host_status_reason"] = host_status.get("reason")
                item["host_status_reason_ttl"] = host_status.get("reason_ttl")

            for script in host.findall("hostscript/script"):
                script_lines = _format_nmap_script(script)
                item["nse_scripts"].append(_parse_nmap_script_data(script))
                _parse_nmap_script_lines(script_lines, item, item["raw_fingerprint"], script.get("id", ""))

            for script in port.findall("script"):
                script_lines = _format_nmap_script(script)
                item["nse_scripts"].append(_parse_nmap_script_data(script))
                _parse_nmap_script_lines(script_lines, item, item["raw_fingerprint"], script.get("id", ""))

            if host_meta:
                item["service_notes"] = host_meta.copy()
            if host_script_lines:
                item.setdefault("service_notes", []).extend(host_script_lines)

            item["service"] = _build_service_summary(item)
            results.append(item)

    return results


def _write_results(output_path: Path, ports: list[dict[str, str]]) -> None:
    if not ports:
        output_path.write_text("No open ports discovered.\n", encoding="utf-8")
        return

    sections: list[str] = ["Open Ports", "==========", ""]
    for item in ports:
        host = item.get("host", "unknown")
        port = item.get("port", "unknown")
        service = item.get("service", "unknown")
        sections.append(f"- {host}:{port} -> {service}")
    sections.append("")
    output_path.write_text("\n".join(sections), encoding="utf-8")


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
        # Use Nmap on the ports discovered by Naabu, not a full 65535-port scan.
        raw_dir = Path("logs")
        raw_dir.mkdir(parents=True, exist_ok=True)
        safe_host = host.replace("/", "_").replace(":", "_").replace(".", "_")
        xml_path = raw_dir / f"nmap_{safe_host}_{'_'.join(ports)}.xml"
        script_list = (
            "default,safe,version,discovery,ssl-cert,ssl-enum-ciphers,http-title,http-headers,"  # noqa: E501
            "http-server-header,http-enum,banner,http-methods,http-security-headers,http-robots.txt,"  # noqa: E501
            "http-auth,ssh-hostkey,ssl-dh-params,tls-nextprotoneg,http-generator,http-favicon,http-cookie-flags"
        )
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
            "-oX",
            str(xml_path),
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

    parsed = []
    if xml_path.exists():
        parsed = _parse_nmap_xml(xml_path, host, aliases, aggregate_results, preserve_aliases)
    if not parsed:
        parsed = _parse_nmap(result.stdout, host, aliases, aggregate_results, preserve_aliases)
    if result.returncode not in {0, 1}:
        return parsed or _unknown_results(host, ports, aliases, aggregate_results, preserve_aliases)

    raw_fingerprint_lines: list[str] = []
    for item in parsed:
        if isinstance(item, dict):
            raw_fingerprint_lines.extend(item.get("raw_fingerprint", []))
    if raw_fingerprint_lines:
        try:
            raw_dir = Path("logs")
            raw_dir.mkdir(parents=True, exist_ok=True)
            raw_fingerprint_path = raw_dir / f"nmap_raw_fingerprint_{safe_host}_{'_'.join(ports)}.txt"
            raw_fingerprint_path.write_text("\n".join(raw_fingerprint_lines) + "\n", encoding="utf-8")
        except Exception:
            pass

    # If Nmap produced only minimal service strings (like just 'http'/'https' or 'unknown'),
    # save the raw Nmap stdout/stderr for debugging and deeper offline inspection.
    def _is_minimal(s: str) -> bool:
        low = (s or "").lower()
        if not low or low == "unknown":
            return True
        # if there's no detail like ';' or '/' in the service string, treat as minimal
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


def _merge_results(existing: list[dict[str, Any]], incoming: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for item in existing + incoming:
        key = (item["host"], item["port"])
        if key not in merged:
            merged[key] = dict(item)
            continue

        current_service = merged[key].get("service", "")
        candidate_service = item.get("service", "")
        if _service_is_richer(candidate_service, current_service):
            merged[key] = dict(item)
        elif current_service == "unknown" and candidate_service != "unknown":
            merged[key] = dict(item)
    return sorted(merged.values(), key=lambda item: (item["host"], int(item["port"])))


def _drop_http_redirects(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Prefer HTTPS when the same host redirects from HTTP to HTTPS."""
    by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in results:
        by_host[str(item.get("host", ""))].append(item)

    filtered: list[dict[str, Any]] = []
    for host, host_items in by_host.items():
        https_ports = {item.get("port") for item in host_items if item.get("port") == "443"}
        if not https_ports:
            filtered.extend(host_items)
            continue

        for item in host_items:
            port = str(item.get("port") or "")
            redirect = str(item.get("redirect") or "").strip()
            if port == "80" and redirect.lower().startswith("https://"):
                continue
            filtered.append(item)

    return sorted(filtered, key=lambda item: (item["host"], int(item.get("port", "0") or 0)))


def _probe_httpx(host: str, port: str, httpx_bin: str, timeout: int) -> dict[str, str]:
    """Use httpx to probe a host:port and return structured details."""
    if not shutil.which(httpx_bin):
        return {}
    scheme = "https" if port == "443" else "http"
    url = f"{scheme}://{host}:{port}"
    details: dict[str, str] = {}
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
            status = (
                str(payload.get("status_code") or payload.get("status-code") or payload.get("status") or "")
            )
            redirect = payload.get("redirect_url") or payload.get("redirect") or ""
            if title:
                details["title"] = title
            if server:
                details["server"] = server
            if status:
                details["status"] = status
            if redirect:
                details["redirect"] = redirect
            if details:
                return details

    return details


def _probe_web_service(host: str, port: str, httpx_bin: str | None, curl_bin: str | None, timeout: int) -> dict[str, str]:
    """Probe a web port using httpx when available, otherwise curl."""
    if httpx_bin and shutil.which(httpx_bin):
        detail = _probe_httpx(host, port, httpx_bin, timeout)
        if detail:
            return detail

    if curl_bin and shutil.which(curl_bin):
        scheme = "https" if port == "443" else "http"
        url = f"{scheme}://{host}:{port}"
        details: dict[str, str] = {}
        try:
            head = subprocess.run(
                [curl_bin, "-sS", "-k", "-I", "-m", str(timeout), url],
                capture_output=True,
                text=True,
                check=False,
            )
            if head and head.stdout:
                for hline in head.stdout.splitlines():
                    if hline.lower().startswith("server:"):
                        details["server"] = hline.split(":", 1)[1].strip()
                    if hline.startswith("HTTP/"):
                        fields = hline.split()
                        if len(fields) >= 2:
                            details["status"] = fields[1]
                    if hline.lower().startswith("location:"):
                        details["redirect"] = hline.split(":", 1)[1].strip()
            body = subprocess.run(
                [curl_bin, "-sS", "-k", "-L", "-r", "0-8191", "-m", str(timeout), url],
                capture_output=True,
                text=True,
                check=False,
            )
            if body and body.stdout:
                m = re.search(r"<title[^>]*>(.*?)</title>", body.stdout, re.IGNORECASE | re.DOTALL)
                if m:
                    title = m.group(1).strip()
                    if title:
                        details["title"] = title
        except Exception:
            return {}
        return details

    return {}


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

    httpx_bin = tools.get("httpx")
    curl_bin = tools.get("curl", "curl")
    httpx_timeout = max(5, int(timeouts.get("httpx", 60)))

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
        curl_bin = tools.get("curl", "curl")
        if curl_bin and shutil.which(curl_bin):
            for item in deduped_results:
                if item.get("port") in {"80", "443"} and (item.get("service") == "unknown" or _needs_httpx_enrichment(item.get("service", ""))):
                    detail = _probe_web_service(_host(item["host"]), item["port"], httpx_bin, curl_bin, httpx_timeout)
                    if detail:
                        item.update(detail)
                        item["service"] = _build_service_summary(item)
        deduped_results = _drop_http_redirects(deduped_results)
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
    # Respect configured Nmap timeout (in seconds). Allow longer scans by default.
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

    # Enrich HTTP/HTTPS results with httpx or curl when available.
    if httpx_bin and shutil.which(httpx_bin) or (curl_bin and shutil.which(curl_bin)):
        for item in list(results):
            try:
                port = item.get("port")
                if port in {"80", "443"}:
                    existing_service = item.get("service", "")
                    if _needs_httpx_enrichment(existing_service) or existing_service == "unknown":
                        detail = _probe_web_service(_host(item["host"]), port, httpx_bin, curl_bin, httpx_timeout)
                        if detail:
                            item.update(detail)
                            item["service"] = _build_service_summary(item)
            except Exception:
                # Non-fatal enrichment error; continue
                continue

    # Preserve all discovered results from Naabu and overlay Nmap service identifications.
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

    # Ensure any richer Nmap-derived detail replaces the provisional Naabu service name.
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

    # Fill in HTTP/HTTPS unknowns with httpx or curl when available.
    if httpx_bin and shutil.which(httpx_bin) or (curl_bin and shutil.which(curl_bin)):
        for item in final_results:
            if item.get("port") in {"80", "443"} and (item.get("service") == "unknown" or _needs_httpx_enrichment(item.get("service", ""))):
                try:
                    detail = _probe_web_service(_host(item["host"]), item["port"], httpx_bin, curl_bin, httpx_timeout)
                    if detail:
                        item.update(detail)
                        item["service"] = _build_service_summary(item)
                except Exception:
                    continue

    deduped_results = _drop_http_redirects(final_results)
    processed_hosts.update(targets)
    if aggregate_results is not None:
        aggregate_results[:] = _merge_results(aggregate_results, deduped_results)
        _write_results(output_path, aggregate_results)
        logger.info("Identified %d open host-port combinations across %d hosts", len(aggregate_results), len(discovered))
        return aggregate_results
    _write_results(output_path, deduped_results)
    logger.info("Identified %d open host-port combinations across %d hosts", len(deduped_results), len(discovered))
    return deduped_results
