from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    import dns.exception
    import dns.resolver
except ImportError:  # pragma: no cover - optional dependency fallback
    dns = None

from modules.utils import load_hosts_from_output


# ---------------------------------------------------------------------------
# Host / domain helpers
# ---------------------------------------------------------------------------

def _normalize_host(host: str) -> str:
    """
    Convert a host/URL into a normalized hostname.

    Examples:
        https://mail.example.com/       -> mail.example.com
        http://www.example.com:443      -> www.example.com
        example.com                     -> example.com
    """
    value = (host or "").strip().rstrip("/")

    if not value:
        return ""

    try:
        parsed = urlparse(
            value if "://" in value else f"//{value}"
        )
        hostname = parsed.hostname

        if hostname:
            return hostname.strip().rstrip(".").lower()

    except ValueError:
        pass

    # Fallback
    value = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", value)
    value = value.split("/", 1)[0]
    value = value.split(":", 1)[0]

    return value.strip().rstrip(".").lower()


def _extract_policy(record_text: str, parameter: str = "p") -> str:
    """
    Extract a DMARC tag.

    Example:
        v=DMARC1;p=reject;sp=quarantine

        _extract_policy(record, "p")  -> reject
        _extract_policy(record, "sp") -> quarantine
    """
    if not record_text:
        return ""

    for part in record_text.split(";"):
        cleaned = part.strip()

        if not cleaned:
            continue

        if "=" not in cleaned:
            continue

        key, value = cleaned.split("=", 1)

        if key.strip().lower() == parameter.lower():
            return value.strip().lower()

    return ""


def _is_dmarc_record(record: str) -> bool:
    """
    Verify that a TXT record is actually a DMARC record.
    """
    if not record:
        return False

    normalized = record.replace('"', "").strip().lower()

    return (
        normalized.startswith("v=dmarc1")
        or normalized.startswith("v=dmarc1;")
    )


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

def _query_txt_records(domain: str) -> list[str]:
    """
    Query TXT records for _dmarc.<domain>.

    Uses dnspython when available.

    Falls back to nslookup when dnspython is unavailable.
    """
    domain = _normalize_host(domain)

    if not domain:
        return []

    dmarc_domain = f"_dmarc.{domain}"

    # -----------------------------------------------------------------------
    # Preferred: dnspython
    # -----------------------------------------------------------------------

    if dns is not None:
        try:
            resolver = dns.resolver.Resolver()

            answers = resolver.resolve(
                dmarc_domain,
                "TXT",
                lifetime=5,
            )

            records: list[str] = []

            for rdata in answers:
                try:
                    # dnspython can return TXT strings as:
                    # "v=DMARC1" "p=reject"
                    chunks = getattr(rdata, "strings", None)

                    if chunks:
                        record = "".join(
                            chunk.decode("utf-8", errors="ignore")
                            if isinstance(chunk, bytes)
                            else str(chunk)
                            for chunk in chunks
                        )
                    else:
                        record = rdata.to_text()

                    record = record.strip().strip('"')

                    if record:
                        records.append(record)

                except Exception:
                    continue

            return records

        except (
            dns.exception.DNSException,
            AttributeError,
            OSError,
        ):
            return []

    # -----------------------------------------------------------------------
    # Fallback: nslookup
    # -----------------------------------------------------------------------

    nslookup = shutil.which("nslookup")

    if not nslookup:
        return []

    try:
        completed = subprocess.run(
            [
                nslookup,
                "-type=TXT",
                dmarc_domain,
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )

    except (
        OSError,
        subprocess.SubprocessError,
    ):
        return []

    output = (
        completed.stdout or ""
    ) + "\n" + (
        completed.stderr or ""
    )

    records: list[str] = []

    # Handle normal nslookup output such as:
    #
    # _dmarc.example.com text =
    #     "v=DMARC1;p=reject;sp=reject"

    for line in output.splitlines():

        line = line.strip()

        if not line:
            continue

        # Direct quoted line
        if line.startswith('"') and line.endswith('"'):
            record = line.strip('"').strip()

            if record:
                records.append(record)

            continue

        # Extract quoted content
        matches = re.findall(
            r'"([^"]+)"',
            line,
        )

        for match in matches:
            record = match.strip()

            if record:
                records.append(record)

    return records


def _get_dmarc_record(domain: str) -> str:
    """
    Return the first valid DMARC TXT record for a domain.
    """
    records = _query_txt_records(domain)

    for record in records:
        if _is_dmarc_record(record):
            return record

    return ""


# ---------------------------------------------------------------------------
# Organizational domain
# ---------------------------------------------------------------------------

def _derive_root_domain(hosts: list[str]) -> str:
    """
    Derive a probable organizational domain from the supplied hosts.

    This is intentionally conservative and aims to handle the common cases in
    this project:

        www.example.org         -> example.org
        mail.example.org        -> example.org
        mail.pha.org.pk         -> pha.org.pk
        mail.example.co.uk      -> example.co.uk
    """
    normalized = [
        _normalize_host(host)
        for host in hosts
        if _normalize_host(host)
    ]

    if not normalized:
        return ""

    # Single-host case: infer the parent domain rather than returning the
    # subdomain itself when a hostname such as www.example.org is supplied.
    if len(normalized) == 1:
        host = normalized[0]
        labels = host.split(".")

        if len(labels) <= 2:
            return host

        multi_tld_suffixes = {
            "ac.uk",
            "co.uk",
            "com.au",
            "com.pk",
            "gov.uk",
            "org.pk",
            "org.uk",
        }

        last_two = ".".join(labels[-2:])
        if last_two in multi_tld_suffixes and len(labels) >= 3:
            return ".".join(labels[-3:])

        return ".".join(labels[-2:])

    labels_by_host = [
        host.split(".")
        for host in normalized
    ]

    # If all hosts are exactly the same domain.
    if all(host == normalized[0] for host in normalized):
        return _derive_root_domain([normalized[0]])

    # Find the common suffix across multiple hosts.
    common_suffix: list[str] = []

    min_labels = min(
        len(labels)
        for labels in labels_by_host
    )

    for index in range(1, min_labels + 1):
        current_label = labels_by_host[0][-index]

        if all(
            labels[-index] == current_label
            for labels in labels_by_host
        ):
            common_suffix.insert(0, current_label)
        else:
            break

    if len(common_suffix) >= 2:
        return ".".join(common_suffix)

    return _derive_root_domain([normalized[0]])


# ---------------------------------------------------------------------------
# DMARC policy evaluation
# ---------------------------------------------------------------------------

def _policy_type_for(policy: str) -> str:
    normalized = (policy or "none").lower()

    if normalized == "none":
        return "MONITORING"
    if normalized in {"quarantine", "reject"}:
        return "ENFORCEMENT"
    return "UNKNOWN"


def _format_policy_source(source_type: str, policy_source: str) -> str:
    source_label = (source_type or "none").upper()
    policy_label = (policy_source or "none").upper()

    if source_label == "NONE" or policy_label == "NONE":
        return "NONE"

    return f"{source_label} {policy_label}"


def _assessment_for(policy: str) -> str:
    normalized = (policy or "none").lower()

    if normalized == "none":
        return (
            "DMARC is configured, but the policy is set to NONE. "
            "The domain is monitoring DMARC failures without requesting "
            "quarantine or rejection."
        )
    if normalized == "quarantine":
        return "DMARC is configured with a quarantine policy."
    if normalized == "reject":
        return "DMARC is configured with a reject policy."
    return "DMARC is configured with an unknown policy."


def _check_dmarc_for_domain(
    host: str,
    root_domain: str | None = None,
) -> dict[str, str]:

    domain = _normalize_host(host)

    if not domain:
        return {
            "host": host,
            "domain": "",
            "status": "invalid",
            "policy": "none",
            "source": "none",
            "source_type": "none",
            "policy_source": "none",
            "source_domain": "",
            "dmarc_record": "none",
        }

    # -----------------------------------------------------------------------
    # 1. Direct DMARC record
    #
    # Example:
    #
    # _dmarc.mail.example.com
    # -----------------------------------------------------------------------

    direct_record = _get_dmarc_record(domain)

    if direct_record:

        policy = _extract_policy(
            direct_record,
            "p",
        )

        if policy not in {
            "none",
            "quarantine",
            "reject",
        }:
            policy = "unknown"

        return {
            "host": host,
            "domain": domain,
            "status": "configured",
            "policy": policy,
            "source": domain,
            "source_type": "direct",
            "policy_source": "p",
            "source_domain": domain,
            "dmarc_record": direct_record,
        }

    # -----------------------------------------------------------------------
    # 2. Organizational/root domain
    #
    # Example:
    #
    # _dmarc.example.com
    #
    # applies to:
    #
    # mail.example.com
    # www.example.com
    # etc.
    # -----------------------------------------------------------------------

    if root_domain:
        root_domain = _normalize_host(root_domain)

    if (
        root_domain
        and domain != root_domain
    ):

        root_record = _get_dmarc_record(root_domain)

        if root_record:

            # DMARC subdomain policy.
            #
            # If sp= exists, it controls subdomains.
            # Otherwise p= is used.
            subdomain_policy = _extract_policy(
                root_record,
                "sp",
            )

            if subdomain_policy:

                policy = subdomain_policy
                policy_source = "sp"

            else:

                policy = _extract_policy(
                    root_record,
                    "p",
                )

                policy_source = "p"

            if policy not in {
                "none",
                "quarantine",
                "reject",
            }:
                policy = "unknown"

            return {
                "host": host,
                "domain": domain,
                "status": "inherited",
                "policy": policy,
                "source": root_domain,
                "source_type": "organizational",
                "policy_source": policy_source,
                "source_domain": root_domain,
                "dmarc_record": root_record,
            }

    # -----------------------------------------------------------------------
    # 3. No DMARC record
    # -----------------------------------------------------------------------

    return {
        "host": host,
        "domain": domain,
        "status": "missing",
        "policy": "none",
        "source": "none",
        "source_type": "none",
        "policy_source": "none",
        "source_domain": "",
        "dmarc_record": "none",
    }


# ---------------------------------------------------------------------------
# Main discovery function
# ---------------------------------------------------------------------------

def discover_dmarc(
    hosts: list[str],
    config: dict[str, Any],
) -> list[dict[str, str]]:

    project_root = Path(__file__).resolve().parents[1]

    # -----------------------------------------------------------------------
    # Output path
    # -----------------------------------------------------------------------

    output_path = Path(
        config.get(
            "output",
            {},
        ).get(
            "dmarc",
            "output/dmarc.txt",
        )
    )

    if not output_path.is_absolute():
        output_path = (
            project_root / output_path
        ).resolve()

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    # -----------------------------------------------------------------------
    # Get hosts
    # -----------------------------------------------------------------------

    target_hosts = [
        host.strip()
        for host in hosts
        if host and host.strip()
    ]

    # If hosts were not passed to the function,
    # read live_hosts.txt.
    if not target_hosts:

        target_hosts = load_hosts_from_output(
            config,
            "live_hosts",
            "output/live_hosts.txt",
        )

    # -----------------------------------------------------------------------
    # Normalize and deduplicate
    # -----------------------------------------------------------------------

    normalized_hosts: list[str] = []

    seen_hosts: set[str] = set()

    for host in target_hosts:

        normalized = _normalize_host(host)

        if not normalized:
            continue

        if normalized in seen_hosts:
            continue

        seen_hosts.add(normalized)

        normalized_hosts.append(normalized)

    # -----------------------------------------------------------------------
    # No hosts
    # -----------------------------------------------------------------------

    if not normalized_hosts:

        output_path.write_text(
            "DMARC Findings\n"
            "==============\n\n"
            "No hosts found.\n",
            encoding="utf-8",
        )

        return []

    # -----------------------------------------------------------------------
    # Determine organizational/root domain
    # -----------------------------------------------------------------------

    root_domain = _derive_root_domain(
        normalized_hosts
    )

    # -----------------------------------------------------------------------
    # Scan
    # -----------------------------------------------------------------------

    results: list[dict[str, str]] = []

    for host in normalized_hosts:

        result = _check_dmarc_for_domain(
            host,
            root_domain=root_domain,
        )

        results.append(result)

    # -----------------------------------------------------------------------
    # Generate output
    # -----------------------------------------------------------------------

    configured_count = sum(
        1 for item in results if item.get("status") == "configured"
    )
    inherited_count = sum(
        1 for item in results if item.get("status") == "inherited"
    )
    missing_count = sum(
        1 for item in results if item.get("status") == "missing"
    )
    unknown_count = sum(
        1 for item in results if item.get("status") in {"invalid", "unknown"}
    )

    sections: list[str] = [
        "DMARC SECURITY FINDINGS",
        "=======================",
        f"Total Hosts Checked : {len(results)}",
        f"Organizational Domain : {root_domain or 'unknown'}",
        f"Hosts with DMARC    : {configured_count + inherited_count}",
        f"Hosts without DMARC : {missing_count + unknown_count}",
        "------------------------------------------------------------",
    ]

    for item in results:
        host = item.get("host", "unknown")
        status = (item.get("status") or "missing").upper()
        policy = (item.get("policy") or "none").upper()
        source = item.get("source_domain") or item.get("source") or "NONE"
        record = item.get("dmarc_record") or "NONE"

        if item.get("status") in {"missing", "invalid"}:
            details = (
                f"No DMARC record was found for this host or the "
                f"organizational domain {root_domain or 'unknown'}."
            )
            sections.extend(
                [
                    "",
                    "[LOW] DMARC Policy Missing",
                    f"Host        : {host}",
                    f"Status      : {status}",
                    f"Policy      : {policy}",
                    "Source      : NONE",
                    "Record      : NONE",
                    f"Description : {details}",
                    "------------------------------------------------------------",
                ]
            )
            continue

        source_type = (item.get("source_type") or "none").upper()
        policy_source = (item.get("policy_source") or "none").upper()
        policy_type = _policy_type_for(policy)
        policy_source_label = _format_policy_source(item.get("source_type"), item.get("policy_source"))
        assessment = _assessment_for(policy)

        sections.extend(
            [
                "",
                "[INFO] DMARC Policy Present",
                f"Host        : {host}",
                f"Status      : {status}",
                f"Policy      : {policy}",
                f"Policy Type : {policy_type}",
                f"Source      : {source}",
                f"Source Type : {source_type}",
                f"Policy Source: {policy_source_label}",
                f"Record      : {record}",
                f"Assessment  : {assessment}",
                "------------------------------------------------------------",
            ]
        )

    if root_domain:
        has_configured_dmarc = configured_count + inherited_count > 0
        has_missing_dmarc = missing_count + unknown_count > 0

        if has_missing_dmarc and not has_configured_dmarc:
            sections.extend(
                [
                    "",
                    "RECOMMENDATION",
                    "--------------",
                    f"No DMARC record was found for the organizational domain {root_domain}.",
                    "Consider publishing a DMARC TXT record at:",
                    f"_dmarc.{root_domain}",
                ]
            )
        elif has_configured_dmarc:
            inherited_policy = ""

            for item in results:
                if item.get("status") in {"inherited", "configured"}:
                    policy_source = item.get("policy_source") or ""
                    if policy_source:
                        inherited_policy = policy_source
                        break

            if inherited_policy == "sp":
                subdomain_note = (
                    f"Subdomains without their own DMARC record inherit the subdomain policy (sp={(item.get('policy') or 'none').lower()})."
                )
            else:
                subdomain_note = (
                    f"Subdomains without their own DMARC record inherit the organizational-domain policy."
                )

            sections.extend(
                [
                    "",
                    "RECOMMENDATION",
                    "--------------",
                    f"DMARC is configured for the organizational domain {root_domain}.",
                    subdomain_note,
                ]
            )

    # -----------------------------------------------------------------------
    # Write file
    # -----------------------------------------------------------------------

    output_path.write_text(
        "\n".join(sections).rstrip() + "\n",
        encoding="utf-8",
    )

    return results