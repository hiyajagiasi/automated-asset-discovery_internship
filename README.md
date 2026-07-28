# Automated Asset Discovery and Reconnaissance Framework

## Overview

`Automated-Asset-Discovery` is a Python-based reconnaissance automation framework designed to centralize asset discovery, live host validation, port scanning, technology fingerprinting, and reporting. It integrates open-source tools into a modular workflow, producing structured outputs in `output/`, `reports/`, and `logs/` directories.

## Workflow

The current workflow is live-host-driven and consists of:

1. Subdomain discovery
2. Live host probing and validation
3. Port scanning and service identification
4. Technology detection from validated live hosts
5. Report generation in HTML and Excel

This workflow ensures that later analysis stages use only confirmed live HTTP/S hosts, not raw unresolved candidates.

## Key Files

- `main.py` — entry point for the automation workflow
- `config.yaml` — tool paths, timeouts, batch settings, and output file paths
- `requirements.txt` — Python dependency list
- `README.md` — project overview and documentation
- `modules/` — core reconnaissance and report generation logic
- `output/` — raw scan outputs such as `live_hosts.txt`, `ports.txt`, and `technologies.txt`
- `reports/` — generated HTML report files
- `logs/` — execution logs and error tracing

## Core Modules

### `modules/recon_service.py`

- Orchestrates the full workflow
- Loads configuration and logging
- Executes discovery stages in order
- Uses live host output as the source for technology and security stages
- Generates HTML and Excel reports from collected results

### `modules/subdomain.py`

- Discovers candidate hostnames for a target domain
- Writes raw subdomain candidates to `output/subdomains.txt`

### `modules/live_hosts.py`

- Probes candidate hosts with `httpx`
- Optionally resolves candidates with `dnsx` first
- Writes validated live HTTP/S hosts to `output/live_hosts.txt`
- Supports batching and rate-limited concurrency for reliability

### `modules/port_scan.py`

- Scans validated live hosts for open ports using `naabu` and `nmap`
- Writes results to `output/ports.txt`

### `modules/technology.py`

- Identifies technologies from validated live hosts
- Uses HTTP responses, headers, and fingerprinting tools such as `webanalyze`
- Produces normalized technology output in `output/technologies.txt`

### `modules/report_html.py`

- Builds a consumable HTML report from scan results

### `modules/report_excel.py`

- Builds an Excel workbook from scan results

### `modules/utils.py`

- Loads YAML configuration
- Creates directories
- Provides logging and validation helpers

## Configuration

The workflow is configured through `config.yaml`.

### Example settings

- Tool binaries: `subfinder`, `dnsx`, `httpx`, `naabu`, `nmap`, `whatweb`, `webanalyze`
- Output files:
  - `output/subdomains.txt`
  - `output/live_hosts.txt`
  - `output/ports.txt`
  - `output/technologies.txt`
- Timeouts for tool execution
- HTTPX tuning for thread count, timeout, retries, and streaming
- DNSX options for resolution validation
- Batch size and worker settings for stable concurrent processing

## Tool Roles

- `subfinder` — subdomain enumeration
- `dnsx` — DNS resolution and candidate filtering
- `httpx` — live HTTP/S host validation and response collection
- `naabu` — fast TCP port scanning
- `nmap` — service and port fingerprinting
- `whatweb` — web technology fingerprinting
- `webanalyze` — app/framework fingerprinting from headers and content

## Technology Detection

Technology discovery is intentionally driven by confirmed live hosts. This means:

- Only validated `output/live_hosts.txt` entries are used for fingerprinting
- Technology analysis is performed on hosts that responded over HTTP/S
- This improves accuracy and avoids wasted scans on dead or unresolved hosts

## Project Structure

```text
Automated-Asset-Discovery/
  main.py
  config.yaml
  requirements.txt
  README.md
  modules/
    __init__.py
    live_hosts.py
    port_scan.py
    recon_service.py
    report_excel.py
    report_html.py
    subdomain.py
    technology.py
    utils.py
  templates/
  reports/
  output/
  logs/
```

## Notes

- The current implementation emphasizes live-host-driven analysis.
- Technology and downstream stages consume `output/live_hosts.txt` rather than raw subdomain candidates.
- The repository is designed for extension, including additional security scanning and vulnerability assessment phases.

```

---

## Chapter 14

### Module Description

#### main.py

Controls the entire workflow.

Responsibilities:

- Read configuration
- Accept user input
- Execute modules
- Generate reports
- Save logs

#### subdomain.py

Responsibilities:

- Validate domain
- Execute Subfinder
- Save output
- Return list

#### live_hosts.py

Responsibilities:

- Verify responding hosts
- Store live hosts
- Remove inactive hosts

#### port_scan.py

Responsibilities:

- Identify open ports
- Parse scan results
- Save output

#### technology.py

Responsibilities:

- Identify technologies
- Parse results
- Store technologies

#### report_html.py

Responsibilities:

- Create HTML report
- Render Jinja2 template

#### report_excel.py

Responsibilities:

- Create Excel workbook
- Multiple worksheets
- Summary page

#### utils.py

Contains helper functions.

Examples:

- Logger
- Validation
- Directory creation
- Command execution

---

## Chapter 15

### Reconnaissance Tools

| Tool | Purpose |
| --- | --- |
| Subfinder | Passive subdomain discovery |
| HTTPX | Live host verification |
| Naabu | Fast port identification |
| Nmap | Service identification |
| WhatWeb | Technology fingerprinting |
| DNSx | DNS information |
| Katana | URL crawling |
| Nuclei | Future enhancement |

---

## Chapter 16

### Python Libraries

- subprocess
- pathlib
- logging
- argparse
- concurrent.futures
- pandas
- openpyxl
- yaml
- jinja2
- rich

---

## Chapter 17

### Configuration

config.yaml stores:

- Tool paths
- Output directories
- Timeouts
- Thread count
- Report options

---

## Chapter 18

### Logging

The framework records:

- Start time
- End time
- Errors
- Executed modules
- Scan duration

Log file:

```text
logs/scan.log
```

---

## Chapter 19

### Report Generation

#### HTML

Contains:

- Summary
- Tables
- Statistics
- Technologies
- Ports
- Hosts

#### Excel

Worksheets:

- Summary
- Subdomains
- Hosts
- Ports
- Services
- Technologies

---

## Chapter 20

### Output Files

```text
reports/

report.html

report.xlsx

output/

subdomains.txt

live_hosts.txt

ports.txt

technologies.txt
```

---

## Chapter 21

### Implementation

Workflow:

1. Read configuration
2. Validate target
3. Execute reconnaissance modules
4. Process results
5. Generate reports
6. Save logs

---

## Chapter 22

### Error Handling

The framework handles:

- Missing tools
- Invalid domains
- Command failures
- Timeouts
- Empty results
- Report generation errors

---

## Chapter 23

### Testing

Test Cases:

- Valid domain
- Invalid domain
- Missing Subfinder
- Missing HTTPX
- Empty response
- Report generation
- Excel generation

---

## Chapter 24

### Results

Generated Files:

- HTML Report
- Excel Report
- Log File
- Raw Outputs

Performance:

- Faster execution
- Organized reporting
- Reduced manual effort

---

## Chapter 25

### Advantages

- Automation
- Modular architecture
- Easy maintenance
- Professional reports
- Cross-platform compatibility
- Extensible design
- Better productivity

---

## Chapter 26

### Limitations

- Requires installed third-party tools.
- Depends on publicly available data sources.
- Internet connectivity is required for passive data collection.
- Results are limited by the accuracy and availability of external reconnaissance sources.

---

## Chapter 27

### Future Enhancements

- Database integration
- Dashboard
- Docker support
- Scheduled scans
- Historical comparison
- REST API
- Authentication
- PDF reports
- Notifications
- Additional authorized assessment modules

---

## Chapter 28

### Conclusion

The Automated Asset Discovery and Reconnaissance Framework simplifies the collection and organization of asset information for authorized security assessments. By automating multiple stages of asset discovery and generating structured reports, it reduces manual effort, improves consistency, and provides a scalable foundation for future enhancements. Its modular design makes it suitable for academic projects, internships, and defensive security operations where proper authorization has been obtained.

---

## Chapter 29

### References

1. Python Official Documentation
2. ProjectDiscovery Documentation (Subfinder, HTTPX, Naabu, DNSx, Nuclei)
3. Nmap Official Documentation
4. WhatWeb Documentation
5. Jinja2 Documentation
6. OpenPyXL Documentation
7. Pandas Documentation
8. OWASP Web Security Testing Guide (WSTG)
