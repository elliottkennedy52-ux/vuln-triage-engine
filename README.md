[![Python CI](https://github.com/elliottkennedy52-ux/vuln-triage-engine/actions/workflows/python-ci.yml/badge.svg)](https://github.com/elliottkennedy52-ux/vuln-triage-engine/actions/workflows/python-ci.yml)

# Nessus & CISA KEV Vulnerability Triage Engine

Zero-dependency Python CLI vulnerability management engine that ingests **Nessus CSV scan exports**, correlates CVEs against the **CISA Known Exploited Vulnerabilities (KEV)** catalog, weighs **CVSS v3** severity and asset criticality (`Production`, `Staging`, `Internal`, `Lab`), and generates SLA-prioritized remediation queues.

## SLA Prioritization Matrix
- **P1 - EMERGENCY (24 Hours):** Active CISA KEV exploit on a `Production` asset
- **P2 - URGENT (7 Days):** Active CISA KEV exploit on non-production OR `CVSS >= 9.0` on `Production`
- **P3 - HIGH (30 Days):** High-severity findings (`CVSS 7.0 - 8.9`)
- **P4 - STANDARD (90 Days):** Medium/Low findings (`CVSS < 7.0`)

## Quick Start
```bash
python3 triage_engine.py -f samples/nessus_scan_export.csv -k samples/cisa_kev_catalog.json
python3 triage_engine.py -f samples/nessus_scan_export.csv -o queue.json
```
