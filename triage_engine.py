#!/usr/bin/env python3
"""
Nessus & CISA KEV Vulnerability Triage Engine
Correlates Nessus CSV vulnerability scan exports with CISA Known Exploited Vulnerabilities (KEV),
CVSS v3 scores, and asset criticality tiers to assign risk-based remediation SLAs.
"""

import argparse
import csv
import json
from pathlib import Path


def load_kev_catalog(kev_path: Path) -> dict[str, dict]:
    data = json.loads(kev_path.read_text(encoding="utf-8"))
    return {
        item["cveID"].strip().upper(): item
        for item in data.get("vulnerabilities", [])
        if item.get("cveID")
    }


def calculate_priority(cvss: float, in_kev: bool, asset_tier: str) -> tuple[str, str, int]:
    tier = asset_tier.strip().lower()
    prod_bonus = 15 if tier == "production" else (5 if tier == "staging" else 0)
    kev_bonus = 35 if in_kev else 0
    composite = min(100, round(cvss * 5 + kev_bonus + prod_bonus))

    if in_kev and tier == "production":
        return "P1 - EMERGENCY", "24 Hours", composite
    if in_kev or (cvss >= 9.0 and tier == "production"):
        return "P2 - URGENT", "7 Days", composite
    if cvss >= 7.0:
        return "P3 - HIGH", "30 Days", composite
    return "P4 - STANDARD", "90 Days", composite


def triage_nessus_csv(csv_path: Path, kev_path: Path) -> dict:
    kev_map = load_kev_catalog(kev_path)
    tickets: list[dict] = []

    with csv_path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            cve = row.get("CVE", "").strip().upper()
            cvss = float(row.get("CVSS v3.0 Base Score") or 0.0)
            host = row.get("Host", "unknown-host").strip()
            asset_tier = row.get("Asset Tier", "Internal").strip()
            title = row.get("Name", "Unnamed Finding").strip()
            plugin_id = row.get("Plugin ID", "0").strip()

            kev_entry = kev_map.get(cve)
            in_kev = kev_entry is not None
            priority, sla, risk_score = calculate_priority(cvss, in_kev, asset_tier)

            tickets.append({
                "priority": priority,
                "sla_window": sla,
                "composite_risk_score": risk_score,
                "cve": cve or "N/A",
                "cisa_kev": in_kev,
                "ransomware_linked": kev_entry.get("knownRansomwareCampaignUse", "Unknown") if kev_entry else "No",
                "cvss_v3": cvss,
                "host": host,
                "asset_tier": asset_tier,
                "plugin_id": plugin_id,
                "vulnerability": title,
            })

    tickets.sort(key=lambda t: (-t["composite_risk_score"], -t["cvss_v3"]))

    p1_count = sum(1 for t in tickets if t["priority"].startswith("P1"))
    kev_count = sum(1 for t in tickets if t["cisa_kev"])

    return {
        "source_scan": csv_path.name,
        "total_findings": len(tickets),
        "cisa_kev_matches": kev_count,
        "p1_emergency_tickets": p1_count,
        "prioritized_queue": tickets,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prioritize Nessus CSV scan findings using CISA KEV, CVSS v3, and asset criticality."
    )
    parser.add_argument(
        "-f", "--file",
        default="samples/nessus_scan_export.csv",
        help="Path to Nessus CSV export (default: samples/nessus_scan_export.csv)",
    )
    parser.add_argument(
        "-k", "--kev",
        default="samples/cisa_kev_catalog.json",
        help="Path to CISA KEV JSON catalog (default: samples/cisa_kev_catalog.json)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Optional output path to save prioritized JSON remediation queue",
    )
    args = parser.parse_args()

    report = triage_nessus_csv(Path(args.file), Path(args.kev))
    print(json.dumps(report, indent=2))
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\n[+] Remediation queue saved to {args.output}")


if __name__ == "__main__":
    main()
