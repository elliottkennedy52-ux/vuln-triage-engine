from pathlib import Path

from triage_engine import calculate_priority, triage_nessus_csv


def test_kev_production_gets_p1_emergency():
    priority, sla, score = calculate_priority(cvss=9.8, in_kev=True, asset_tier="Production")
    assert priority == "P1 - EMERGENCY"
    assert sla == "24 Hours"
    assert score == 99


def test_sample_nessus_triage_ranking():
    report = triage_nessus_csv(
        Path("samples/nessus_scan_export.csv"),
        Path("samples/cisa_kev_catalog.json"),
    )
    assert report["total_findings"] == 6
    assert report["cisa_kev_matches"] == 3
    assert report["p1_emergency_tickets"] == 2
    assert report["prioritized_queue"][0]["cve"] == "CVE-2024-3400"
