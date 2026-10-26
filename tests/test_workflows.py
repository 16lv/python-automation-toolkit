from __future__ import annotations

import json
from pathlib import Path

from src.automation_toolkit.workflows import (
    AuditLedger,
    sanitize_and_export_csv,
    scan_duplicates,
)


def test_two_stage_duplicate_scanner_identifies_identical_payloads(tmp_path: Path) -> None:
    ledger = AuditLedger(":memory:")

    (tmp_path / "alpha.txt").write_bytes(b"cardiff-university-software-engineering-2026")
    (tmp_path / "beta_copy.txt").write_bytes(b"cardiff-university-software-engineering-2026")
    (tmp_path / "unique.txt").write_bytes(b"distinct-payload")

    report = scan_duplicates(tmp_path, ledger=ledger)
    assert report.scanned_files == 3
    assert report.unique_hashes == 2
    assert len(report.duplicate_groups) == 1
    assert report.duplicate_groups[0].reclaimable_bytes == 44

    runs = ledger.list_runs()
    assert len(runs) == 1
    assert runs[0]["workflow_type"] == "deduplicate_scan"


def test_csv_sanitizer_filters_invalid_rows_and_deduplicates(tmp_path: Path) -> None:
    ledger = AuditLedger(":memory:")
    csv_file = tmp_path / "applicants.csv"
    out_json = tmp_path / "out" / "cleaned.json"

    csv_file.write_text(
        "id,email,module\n"
        "101, alice@cardiff.ac.uk ,CM2104\n"
        "102,ALICE@cardiff.ac.uk,CM2104\n"
        "103,,CM2104\n"
        "104,bob@cardiff.ac.uk,CM2208\n",
        encoding="utf-8",
    )

    report = sanitize_and_export_csv(
        input_csv=csv_file,
        output_json=out_json,
        required_fields=["id", "email", "module"],
        dedupe_key="email",
        ledger=ledger,
    )

    assert report.input_rows == 4
    assert report.valid_rows == 2
    assert report.rejected_rows == 1
    assert report.duplicates_removed == 1

    exported = json.loads(out_json.read_text(encoding="utf-8"))
    assert len(exported) == 2
    assert exported[0]["email"] == "alice@cardiff.ac.uk"
