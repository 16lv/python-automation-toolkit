from __future__ import annotations

import csv
import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class DuplicateGroup:
    sha256: str
    size_bytes: int
    canonical_path: str
    duplicate_paths: list[str]

    @property
    def reclaimable_bytes(self) -> int:
        return self.size_bytes * len(self.duplicate_paths)


@dataclass(frozen=True)
class DeduplicationReport:
    scanned_files: int
    unique_hashes: int
    duplicate_groups: list[DuplicateGroup]
    total_reclaimable_bytes: int


@dataclass(frozen=True)
class TransformReport:
    input_rows: int
    valid_rows: int
    rejected_rows: int
    duplicates_removed: int
    output_path: str


class AuditLedger:
    """SQLite audit log recording automation runs, file transformations, and deduplication passes."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._conn = sqlite3.connect(str(db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS workflow_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workflow_type TEXT NOT NULL,
                executed_at TEXT NOT NULL,
                processed_items INTEGER NOT NULL,
                affected_items INTEGER NOT NULL,
                details_json TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def record_run(
        self,
        workflow_type: str,
        processed_items: int,
        affected_items: int,
        details: dict[str, Any],
    ) -> int:
        cur = self._conn.execute(
            """
            INSERT INTO workflow_runs (
                workflow_type, executed_at, processed_items, affected_items, details_json
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                workflow_type,
                datetime.now(UTC).isoformat(),
                processed_items,
                affected_items,
                json.dumps(details, sort_keys=True),
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid or 0)

    def list_runs(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM workflow_runs ORDER BY id DESC"
        ).fetchall()
        return [
            {
                "id": r["id"],
                "workflow_type": r["workflow_type"],
                "executed_at": r["executed_at"],
                "processed_items": r["processed_items"],
                "affected_items": r["affected_items"],
                "details": json.loads(r["details_json"]),
            }
            for r in rows
        ]


def compute_sha256(path: Path, chunk_size: int = 65536) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def scan_duplicates(
    root_dir: Path,
    ledger: AuditLedger | None = None,
) -> DeduplicationReport:
    """
    Two-stage duplicate detector:
    1. Groups candidate files by exact byte length (eliminating unique-sized files without hashing).
    2. Computes streaming SHA-256 digests only for size collisions.
    """
    by_size: dict[int, list[Path]] = {}
    scanned = 0

    for entry in sorted(root_dir.rglob("*")):
        if entry.is_file():
            scanned += 1
            size = entry.stat().st_size
            by_size.setdefault(size, []).append(entry)

    by_hash: dict[str, tuple[int, list[Path]]] = {}
    unique_count = 0

    for size, paths in by_size.items():
        if len(paths) == 1:
            unique_count += 1
            continue
        for file_path in paths:
            digest = compute_sha256(file_path)
            if digest not in by_hash:
                by_hash[digest] = (size, [file_path])
            else:
                by_hash[digest][1].append(file_path)

    groups: list[DuplicateGroup] = []
    for digest, (size, paths) in by_hash.items():
        unique_count += 1
        if len(paths) > 1:
            ordered = [str(p) for p in paths]
            groups.append(
                DuplicateGroup(
                    sha256=digest,
                    size_bytes=size,
                    canonical_path=ordered[0],
                    duplicate_paths=ordered[1:],
                )
            )

    total_reclaimable = sum(g.reclaimable_bytes for g in groups)
    report = DeduplicationReport(
        scanned_files=scanned,
        unique_hashes=unique_count,
        duplicate_groups=groups,
        total_reclaimable_bytes=total_reclaimable,
    )

    if ledger is not None:
        ledger.record_run(
            workflow_type="deduplicate_scan",
            processed_items=scanned,
            affected_items=sum(len(g.duplicate_paths) for g in groups),
            details={"reclaimable_bytes": total_reclaimable, "groups": len(groups)},
        )

    return report


def sanitize_and_export_csv(
    input_csv: Path,
    output_json: Path,
    required_fields: list[str],
    dedupe_key: str,
    ledger: AuditLedger | None = None,
) -> TransformReport:
    """
    Streams a CSV dataset, trims whitespace, validates required non-empty fields,
    deduplicates records on a primary key column, and writes deterministic JSON output.
    """
    input_rows = 0
    rejected_rows = 0
    duplicates_removed = 0
    seen_keys: set[str] = set()
    cleaned_records: list[dict[str, str]] = []

    with input_csv.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for raw_row in reader:
            input_rows += 1
            normalized = {
                (k.strip() if k else ""): (v.strip() if v else "")
                for k, v in raw_row.items()
            }
            if any(not normalized.get(field) for field in required_fields):
                rejected_rows += 1
                continue

            key_val = normalized.get(dedupe_key, "").lower()
            if key_val in seen_keys:
                duplicates_removed += 1
                continue

            seen_keys.add(key_val)
            cleaned_records.append(normalized)

    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(
        json.dumps(cleaned_records, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    report = TransformReport(
        input_rows=input_rows,
        valid_rows=len(cleaned_records),
        rejected_rows=rejected_rows,
        duplicates_removed=duplicates_removed,
        output_path=str(output_json),
    )

    if ledger is not None:
        ledger.record_run(
            workflow_type="csv_to_json_sanitize",
            processed_items=input_rows,
            affected_items=len(cleaned_records),
            details={
                "rejected_rows": rejected_rows,
                "duplicates_removed": duplicates_removed,
                "output_path": str(output_json),
            },
        )

    return report
