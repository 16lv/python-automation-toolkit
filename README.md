# Python Automation Toolkit

A deterministic file deduplication, CSV-to-JSON data sanitization, and SQLite audit-logging toolkit built with **Python 3.12**.

## Overview

`python-automation-toolkit` automates two common operational tasks:
1. **Two-Stage Content-Addressable Deduplication:** Scans directory trees by grouping files by byte length first and streaming 64KB SHA-256 chunks only when file sizes collide, avoiding unnecessary disk reads on unique files.
2. **Tabular CSV Sanitization & Deduplication:** Cleans raw CSV exports, strips whitespace, rejects rows missing required schema columns, removes case-insensitive duplicate keys, and emits deterministic sorted JSON alongside an audit entry in SQLite.

## Features

- **Size-Pre-Filtered SHA-256 Deduplicator:** Calculates exact reclaimable bytes and groups duplicate paths against a canonical path.
- **CSV-to-JSON Validation Pipeline:** Enforces required fields and primary-key uniqueness with structured row counts (`input_rows`, `valid_rows`, `rejected_rows`, `duplicates_removed`).
- **SQLite Audit Ledger (`AuditLedger`):** Records every automation execution with UTC timestamps, item counts, and JSON metadata for reproducibility.

## Running Tests & Linter

```bash
ruff check .
pytest -v
```
