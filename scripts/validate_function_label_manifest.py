#!/usr/bin/env python3
"""Validate independently annotated function/span labels for PRISM.

The existing corpus labels are contract-derived.  This validator deliberately
rejects that provenance: its input is only for blinded human annotations and
their adjudications.  It validates source locations before such labels can be
used for a function-level evaluation.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
REQUIRED_COLUMNS = {
    "contract_id",
    "source_path",
    "function_signature",
    "start_line",
    "end_line",
    "decision",
    "vulnerability_class",
    "label_source",
    "annotator_id",
    "adjudication_status",
}
VALID_DECISIONS = {"vulnerable", "safe", "uncertain"}
VALID_SOURCES = {"independent_manual", "joint_adjudication", "expert_semantic_review", "provisional_expert_review"}
VALID_ADJUDICATIONS = {"pending", "agreed", "adjudicated", "reviewed"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="CSV following data/function_labels/README.md")
    parser.add_argument("--output", type=Path, help="Optional JSON validation report")
    parser.add_argument(
        "--require-final",
        action="store_true",
        help="Fail pending/uncertain rows; use before reporting function-level metrics.",
    )
    return parser.parse_args()


def source_for(row: dict[str, str]) -> Path:
    candidate = Path(row["source_path"])
    return candidate if candidate.is_absolute() else ROOT / candidate


def main() -> int:
    args = parse_args()
    with args.manifest.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        columns = set(reader.fieldnames or [])
        missing = REQUIRED_COLUMNS - columns
        if missing:
            raise SystemExit(f"Missing required columns: {', '.join(sorted(missing))}")
        rows = list(reader)

    errors: list[dict[str, object]] = []
    keys: set[tuple[str, str, str, str]] = set()
    per_status: Counter[str] = Counter()
    per_decision: Counter[str] = Counter()
    for line_number, row in enumerate(rows, start=2):
        def error(message: str) -> None:
            errors.append({"line": line_number, "contract_id": row.get("contract_id"), "error": message})

        if row["decision"] not in VALID_DECISIONS:
            error(f"decision must be one of {sorted(VALID_DECISIONS)}")
        if row["label_source"] not in VALID_SOURCES:
            error(
                "label_source must be independent_manual or joint_adjudication; "
                "contract-derived labels are intentionally invalid here"
            )
        if row["adjudication_status"] not in VALID_ADJUDICATIONS:
            error(f"adjudication_status must be one of {sorted(VALID_ADJUDICATIONS)}")
        if not row["annotator_id"].strip():
            error("annotator_id is required for provenance")
        if not row["vulnerability_class"].strip() and row["decision"] == "vulnerable":
            error("vulnerability_class is required for a vulnerable decision")

        try:
            start, end = int(row["start_line"]), int(row["end_line"])
        except ValueError:
            error("start_line and end_line must be integers")
            continue
        if start < 1 or end < start:
            error("source span must satisfy 1 <= start_line <= end_line")
        source = source_for(row)
        if not source.is_file():
            error(f"source_path does not exist: {row['source_path']}")
        elif end > len(source.read_text(encoding="utf-8").splitlines()):
            error(f"end_line {end} exceeds source length")

        key = (row["contract_id"], row["function_signature"], row["annotator_id"], row["decision"])
        if key in keys:
            error("duplicate contract/function/annotator/decision row")
        keys.add(key)
        per_status[row["adjudication_status"]] += 1
        per_decision[row["decision"]] += 1

        if args.require_final and row["adjudication_status"] == "pending":
            error("pending row is not eligible for final metrics")
        if args.require_final and row["decision"] == "uncertain":
            error("uncertain row is not eligible for final metrics")

    try:
        manifest_rel = str(args.manifest.resolve().relative_to(ROOT))
    except ValueError:
        manifest_rel = str(args.manifest)

    report = {
        "manifest": manifest_rel,
        "row_count": len(rows),
        "valid": not errors,
        "decisions": dict(per_decision),
        "adjudication_statuses": dict(per_status),
        "errors": errors,
        "scope": "Independent function/span annotations only; contract-derived labels are rejected.",
    }
    print(json.dumps(report, indent=2))
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
