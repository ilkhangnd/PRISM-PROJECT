#!/usr/bin/env python3
"""Create blinded reviewer packets for independent function/span annotation.

Only source paths are read from ground_truth_57.json. Contract-level labels,
categories, and SWC identifiers are intentionally never written to a reviewer
packet. The adjudicator key contains the original path but no label and must
not be distributed to annotators.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import re
import sys
from pathlib import Path
from typing import Iterator


ROOT = Path(__file__).resolve().parent.parent
GROUND_TRUTH = ROOT / "data" / "ground_truth_57.json"
WORKSHEET_COLUMNS = [
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
    "evidence",
]
FUNCTION_START = re.compile(
    r"^\s*(?:(function|modifier)\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)|(constructor|fallback|receive)\s*\(([^)]*)\))"
)
LINE_COMMENT = re.compile(r"//[^\n]*")
BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="Empty directory for the packet")
    parser.add_argument("--reviewers", nargs="+", default=["annotator_A", "annotator_B"])
    parser.add_argument("--limit", type=int, help="Optional number of contracts for a pilot subset")
    parser.add_argument("--shuffle-seed", type=int, default=20260928, help="Fixed seed used only to blind manifest order")
    return parser.parse_args()


def strip_comments(source: str) -> str:
    """Remove comments while preserving newline positions for source spans."""
    source = BLOCK_COMMENT.sub(lambda match: "\n" * match.group(0).count("\n"), source)
    return LINE_COMMENT.sub("", source)


def mask_source(source: str) -> str:
    from src.security.data_masking import DataMasker

    masker = DataMasker(config={"mask_function_names": True, "mask_variable_names": True, "mask_contract_names": True})
    return strip_comments(masker.mask_source(source))


def callable_regions(source: str) -> Iterator[tuple[str, int, int]]:
    """Yield approximate callable spans; the reviewer verifies the final span."""
    lines = source.splitlines()
    for index, line in enumerate(lines):
        matched = FUNCTION_START.match(line)
        if not matched:
            continue
        kind, name, params, special, special_params = matched.groups()
        label = f"{name}({params.strip()})" if kind else f"{special}({special_params.strip()})"
        brace_depth = line.count("{") - line.count("}")
        end = index
        while brace_depth > 0 and end + 1 < len(lines):
            end += 1
            brace_depth += lines[end].count("{") - lines[end].count("}")
        yield label, index + 1, end + 1


def write_csv(path: Path, columns: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    args = parse_args()
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        raise SystemExit(f"Refusing to overwrite a non-empty output directory: {output}")
    if args.limit is not None and args.limit < 1:
        raise SystemExit("--limit must be positive")
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))

    entries = json.loads(GROUND_TRUTH.read_text(encoding="utf-8"))
    # Never preserve corpus ordering: it may itself encode safe/vulnerable
    # groups even when the label columns are withheld from reviewers.
    random.Random(args.shuffle_seed).shuffle(entries)
    if args.limit:
        entries = entries[: args.limit]
    output.mkdir(parents=True, exist_ok=True)
    sources_dir = output / "sources"
    sources_dir.mkdir()
    reviewer_rows: list[dict[str, str]] = []
    adjudicator_rows: list[dict[str, str]] = []

    for number, entry in enumerate(entries, start=1):
        contract_id = f"R{number:03d}"
        original_path = ROOT / entry["relative_path"]
        if not original_path.is_file():
            raise SystemExit(f"Missing source referenced by manifest: {original_path}")
        blinded_path = sources_dir / f"{contract_id}.sol"
        blinded_path.write_text(mask_source(original_path.read_text(encoding="utf-8")), encoding="utf-8")
        relative_blinded = str(blinded_path.relative_to(ROOT)) if blinded_path.is_relative_to(ROOT) else str(blinded_path)
        for signature, start, end in callable_regions(blinded_path.read_text(encoding="utf-8")):
            reviewer_rows.append(
                {
                    "contract_id": contract_id,
                    "source_path": relative_blinded,
                    "function_signature": signature,
                    "start_line": str(start),
                    "end_line": str(end),
                    "decision": "",
                    "vulnerability_class": "",
                    "label_source": "independent_manual",
                    "annotator_id": "",
                    "adjudication_status": "pending",
                    "evidence": "",
                }
            )
        # The private key maps identity only. It must never add a contract label.
        adjudicator_rows.append(
            {
                "contract_id": contract_id,
                "original_relative_path": entry["relative_path"],
                "source_sha256": hashlib.sha256(original_path.read_bytes()).hexdigest(),
            }
        )

    for reviewer in args.reviewers:
        rows = [dict(row, annotator_id=reviewer) for row in reviewer_rows]
        write_csv(output / f"{reviewer}_worksheet.csv", WORKSHEET_COLUMNS, rows)
    write_csv(output / "ADJUDICATOR_ONLY_identity_key.csv", list(adjudicator_rows[0]) if adjudicator_rows else [], adjudicator_rows)
    (output / "ANNOTATOR_INSTRUCTIONS.md").write_text(
        "# Blinded function-level annotation\n\n"
        "Review only the anonymized `sources/R*.sol` files and your own worksheet. "
        "Do not consult `ground_truth_57.json`, filenames from the original corpus, "
        "or `ADJUDICATOR_ONLY_identity_key.csv`. For each callable region, choose "
        "`vulnerable`, `safe`, or `uncertain`; record the vulnerability class and a short "
        "source-grounded rationale. Keep `label_source=independent_manual`.\n\n"
        "An adjudicator should later reconcile the two completed worksheets into a separate "
        "manifest with `label_source=joint_adjudication` and run "
        "`scripts/validate_function_label_manifest.py --require-final`.\n",
        encoding="utf-8",
    )
    print(json.dumps({"contracts": len(entries), "callable_regions": len(reviewer_rows), "shuffle_seed": args.shuffle_seed, "packet": str(output)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
