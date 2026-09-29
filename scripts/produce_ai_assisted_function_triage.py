#!/usr/bin/env python3
"""Materialize Codex's source-grounded, provisional function-level triage.

This is an AI-assisted semantic review, not independent human ground truth.
It is kept separate from the final-label validator on purpose.  The review is
keyed only by blinded packet IDs and source locations inspected by the agent;
it never reads contract-level labels from ground_truth_57.json.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PACKET = ROOT / "artifacts" / "nss2026" / "function_annotation_packet_v2"

# Source-grounded findings from the semantic review. Keys are (blinded packet
# identifier, start line); all other callable regions are provisionally safe.
FINDINGS: dict[tuple[str, str], tuple[str, str]] = {
    ("R001", "5"): ("integer_overflow", "Arithmetic runs inside unchecked without a balance bound."),
    ("R002", "5"): ("reentrancy", "External call occurs before the caller balance is cleared."),
    ("R003", "4"): ("timestamp_dependence", "Payout branch depends on block.timestamp parity."),
    ("R004", "4"): ("unchecked_return", "send result is discarded."),
    ("R007", "4"): ("unchecked_return", "send result is discarded."),
    ("R010", "4"): ("timestamp_dependence", "Payout branch depends on block.timestamp parity."),
    ("R011", "5"): ("access_control", "Public state-changing address setter has no authorization check."),
    ("R013", "5"): ("access_control", "Public state-changing address setter has no authorization check."),
    ("R015", "4"): ("timestamp_dependence", "Payout branch depends on block.timestamp parity."),
    ("R016", "16"): ("timestamp_dependence", "Bet outcome is derived from block.timestamp."),
    ("R017", "5"): ("reentrancy", "External call occurs before the caller balance is cleared."),
    ("R018", "28"): ("reentrancy", "External call occurs before the account balance decrement."),
    ("R018", "49"): ("access_control", "Any caller can withdraw the complete contract balance."),
    ("R018", "57"): ("unchecked_return", "Owner-gated send result is ignored."),
    ("R019", "4"): ("unchecked_return", "send result is discarded."),
    ("R020", "4"): ("unchecked_return", "send result is discarded."),
    ("R021", "5"): ("integer_overflow", "Arithmetic runs inside unchecked without a balance bound."),
    ("R031", "5"): ("integer_overflow", "Arithmetic runs inside unchecked without a balance bound."),
    ("R032", "22"): ("access_control", "Public state-changing owner/address setter has no authorization check."),
    ("R032", "29"): ("access_control", "Any caller can withdraw the complete contract balance."),
    ("R033", "12"): ("integer_overflow", "Payment multiplication is explicitly unchecked."),
    ("R036", "5"): ("integer_overflow", "Arithmetic runs inside unchecked without a balance bound."),
    ("R037", "5"): ("reentrancy", "External call occurs before the caller balance is cleared."),
    ("R038", "5"): ("access_control", "Public state-changing address setter has no authorization check."),
    ("R041", "5"): ("access_control", "Public state-changing address setter has no authorization check."),
    ("R042", "17"): ("reentrancy", "External call occurs before the caller balance decrement."),
    ("R043", "5"): ("integer_overflow", "Arithmetic runs inside unchecked without a balance bound."),
    ("R046", "5"): ("reentrancy", "External call occurs before the caller balance is cleared."),
    ("R048", "5"): ("access_control", "Public state-changing address setter has no authorization check."),
    ("R052", "4"): ("unchecked_return", "send result is discarded."),
    ("R054", "4"): ("timestamp_dependence", "Payout branch depends on block.timestamp parity."),
    ("R056", "5"): ("reentrancy", "External call occurs before the caller balance is cleared."),
    ("R057", "4"): ("timestamp_dependence", "Payout branch depends on block.timestamp parity."),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", type=Path, default=DEFAULT_PACKET)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    worksheet = args.packet / "annotator_A_worksheet.csv"
    with worksheet.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
        fields = list(rows[0]) if rows else []
    if not rows:
        raise SystemExit("The source worksheet is empty")

    findings_seen: set[tuple[str, str]] = set()
    for row in rows:
        key = (row["contract_id"], row["start_line"])
        if key in FINDINGS:
            finding_class, evidence = FINDINGS[key]
            row.update(
                decision="vulnerable",
                vulnerability_class=finding_class,
                label_source="ai_assisted_review",
                annotator_id="codex_ai_semantic_v1",
                adjudication_status="pending",
                evidence=evidence,
            )
            findings_seen.add(key)
        else:
            row.update(
                decision="safe",
                vulnerability_class="",
                label_source="ai_assisted_review",
                annotator_id="codex_ai_semantic_v1",
                adjudication_status="pending",
                evidence="No target-class exploit pattern identified in this callable region during AI semantic review.",
            )
    unmatched = sorted(set(FINDINGS) - findings_seen)
    if unmatched:
        raise SystemExit(f"Finding locations absent from worksheet: {unmatched}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    metadata = {
        "provenance": "AI-assisted semantic triage by Codex; not independent human annotation or final ground truth.",
        "input_packet": str(args.packet),
        "row_count": len(rows),
        "vulnerable_rows": sum(row["decision"] == "vulnerable" for row in rows),
        "safe_rows": sum(row["decision"] == "safe" for row in rows),
        "unresolved_rows": 0,
        "final_metrics_eligible": False,
    }
    args.output.with_suffix(".json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(json.dumps(metadata, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
