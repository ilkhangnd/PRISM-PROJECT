#!/usr/bin/env python3
"""Map SolidiFI BugLog source spans to callable Solidity bodies.

This builds a provenance-preserving *reliability subset*.  Unlike the primary
corpus labels, a positive row is emitted only when a published BugLog line
maps to exactly one callable body.  It is not a replacement for the five-way
benchmark: classes with too few mapped examples stay explicitly out of scope.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SOLIDIFI = ROOT / "data" / "solidifi" / "buggy_contracts"
CALLABLE = re.compile(r"^\s*(function|modifier|constructor|fallback|receive)\b\s*([A-Za-z_$][\w$]*)?")
BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
LINE_COMMENT = re.compile(r"//[^\n]*")


@dataclass(frozen=True)
class Region:
    kind: str
    name: str
    start_line: int
    end_line: int


def without_comments(source: str) -> str:
    source = BLOCK_COMMENT.sub(lambda m: "\n" * m.group(0).count("\n"), source)
    return LINE_COMMENT.sub("", source)


def callable_regions(source: str) -> list[Region]:
    """Extract function-like brace regions without compiling arbitrary sources."""
    lines = without_comments(source).splitlines()
    regions: list[Region] = []
    index = 0
    while index < len(lines):
        match = CALLABLE.match(lines[index])
        if not match:
            index += 1
            continue
        kind, maybe_name = match.groups()
        name = maybe_name or kind
        start = index
        cursor = index
        depth = 0
        opened = False
        while cursor < len(lines):
            line = lines[cursor]
            if "{" in line:
                opened = True
            if opened:
                depth += line.count("{") - line.count("}")
                if depth == 0:
                    regions.append(Region(kind, name, start + 1, cursor + 1))
                    break
            elif ";" in line:
                break  # Interface declaration: no function body to label.
            cursor += 1
        index = max(index + 1, cursor + 1)
    return regions


def buglog_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def sha256_file(path: Path) -> str:
    """Return a content hash without embedding machine-specific paths."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=SOLIDIFI)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "artifacts" / "nss2026" / "solidifi_span_ground_truth")
    args = parser.parse_args()
    source_root, output = args.source_root.resolve(), args.output_dir.resolve()
    if not source_root.is_dir():
        raise SystemExit(f"SolidiFI source root does not exist: {source_root}")
    if output.exists() and any(output.iterdir()):
        raise SystemExit(f"Refusing to overwrite non-empty output directory: {output}")
    output.mkdir(parents=True)

    positive_rows: list[dict[str, object]] = []
    stats: Counter[str] = Counter()
    per_class: dict[str, Counter[str]] = {}
    input_manifest: list[dict[str, str]] = []
    for log_path in sorted(source_root.glob("*/BugLog_*.csv")):
        category = log_path.parent.name
        number = log_path.stem.removeprefix("BugLog_")
        source_path = log_path.parent / f"buggy_{number}.sol"
        if not source_path.is_file():
            stats["missing_source"] += 1
            continue
        input_manifest.extend([
            {"path": str(log_path.relative_to(ROOT)), "sha256": sha256_file(log_path)},
            {"path": str(source_path.relative_to(ROOT)), "sha256": sha256_file(source_path)},
        ])
        regions = callable_regions(source_path.read_text(encoding="utf-8", errors="replace"))
        class_stats = per_class.setdefault(category, Counter())
        for row in buglog_rows(log_path):
            stats["bug_spans_total"] += 1
            class_stats["bug_spans_total"] += 1
            try:
                line = int(row["loc"])
            except (KeyError, ValueError):
                stats["invalid_bug_span"] += 1
                class_stats["invalid_bug_span"] += 1
                continue
            matches = [region for region in regions if region.start_line <= line <= region.end_line]
            if len(matches) == 1:
                region = matches[0]
                stats["uniquely_mapped_spans"] += 1
                class_stats["uniquely_mapped_spans"] += 1
                positive_rows.append(
                    {
                        "source_category": category,
                        "contract_id": f"{category}_buggy_{number}",
                        "source_path": str(source_path.relative_to(ROOT)),
                        "bug_line": line,
                        "bug_length": row.get("length", ""),
                        "bug_type": row.get("bug type", ""),
                        "injection_approach": row.get("approach", ""),
                        "callable_kind": region.kind,
                        "function_name": region.name,
                        "function_start_line": region.start_line,
                        "function_end_line": region.end_line,
                        "label_provenance": "SolidiFI BugLog span mapped uniquely to callable body",
                    }
                )
            elif not matches:
                stats["unmapped_spans"] += 1
                class_stats["unmapped_spans"] += 1
            else:
                stats["ambiguous_spans"] += 1
                class_stats["ambiguous_spans"] += 1

    fields = list(positive_rows[0]) if positive_rows else []
    with (output / "unique_span_positive_rows.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(positive_rows)
    manifest_bytes = json.dumps(input_manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "purpose": "SolidiFI source-span to function-body mapping for a provenance-preserving reliability subset",
        "scope": "Positive examples only; no negative-label or five-class completeness claim.",
        "source_root": str(source_root.relative_to(ROOT)) if source_root.is_relative_to(ROOT) else source_root.name,
        "summary": dict(stats),
        "per_source_category": {key: dict(value) for key, value in sorted(per_class.items())},
        "row_count": len(positive_rows),
        "parser": "comment-stripping brace-region extractor; records only uniquely mapped spans",
        "provenance": {
            "script_sha256": sha256_file(Path(__file__)),
            "input_file_count": len(input_manifest),
            "input_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        },
    }
    (output / "summary.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
