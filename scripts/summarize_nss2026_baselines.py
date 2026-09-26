#!/usr/bin/env python3
"""Summarise complete NSS 2026 baseline runs without creating paper-ready claims."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODELS = ("gcn", "gin", "gat", "gatv2", "gnnmhav2")
SPLITS = ("random", "lineage")


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate and summarise NSS baseline artifacts")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--runs-root", type=Path, default=ROOT / "artifacts/nss2026/runs")
    parser.add_argument("--splits", nargs="*", choices=SPLITS, default=list(SPLITS))
    parser.add_argument("--output-json", type=Path, default=ROOT / "artifacts/nss2026/phase1_seed42_summary.json")
    parser.add_argument("--output-md", type=Path, default=ROOT / "artifacts/nss2026/phase1_seed42_summary.md")
    args = parser.parse_args()
    rows, missing = [], []
    for split in args.splits:
        for model in MODELS:
            run_dir = args.runs_root / split / model / f"seed_{args.seed}"
            metrics_path, predictions_path = run_dir / "metrics.json", run_dir / "test_predictions.jsonl"
            if not metrics_path.exists() or not predictions_path.exists():
                missing.append({"split": split, "model": model, "run_dir": str(run_dir.relative_to(ROOT))})
                continue
            metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
            predictions = predictions_path.read_text(encoding="utf-8").splitlines()
            expected = 1949 if split == "random" else 2146
            if len(predictions) != expected:
                raise ValueError(f"{run_dir}: expected {expected} prediction rows, found {len(predictions)}")
            measure = metrics["metrics"]
            rows.append(
                {
                    "split": split,
                    "model": model,
                    "seed": metrics["seed"],
                    "accuracy": measure["accuracy"],
                    "macro_precision": measure["macro_precision"],
                    "macro_recall": measure["macro_recall"],
                    "macro_f1": measure["macro_f1"],
                    "elapsed_seconds": metrics["elapsed_seconds"],
                    "prediction_rows": len(predictions),
                    "run_dir": str(run_dir.relative_to(ROOT)),
                }
            )
    payload = {
        "purpose": "Single-seed intermediate summary; not a mean-plus-standard-deviation comparison table",
        "seed": args.seed,
        "label_protocol": "contract-derived weak labels",
        "complete_runs": rows,
        "missing_runs": missing,
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# Phase 1 seed-42 baseline summary",
        "",
        "This is an intermediate single-seed validation. It must not be copied into `main.tex` before the planned multi-seed runs and statistical tests.",
        "",
        "| Split | Model | Acc. | Macro-P | Macro-R | Macro-F1 | Test rows | Seconds |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in rows:
        lines.append(
            f"| {row['split']} | {row['model']} | {row['accuracy']:.4f} | {row['macro_precision']:.4f} | "
            f"{row['macro_recall']:.4f} | {row['macro_f1']:.4f} | {row['prediction_rows']} | {row['elapsed_seconds']:.1f} |"
        )
    if missing:
        lines.extend(["", "## Missing runs", ""])
        lines.extend(f"- `{item['split']}/{item['model']}`" for item in missing)
    args.output_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {args.output_json} and {args.output_md}; {len(rows)} complete, {len(missing)} missing")


if __name__ == "__main__":
    main()
