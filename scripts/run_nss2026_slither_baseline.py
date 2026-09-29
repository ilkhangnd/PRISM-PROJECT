#!/usr/bin/env python3
"""Run Slither mapped-to-Top-5 baseline on the frozen NSS 2026 test sets.

Maps Slither detectors to the 5 canonical PRISM classes:
0: reentrancy
1: integer_overflow
2: access_control
3: unchecked_return
4: front_running
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from sklearn.metrics import accuracy_score, classification_report, f1_score, precision_score, recall_score

ROOT = Path(__file__).resolve().parents[1]

LABELS = ["reentrancy", "integer_overflow", "access_control", "unchecked_return", "front_running"]

CHECK_TO_CLASS = {
    # 0: Reentrancy
    "reentrancy-eth": 0,
    "reentrancy-no-eth": 0,
    "reentrancy-benign": 0,
    "reentrancy-events": 0,
    "reentrancy-unlimited-gas": 0,
    # 1: Integer Overflow
    "tautology": 1,
    "divide-before-multiply": 1,
    # 2: Access Control
    "arbitrary-send": 2,
    "arbitrary-send-eth": 2,
    "arbitrary-send-erc20": 2,
    "unprotected-upgrade": 2,
    "suicidal": 2,
    "tx-origin": 2,
    # 3: Unchecked Return
    "unchecked-lowlevel": 3,
    "unchecked-send": 3,
    "unchecked-transfer": 3,
    "unused-return": 3,
    "low-level-calls": 3,
    # 4: Timestamp dependence
    "timestamp": 4,
    "block-timestamp": 4,
    "weak-prng": 4,
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_slither_cache() -> dict[str, list[tuple[str, str]]]:
    """Index all available SolidiFI Slither JSON outputs: filename -> list of (check, function_name)."""
    cache: dict[str, list[tuple[str, str]]] = {}
    base_dir = ROOT / "data/solidifi/results/Slither/analyzed_buggy_contracts"
    for p in base_dir.glob("*/results/*.sol.json"):
        fname = p.name.replace(".sol.json", ".sol")
        try:
            data = json.load(open(p, encoding="utf-8"))
            entries = []
            for det in data.get("results", {}).get("detectors", []):
                check = det.get("check")
                if check in CHECK_TO_CLASS:
                    func_names = [
                        e.get("name") for e in det.get("elements", [])
                        if e.get("type") == "function" and e.get("name")
                    ]
                    for fn in func_names:
                        entries.append((check, fn))
                    if not func_names:
                        entries.append((check, "*"))
            cache[fname] = entries
        except Exception:
            pass
    return cache


def main():
    parser = argparse.ArgumentParser(description="Slither mapped baseline")
    parser.add_argument("--split", choices=("random", "lineage"), default="random")
    parser.add_argument("--output-root", type=Path, default=ROOT / "artifacts/nss2026/runs")
    args = parser.parse_args()

    split_manifest = json.load(open(ROOT / "artifacts/nss2026/frozen_splits.json", encoding="utf-8"))
    corpus_manifest = json.load(open(ROOT / "artifacts/nss2026/corpus_manifest.json", encoding="utf-8"))
    by_sample_id = {r["sample_id"]: r for r in corpus_manifest["records"]}

    split_key = "random_stratified" if args.split == "random" else "lineage_disjoint"
    test_ids = split_manifest[split_key]["sample_ids"]["test"]

    slither_cache = build_slither_cache()

    true_labels = []
    predicted_labels = []
    probabilities = []
    prediction_rows = []

    # Count baseline class frequencies for informative prior
    train_ids = split_manifest[split_key]["sample_ids"]["train"]
    train_labels = [by_sample_id[i]["canonical_label_id"] for i in train_ids]
    total_train = len(train_labels)
    class_prior = [train_labels.count(c) / total_train for c in range(5)]
    majority_class = int(train_labels.count(max(set(train_labels), key=train_labels.count)))
    # fallback to most frequent class in train
    fallback_class = 3  # unchecked_return is most frequent

    for s_id in test_ids:
        record = by_sample_id[s_id]
        true_cls = record["canonical_label_id"]
        true_labels.append(true_cls)

        source_file = Path(record["source_file"]).name
        func_full = record["function_name"]
        func_short = func_full.split(".")[-1] if "." in func_full else func_full

        matched_check = None
        if source_file in slither_cache:
            for check, fn in slither_cache[source_file]:
                if fn == "*" or fn == func_short or fn == func_full:
                    matched_check = check
                    break

        if matched_check is not None:
            pred_cls = CHECK_TO_CLASS[matched_check]
            probs = [0.05] * 5
            probs[pred_cls] = 0.80
        else:
            pred_cls = fallback_class
            probs = list(class_prior)

        predicted_labels.append(pred_cls)
        probabilities.append(probs)
        prediction_rows.append({
            "sample_id": s_id,
            "true_label": true_cls,
            "predicted_label": pred_cls,
            "probabilities": probs,
        })

    report = classification_report(true_labels, predicted_labels, labels=list(range(5)), target_names=LABELS, output_dict=True, zero_division=0)
    acc = accuracy_score(true_labels, predicted_labels)
    macro_p = precision_score(true_labels, predicted_labels, average="macro", zero_division=0)
    macro_r = recall_score(true_labels, predicted_labels, average="macro", zero_division=0)
    macro_f1 = f1_score(true_labels, predicted_labels, average="macro", zero_division=0)

    out_dir = args.output_root / args.split / "slither_mapped" / "seed_42"
    out_dir.mkdir(parents=True, exist_ok=True)

    payload = {
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        "model": "slither_0.11.5_mapped",
        "split": args.split,
        "seed": 42,
        "metrics": {
            "accuracy": acc,
            "macro_precision": macro_p,
            "macro_recall": macro_r,
            "macro_f1": macro_f1,
            "classification_report": report,
        },
    }

    (out_dir / "metrics.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    (out_dir / "test_predictions.jsonl").write_text("".join(json.dumps(r) + "\n" for r in prediction_rows), encoding="utf-8")
    (out_dir / "sha256sums.txt").write_text(
        "".join(f"{sha256_file(p)}  {p.name}\n" for p in sorted(out_dir.iterdir()) if p.is_file() and p.name != "sha256sums.txt"),
        encoding="utf-8",
    )

    print(f"\n[OK] Slither 0.11.5 ({args.split}) -> Acc: {acc:.4f}, Macro-P: {macro_p:.4f}, Macro-R: {macro_r:.4f}, Macro-F1: {macro_f1:.4f}")
    print(f"Results saved to {out_dir}")


if __name__ == "__main__":
    main()
