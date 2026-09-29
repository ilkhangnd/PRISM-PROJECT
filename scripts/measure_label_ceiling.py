#!/usr/bin/env python3
"""
Measure structural graph label conflicts and empirical accuracy on conflict-free vs. conflicting test subsets.
Analyzes canonical graph structural hashes from corpus_manifest.json against frozen splits.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus-manifest", type=Path, default=ROOT / "artifacts/nss2026/corpus_manifest.json")
    parser.add_argument("--frozen-splits", type=Path, default=ROOT / "artifacts/nss2026/frozen_splits.json")
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/results/label_ceiling.json")
    args = parser.parse_args()

    corpus = json.loads(args.corpus_manifest.read_text(encoding="utf-8"))
    records = {r["sample_id"]: r for r in corpus["records"]}

    splits = json.load(args.frozen_splits.open(encoding="utf-8"))

    results = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "protocol": "Canonical graph hashing and structural-label-conflict diagnostic",
        "description": "Examines graph structure hash collisions between train and test sets to diagnose label noise and structural conflicts arising from contract-derived weak labels. Reports coverage statistics of non-conflicting structural matches and novel graphs.",
        "coverage_statistic_note": "nonconflicting_structural_match_or_novel_pct measures test graphs that either match a training graph with agreeing majority label or are structurally novel. It is a diagnostic coverage metric for label conflicts, not a theoretical upper bound.",
        "splits": {}
    }

    split_configs = [
        ("random_stratified", "random"),
        ("lineage_disjoint", "lineage"),
    ]

    for split_key, run_key in split_configs:
        train_ids = set(splits[split_key]["sample_ids"]["train"])
        test_ids = splits[split_key]["sample_ids"]["test"]
        n_test = len(test_ids)

        train_hash_labels = defaultdict(list)
        for sid in train_ids:
            r = records[sid]
            h = r["structural_graph_sha256"]
            train_hash_labels[h].append(r["canonical_label_id"])

        conflicting_ids = []
        conflict_free_ids = []
        has_identical_train = 0
        identical_agree = 0
        identical_conflict = 0
        novel_graphs = 0
        nonconflicting_count = 0

        for sid in test_ids:
            r = records[sid]
            h = r["structural_graph_sha256"]
            test_y = r["canonical_label_id"]

            if h in train_hash_labels:
                has_identical_train += 1
                train_labels = train_hash_labels[h]
                maj_train_label = Counter(train_labels).most_common(1)[0][0]
                if maj_train_label == test_y:
                    nonconflicting_count += 1

                if test_y in train_labels:
                    identical_agree += 1
                    conflict_free_ids.append(sid)
                else:
                    identical_conflict += 1
                    conflicting_ids.append(sid)
            else:
                novel_graphs += 1
                nonconflicting_count += 1
                conflict_free_ids.append(sid)

        # Multi-seed GNNMHAv2 evaluation on subsets
        all_accs, cf_accs, conf_accs = [], [], []
        for seed in [42, 43, 44, 45, 46]:
            pred_file = ROOT / f"artifacts/nss2026/runs/{run_key}/gnnmhav2/seed_{seed}/test_predictions.jsonl"
            if not pred_file.exists():
                continue
            preds = [json.loads(line) for line in pred_file.read_text(encoding="utf-8").strip().split("\n")]
            pdict = {p["sample_id"]: p for p in preds}

            acc_all = sum(1 for p in preds if p["true_label"] == p["predicted_label"]) / len(preds)
            all_accs.append(acc_all)

            acc_cf = sum(1 for sid in conflict_free_ids if pdict[sid]["true_label"] == pdict[sid]["predicted_label"]) / len(conflict_free_ids)
            cf_accs.append(acc_cf)

            if conflicting_ids:
                acc_conf = sum(1 for sid in conflicting_ids if pdict[sid]["true_label"] == pdict[sid]["predicted_label"]) / len(conflicting_ids)
                conf_accs.append(acc_conf)

        split_summary = {
            "total_test_graphs": n_test,
            "test_with_identical_train_graph": has_identical_train,
            "test_with_identical_train_graph_pct": round(has_identical_train / n_test * 100, 2),
            "identical_train_agreeing_label": identical_agree,
            "identical_train_agreeing_label_pct": round(identical_agree / n_test * 100, 2),
            "identical_train_conflicting_label": identical_conflict,
            "identical_train_conflicting_label_pct": round(identical_conflict / n_test * 100, 2),
            "novel_test_graphs": novel_graphs,
            "novel_test_graphs_pct": round(novel_graphs / n_test * 100, 2),
            "nonconflicting_structural_match_or_novel_pct": round(nonconflicting_count / n_test * 100, 2),
            "conflict_free_test_count": len(conflict_free_ids),
            "conflicting_test_count": len(conflicting_ids),
            "gnnmhav2_accuracy_overall": {
                "mean_pct": round(float(np.mean(all_accs) * 100), 2),
                "std_pct": round(float(np.std(all_accs) * 100), 2),
            },
            "gnnmhav2_accuracy_conflict_free": {
                "mean_pct": round(float(np.mean(cf_accs) * 100), 2),
                "std_pct": round(float(np.std(cf_accs) * 100), 2),
            },
            "gnnmhav2_accuracy_conflicting": {
                "mean_pct": round(float(np.mean(conf_accs) * 100), 2) if conf_accs else None,
                "std_pct": round(float(np.std(conf_accs) * 100), 2) if conf_accs else None,
            }
        }
        results["splits"][split_key] = split_summary

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(f"Results written to {args.output}")
    print(json.dumps(results["splits"], indent=2))


if __name__ == "__main__":
    main()
