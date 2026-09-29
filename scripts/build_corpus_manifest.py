#!/usr/bin/env python3
"""Build artifacts/nss2026/corpus_manifest.json from processed_v2 graph datasets and frozen splits."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import torch

ROOT = Path(__file__).resolve().parent.parent
SPLIT_PATH = ROOT / "artifacts/corpus/frozen_splits.json"
OUT_MANIFEST = ROOT / "artifacts/nss2026/corpus_manifest.json"

RAW_TO_CANONICAL = {0: 0, 1: 1, 2: 2, 3: 3, 5: 4}
CANONICAL_NAMES = ["reentrancy", "integer_overflow", "access_control", "unchecked_return", "front_running"]


def main():
    with SPLIT_PATH.open(encoding="utf-8") as f:
        splits = json.load(f)

    split_ids = set(
        splits["random_stratified"]["sample_ids"]["train"]
        + splits["random_stratified"]["sample_ids"]["val"]
        + splits["random_stratified"]["sample_ids"]["test"]
    )
    print(f"Loaded {len(split_ids)} split sample IDs from {SPLIT_PATH.name}")

    index = 0
    records = []
    for dataset in ("smartbugs", "solidifi", "lisa"):
        pt_path = ROOT / f"data/{dataset}/processed_v2/data_list.pt"
        if not pt_path.exists():
            raise FileNotFoundError(f"Missing {pt_path}")
        graphs = torch.load(pt_path, weights_only=False)
        print(f"Scanning {dataset}: {len(graphs)} graphs...")

        for g in graphs:
            sid = f"graph_{index:05d}_{g.contract_name}"
            if sid in split_ids:
                raw_y = int(g.y.item())
                can_y = RAW_TO_CANONICAL.get(raw_y, 0)
                feat_bytes = g.x.cpu().numpy().round(4).tobytes()
                edge_bytes = g.edge_index.cpu().numpy().tobytes()
                ghash = hashlib.sha256(feat_bytes + edge_bytes).hexdigest()

                record = {
                    "sample_id": sid,
                    "dataset_source": dataset,
                    "contract_name": str(getattr(g, "contract_name", "")),
                    "function_name": str(getattr(g, "function_name", "")),
                    "source_file": str(getattr(g, "source_file", "")),
                    "raw_label_id": raw_y,
                    "canonical_label_id": can_y,
                    "canonical_label_name": CANONICAL_NAMES[can_y],
                    "num_nodes": int(g.num_nodes),
                    "num_edges": int(g.edge_index.shape[1]),
                    "structural_graph_sha256": ghash,
                }
                records.append(record)
            index += 1

    print(f"Successfully matched {len(records)} records for corpus manifest.")
    if len(records) != len(split_ids):
        raise ValueError(f"Mismatch: matched {len(records)} vs expected {len(split_ids)}")

    manifest = {
        "schema_version": 1,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "total_records": len(records),
        "protocol": "contract-derived weak labels across 5 canonical SWC classes",
        "labels": CANONICAL_NAMES,
        "records": records,
    }

    OUT_MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    with OUT_MANIFEST.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    # Compute sha256
    manifest_sha = hashlib.sha256(OUT_MANIFEST.read_bytes()).hexdigest()
    print(f"Wrote {OUT_MANIFEST} ({len(records)} records, sha256={manifest_sha[:16]}...)")


if __name__ == "__main__":
    main()
