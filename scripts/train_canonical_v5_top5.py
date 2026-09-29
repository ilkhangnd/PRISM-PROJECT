#!/usr/bin/env python3
"""Canonical Top-5 SWC Dataset Loader & Training Utility for NSS 2026.

Provides `load_canonical_data()` for baseline evaluations and reproducibility scripts.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List

import torch
import torch.nn as nn
from torch_geometric.data import Data

ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = ROOT / "artifacts/nss2026/corpus_manifest.json"
SPLIT_PATH = ROOT / "artifacts/corpus/frozen_splits.json"

RAW_TO_CANONICAL = {0: 0, 1: 1, 2: 2, 3: 3, 5: 4}
CANONICAL_NAMES = ["reentrancy", "integer_overflow", "access_control", "unchecked_return", "front_running"]


def load_canonical_data(manifest_path: Path | None = None) -> List[Data]:
    """Load the 12,991 canonical function graphs matching corpus_manifest.json.

    Each graph Data object contains:
      - x: node feature matrix [N, 32]
      - edge_index: graph connectivity [2, E]
      - edge_attr: edge features [E, 4]
      - y: canonical 5-class target tensor [1] (0..4)
      - sample_id: unique identifier matching frozen_splits.json
      - contract_name: source contract
      - function_name: target function
      - source_file: path to source contract
    """
    m_path = manifest_path or MANIFEST_PATH
    if not m_path.exists():
        # Fall back to SPLIT_PATH to extract sample IDs if manifest hasn't been built
        if SPLIT_PATH.exists():
            with SPLIT_PATH.open(encoding="utf-8") as f:
                sp = json.load(f)
            split_ids = set(
                sp["random_stratified"]["sample_ids"]["train"]
                + sp["random_stratified"]["sample_ids"]["val"]
                + sp["random_stratified"]["sample_ids"]["test"]
            )
        else:
            raise FileNotFoundError(f"Neither {m_path} nor {SPLIT_PATH} found.")
    else:
        with m_path.open(encoding="utf-8") as f:
            manifest = json.load(f)
        split_ids = {r["sample_id"] for r in manifest["records"]}

    index = 0
    canonical_graphs: List[Data] = []
    for dataset in ("smartbugs", "solidifi", "lisa"):
        pt_path = ROOT / f"data/{dataset}/processed_v2/data_list.pt"
        if not pt_path.exists():
            continue
        graphs = torch.load(pt_path, map_location="cpu", weights_only=False)
        for g in graphs:
            sid = f"graph_{index:05d}_{g.contract_name}"
            if sid in split_ids:
                g_clone = g.clone()
                g_clone.sample_id = sid
                raw_y = int(g.y.item())
                can_y = RAW_TO_CANONICAL.get(raw_y, 0)
                g_clone.y = torch.tensor([can_y], dtype=torch.long)
                canonical_graphs.append(g_clone)
            index += 1

    return canonical_graphs


def main():
    parser = argparse.ArgumentParser(description="Canonical NSS 2026 Top-5 Loader Diagnostic")
    parser.add_argument("--test-load", action="store_true", default=True, help="Verify data loading")
    args = parser.parse_args()

    print("Loading canonical data...")
    data = load_canonical_data()
    print(f"Loaded {len(data)} canonical function graphs.")
    if data:
        s = data[0]
        print(f"Sample 0: ID={s.sample_id}, y={int(s.y.item())} ({CANONICAL_NAMES[int(s.y.item())]}), nodes={s.num_nodes}, edges={s.edge_index.shape[1]}")


if __name__ == "__main__":
    main()
