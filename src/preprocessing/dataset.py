"""
PyG Dataset — InMemoryDataset for batch loading smart contract graphs.

Handles the full pipeline: Solidity → Slither → CFG/DFG → PyG Data objects
with caching for efficient reloading.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import torch

logger = logging.getLogger(__name__)

# Vulnerability label mapping
VULN_LABELS = {
    "reentrancy": 0,
    "integer_overflow": 1,
    "access_control": 2,
    "unchecked_return": 3,
    "denial_of_service": 4,
    "front_running": 5,
    "timestamp_dependence": 6,
    "delegatecall": 7,
    "safe": 8,  # No vulnerability (negative sample)
}

LABEL_NAMES = {v: k for k, v in VULN_LABELS.items()}


class SmartContractDataset:
    """
    Dataset for smart contract vulnerability detection.

    Processes Solidity files into PyG Data objects with CFG+DFG graphs.
    Supports both labeled (supervised) and unlabeled (inference) modes.

    Usage:
        dataset = SmartContractDataset(
            root="data/processed",
            raw_dir="data/raw",
            labels_file="data/labels.json",  # Optional
        )
        dataset.process()
        train_loader = dataset.get_dataloader(split="train", batch_size=32)
    """

    def __init__(
        self,
        root: str = "data/processed",
        raw_dir: str = "data/raw",
        labels_file: str | None = None,
        solc: str = "solc",
        embedding_dim: int = 128,
        graph_type: str = "cfg+dfg",
    ):
        """
        Args:
            root: Directory to save processed PyG data.
            raw_dir: Directory containing raw .sol files.
            labels_file: Optional JSON file mapping contract names to vulnerability labels.
            solc: Path to the solc binary.
            embedding_dim: Dimension for node feature vectors.
            graph_type: Type of graph to build: "cfg", "dfg", or "cfg+dfg".
        """
        self.root = Path(root)
        self.raw_dir = Path(raw_dir)
        self.labels_file = Path(labels_file) if labels_file else None
        self.solc = solc
        self.embedding_dim = embedding_dim
        self.graph_type = graph_type

        self.data_list: list[Any] = []
        self.labels: dict[str, int] = {}
        self.metadata: list[dict] = []

        # Load labels if provided
        if self.labels_file and self.labels_file.exists():
            with open(self.labels_file) as f:
                raw_labels = json.load(f)
            # Convert string labels to integers
            for name, label in raw_labels.items():
                if isinstance(label, str):
                    self.labels[name] = VULN_LABELS.get(label.lower(), 8)
                else:
                    self.labels[name] = int(label)

    def process(self) -> list[Any]:
        """
        Process all .sol files in raw_dir into PyG Data objects.

        Returns:
            List of PyG Data objects.
        """
        from src.preprocessing.cfg_builder import CFGBuilder
        from src.preprocessing.dfg_builder import DFGBuilder
        from src.preprocessing.graph_embeddings import graph_to_pyg_data

        sol_files = sorted(self.raw_dir.glob("**/*.sol"))
        if not sol_files:
            logger.warning(f"No .sol files found in {self.raw_dir}")
            return []

        logger.info(f"Processing {len(sol_files)} Solidity files from {self.raw_dir}")

        for sol_file in sol_files:
            try:
                self._process_file(sol_file, CFGBuilder, DFGBuilder, graph_to_pyg_data)
            except Exception as e:
                logger.warning(f"Failed to process {sol_file.name}: {e}")
                continue

        # Save processed data
        self._save()
        logger.info(f"Processed {len(self.data_list)} graphs from {len(sol_files)} files")
        return self.data_list

    def _process_file(self, sol_file: Path, cfg_builder_cls, dfg_builder_cls, graph_to_pyg_data):
        """Process a single Solidity file into graph data."""
        contract_name = sol_file.stem
        label = self.labels.get(contract_name, 8)  # Default: "safe"

        # Auto-detect solc version from pragma
        source_code = sol_file.read_text()
        try:
            from src.preprocessing.solc_resolver import resolve_and_get_solc

            version, solc_path = resolve_and_get_solc(source_code)
            logger.debug(f"{sol_file.name}: detected solc {version}")
        except Exception:
            solc_path = self.solc  # Fallback to configured solc

        # Build CFG
        cfg_builder = cfg_builder_cls()
        cfgs = cfg_builder.build_from_slither(str(sol_file), solc=solc_path)

        # Build DFG (if requested)
        dfgs = {}
        if "dfg" in self.graph_type:
            dfg_builder = dfg_builder_cls()
            dfgs = dfg_builder.build_from_file(str(sol_file), solc=solc_path)

        # Convert each function's graph to PyG Data
        for func_name, cfg in cfgs.items():
            if cfg.number_of_nodes() < 2:
                continue  # Skip trivial functions

            dfg = dfgs.get(func_name)
            data = graph_to_pyg_data(
                cfg=cfg,
                dfg=dfg if "dfg" in self.graph_type else None,
                label=label,
                embedding_dim=self.embedding_dim,
            )

            # Attach metadata
            data.contract_name = contract_name
            data.function_name = func_name
            data.source_file = str(sol_file)

            self.data_list.append(data)
            self.metadata.append(
                {
                    "contract": contract_name,
                    "function": func_name,
                    "source": str(sol_file),
                    "label": label,
                    "label_name": LABEL_NAMES.get(label, "unknown"),
                    "num_nodes": data.num_nodes,
                    "num_edges": data.edge_index.shape[1] if data.edge_index.numel() > 0 else 0,
                }
            )

    def _save(self):
        """Save processed data and metadata to disk."""
        self.root.mkdir(parents=True, exist_ok=True)

        # Save PyG data list
        torch.save(self.data_list, self.root / "data_list.pt")

        # Save metadata
        with open(self.root / "metadata.json", "w") as f:
            json.dump(self.metadata, f, indent=2)

        logger.info(f"Saved {len(self.data_list)} graphs to {self.root}")

    def load(self) -> list[Any]:
        """Load previously processed data from disk."""
        data_path = self.root / "data_list.pt"
        if not data_path.exists():
            raise FileNotFoundError(f"No processed data at {data_path}. Run process() first.")

        self.data_list = torch.load(data_path, weights_only=False)

        meta_path = self.root / "metadata.json"
        if meta_path.exists():
            with open(meta_path) as f:
                self.metadata = json.load(f)

        logger.info(f"Loaded {len(self.data_list)} graphs from {self.root}")
        return self.data_list

    def split(self, train_ratio: float = 0.7, val_ratio: float = 0.15, seed: int = 42):
        """
        Split dataset into train/val/test sets.

        Args:
            train_ratio: Fraction for training.
            val_ratio: Fraction for validation.
            seed: Random seed for reproducibility.

        Returns:
            Tuple of (train_data, val_data, test_data).
        """
        import random

        random.seed(seed)

        indices = list(range(len(self.data_list)))
        random.shuffle(indices)

        n = len(indices)
        n_train = int(n * train_ratio)
        n_val = int(n * val_ratio)

        train_idx = indices[:n_train]
        val_idx = indices[n_train : n_train + n_val]
        test_idx = indices[n_train + n_val :]

        train_data = [self.data_list[i] for i in train_idx]
        val_data = [self.data_list[i] for i in val_idx]
        test_data = [self.data_list[i] for i in test_idx]

        logger.info(f"Split: train={len(train_data)}, val={len(val_data)}, test={len(test_data)}")
        return train_data, val_data, test_data

    def get_dataloader(self, data: list | None = None, batch_size: int = 32, shuffle: bool = True):
        """
        Create a PyG DataLoader.

        Args:
            data: List of Data objects (if None, uses self.data_list).
            batch_size: Batch size.
            shuffle: Whether to shuffle.

        Returns:
            PyG DataLoader.
        """
        try:
            from torch_geometric.loader import DataLoader
        except ImportError:
            raise ImportError("Install torch-geometric: pip install torch-geometric")

        data = data or self.data_list
        return DataLoader(data, batch_size=batch_size, shuffle=shuffle)

    def stats(self) -> dict:
        """Get dataset statistics."""
        if not self.data_list:
            return {"total": 0}

        label_counts: dict[str, int] = {}
        total_nodes = 0
        total_edges = 0

        for meta in self.metadata:
            label_name = meta.get("label_name", "unknown")
            label_counts[label_name] = label_counts.get(label_name, 0) + 1
            total_nodes += meta.get("num_nodes", 0)
            total_edges += meta.get("num_edges", 0)

        n = len(self.data_list)
        return {
            "total_graphs": n,
            "avg_nodes": total_nodes / n if n else 0,
            "avg_edges": total_edges / n if n else 0,
            "label_distribution": label_counts,
            "unique_contracts": len({m["contract"] for m in self.metadata}),
        }

    def __len__(self):
        return len(self.data_list)

    def __getitem__(self, idx):
        return self.data_list[idx]
