#!/usr/bin/env python3
"""Run an NSS 2026 graph baseline on a frozen weak-label split.

Each run writes the model configuration, frozen-split checksum, metrics, and
one prediction row per test graph. Results are intentionally isolated from
historical `models/` outputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import random
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.metrics import accuracy_score, classification_report, f1_score, precision_score, recall_score
from torch.optim import AdamW
from torch.optim.lr_scheduler import OneCycleLR
from torch_geometric.loader import DataLoader
from torch_geometric.nn import GATConv, GATv2Conv, GCNConv, GINConv, global_mean_pool

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.train_canonical_v5_top5 import load_canonical_data  # noqa: E402
from src.analysis.gnn.model_v2 import GNNMHAv2  # noqa: E402

LABELS = ["reentrancy", "integer_overflow", "access_control", "unchecked_return", "front_running"]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.set_num_threads(4)


class PlainGraphModel(nn.Module):
    def __init__(self, kind: str, in_channels: int, hidden_channels: int, num_layers: int, heads: int, dropout: float):
        super().__init__()
        self.kind, self.dropout = kind, dropout
        self.input = nn.Linear(in_channels, hidden_channels)
        convolutions: list[nn.Module] = []
        for _ in range(num_layers):
            if kind == "gcn":
                convolutions.append(GCNConv(hidden_channels, hidden_channels))
            elif kind == "gin":
                mlp = nn.Sequential(nn.Linear(hidden_channels, hidden_channels), nn.ReLU(), nn.Linear(hidden_channels, hidden_channels))
                convolutions.append(GINConv(mlp))
            elif kind == "gat":
                convolutions.append(GATConv(hidden_channels, hidden_channels, heads=heads, concat=False, dropout=dropout))
            elif kind == "gatv2":
                convolutions.append(GATv2Conv(hidden_channels, hidden_channels, heads=heads, concat=False, dropout=dropout))
            else:
                raise ValueError(f"Unsupported baseline: {kind}")
        self.convolutions = nn.ModuleList(convolutions)
        self.norms = nn.ModuleList(nn.BatchNorm1d(hidden_channels) for _ in range(num_layers))
        self.classifier = nn.Sequential(
            nn.Linear(hidden_channels, hidden_channels), nn.ReLU(), nn.Dropout(dropout), nn.Linear(hidden_channels, 5)
        )

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor, batch: torch.Tensor, edge_attr: torch.Tensor | None = None) -> torch.Tensor:
        del edge_attr
        x = F.relu(self.input(x))
        for convolution, norm in zip(self.convolutions, self.norms):
            residual = x
            x = convolution(x, edge_index)
            x = F.relu(norm(x))
            x = F.dropout(x, p=self.dropout, training=self.training)
            x = x + residual
        return self.classifier(global_mean_pool(x, batch))


def load_frozen_data(split_path: Path, split_name: str) -> tuple[dict[str, list], dict[str, list[str]]]:
    frozen = json.loads(split_path.read_text(encoding="utf-8"))
    split_key = "random_stratified" if split_name == "random" else "lineage_disjoint"
    requested = frozen[split_key]["sample_ids"]
    data = load_canonical_data()
    by_sample_id = {str(graph.sample_id): graph for graph in data}
    if len(by_sample_id) != len(data):
        raise ValueError("Canonical loader produced non-unique sample IDs.")
    result = {}
    for partition, identifiers in requested.items():
        missing = [identifier for identifier in identifiers if identifier not in by_sample_id]
        if missing:
            raise ValueError(f"{partition}: {len(missing)} frozen sample IDs are absent from the canonical loader")
        result[partition] = [by_sample_id[identifier] for identifier in identifiers]
    return result, requested


def class_weights(train_data: list) -> torch.Tensor:
    counts = Counter(int(graph.y.item()) for graph in train_data)
    total = len(train_data)
    weights = torch.tensor([(total / (5 * counts[index])) ** 0.5 for index in range(5)], dtype=torch.float32)
    return weights / weights.sum() * 5


def evaluate(model: nn.Module, loader: DataLoader, device: torch.device, sample_ids: list[str]) -> tuple[dict, list[dict]]:
    model.eval()
    true, predicted, probabilities = [], [], []
    with torch.no_grad():
        for batch in loader:
            batch = batch.to(device)
            logits = model(batch.x, batch.edge_index, batch.batch, edge_attr=getattr(batch, "edge_attr", None))
            probabilities.extend(torch.softmax(logits, dim=1).cpu().tolist())
            predicted.extend(logits.argmax(dim=1).cpu().tolist())
            true.extend(batch.y.cpu().tolist())
    if len(sample_ids) != len(true):
        raise ValueError(f"Prediction/sample ID length mismatch: {len(true)} vs {len(sample_ids)}")
    report = classification_report(true, predicted, labels=list(range(5)), target_names=LABELS, output_dict=True, zero_division=0)
    metrics = {
        "accuracy": accuracy_score(true, predicted),
        "macro_precision": precision_score(true, predicted, average="macro", zero_division=0),
        "macro_recall": recall_score(true, predicted, average="macro", zero_division=0),
        "macro_f1": f1_score(true, predicted, average="macro", zero_division=0),
        "classification_report": report,
    }
    rows = [
        {"sample_id": sample_id, "true_label": int(label), "predicted_label": int(pred), "probabilities": probs}
        for sample_id, label, pred, probs in zip(sample_ids, true, predicted, probabilities)
    ]
    return metrics, rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a reproducible NSS 2026 GNN baseline")
    parser.add_argument("--model", choices=("gcn", "gin", "gat", "gatv2", "gnnmhav2"), required=True)
    parser.add_argument("--split", choices=("random", "lineage"), required=True)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--epochs", type=int, default=35)
    parser.add_argument("--patience", type=int, default=15)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--hidden-channels", type=int, default=256)
    parser.add_argument("--layers", type=int, default=4)
    parser.add_argument("--heads", type=int, default=8)
    parser.add_argument("--dropout", type=float, default=0.15)
    parser.add_argument("--split-manifest", type=Path, default=ROOT / "artifacts/nss2026/frozen_splits.json")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing output directory")
    args = parser.parse_args()
    split_manifest = args.split_manifest.resolve()
    default_output = ROOT / "artifacts/nss2026/runs" / args.split / args.model / f"seed_{args.seed}"
    output_dir = (args.output_dir or default_output).resolve()
    if output_dir.exists() and any(output_dir.iterdir()) and not args.overwrite:
        raise SystemExit(f"Refusing to overwrite non-empty run directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    set_seed(args.seed)
    data, identifiers = load_frozen_data(split_manifest, args.split)
    device = torch.device("cpu")
    sample = data["train"][0]
    if args.model == "gnnmhav2":
        model = GNNMHAv2(
            in_channels=sample.x.shape[1], hidden_channels=args.hidden_channels, num_classes=5,
            num_heads=args.heads, num_layers=args.layers, dropout=args.dropout, edge_dim=sample.edge_attr.shape[-1],
        )
        loss_name = "class_weighted_focal"
    else:
        model = PlainGraphModel(args.model, sample.x.shape[1], args.hidden_channels, args.layers, args.heads, args.dropout)
        loss_name = "class_weighted_cross_entropy"
    model = model.to(device)
    loaders = {
        name: DataLoader(items, batch_size=args.batch_size, shuffle=name == "train") for name, items in data.items()
    }
    weights = class_weights(data["train"]).to(device)
    if args.model == "gnnmhav2":
        class FocalLoss(nn.Module):
            def forward(self, logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
                ce = F.cross_entropy(logits, targets, reduction="none", label_smoothing=0.05)
                return (weights[targets] * (1 - torch.exp(-ce)).pow(2) * ce).mean()
        criterion: nn.Module = FocalLoss()
    else:
        criterion = nn.CrossEntropyLoss(weight=weights, label_smoothing=0.05)
    optimizer = AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    scheduler = OneCycleLR(optimizer, max_lr=1e-3, epochs=args.epochs, steps_per_epoch=len(loaders["train"]), pct_start=0.1)
    started = time.time()
    best_validation_f1, best_epoch, stale, history = -1.0, 0, 0, []
    for epoch in range(1, args.epochs + 1):
        model.train()
        for batch in loaders["train"]:
            batch = batch.to(device)
            optimizer.zero_grad()
            logits = model(batch.x, batch.edge_index, batch.batch, edge_attr=getattr(batch, "edge_attr", None))
            loss = criterion(logits, batch.y)
            loss.backward()
            optimizer.step()
            scheduler.step()
        validation, _ = evaluate(model, loaders["val"], device, identifiers["val"])
        history.append({"epoch": epoch, "validation_macro_f1": validation["macro_f1"]})
        if validation["macro_f1"] > best_validation_f1:
            best_validation_f1, best_epoch, stale = validation["macro_f1"], epoch, 0
            torch.save(model.state_dict(), output_dir / "best_model.pt")
        else:
            stale += 1
            if stale >= args.patience:
                break
    model.load_state_dict(torch.load(output_dir / "best_model.pt", map_location=device, weights_only=True))
    metrics, rows = evaluate(model, loaders["test"], device, identifiers["test"])
    payload = {
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        "model": args.model,
        "split": args.split,
        "seed": args.seed,
        "label_protocol": "contract-derived weak labels",
        "loss": loss_name,
        "device": str(device),
        "python": platform.python_version(),
        "torch": torch.__version__,
        "split_manifest": str(split_manifest.relative_to(ROOT)),
        "split_manifest_sha256": sha256_file(split_manifest),
        "hyperparameters": {"epochs_requested": args.epochs, "epochs_completed": len(history), "best_epoch": best_epoch, "batch_size": args.batch_size, "hidden_channels": args.hidden_channels, "layers": args.layers, "heads": args.heads, "dropout": args.dropout},
        "elapsed_seconds": time.time() - started,
        "metrics": metrics,
        "history": history,
    }
    (output_dir / "metrics.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    (output_dir / "test_predictions.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    (output_dir / "sha256sums.txt").write_text(
        "".join(f"{sha256_file(path)}  {path.name}\n" for path in sorted(output_dir.iterdir()) if path.is_file() and path.name != "sha256sums.txt"),
        encoding="utf-8",
    )
    print(json.dumps({"output": str(output_dir), "accuracy": metrics["accuracy"], "macro_f1": metrics["macro_f1"], "elapsed_seconds": payload["elapsed_seconds"]}, indent=2))


if __name__ == "__main__":
    main()
