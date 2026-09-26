#!/usr/bin/env python3
"""Train one fresh, provenance-bound binary Stage-A model and save predictions."""

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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.analysis.gnn.model_v2 import GNNMHAv2


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def load_data(manifest: dict) -> dict[str, list]:
    graphs_by_id = {}
    index = 0
    for dataset in ("smartbugs", "solidifi", "lisa"):
        graphs = torch.load(ROOT / f"data/{dataset}/processed_v2/data_list.pt", weights_only=False)
        for graph in graphs:
            sample_id = f"graph_{index:05d}_{graph.contract_name}"
            index += 1
            graph = graph.clone()
            graph.y = torch.tensor([1 if int(graph.y.item()) == 8 else 0], dtype=torch.long)
            graphs_by_id[sample_id] = graph
    partitions = {}
    for name, ids in manifest["split_sample_ids"].items():
        missing = [sample_id for sample_id in ids if sample_id not in graphs_by_id]
        if missing:
            raise ValueError(f"{name}: {len(missing)} missing manifest records")
        partitions[name] = [graphs_by_id[sample_id] for sample_id in ids]
    return partitions


def evaluate(model: nn.Module, loader: DataLoader, device: torch.device, sample_ids: list[str]) -> tuple[dict, list[dict]]:
    model.eval()
    truth, predicted, probabilities = [], [], []
    with torch.no_grad():
        for batch in loader:
            batch = batch.to(device)
            logits = model(batch.x, batch.edge_index, batch.batch, edge_attr=batch.edge_attr)
            probabilities.extend(torch.softmax(logits, dim=1).cpu().tolist())
            predicted.extend(logits.argmax(dim=1).cpu().tolist())
            truth.extend(batch.y.cpu().tolist())
    labels = ["vulnerable", "safe"]
    metrics = {
        "accuracy": accuracy_score(truth, predicted),
        "macro_precision": precision_score(truth, predicted, average="macro", zero_division=0),
        "macro_recall": recall_score(truth, predicted, average="macro", zero_division=0),
        "macro_f1": f1_score(truth, predicted, average="macro", zero_division=0),
        "classification_report": classification_report(truth, predicted, labels=[0, 1], target_names=labels, output_dict=True, zero_division=0),
    }
    rows = [{"sample_id": sample_id, "true_label": int(y), "predicted_label": int(p), "probabilities": prob}
            for sample_id, y, p, prob in zip(sample_ids, truth, predicted, probabilities)]
    return metrics, rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=ROOT / "artifacts/nss2026/stage_a_manifest.json")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "artifacts/nss2026/stage_a/seed_42")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--epochs", type=int, default=35)
    parser.add_argument("--patience", type=int, default=15)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise SystemExit(f"refusing to overwrite {args.output_dir}")
    args.output_dir.mkdir(parents=True)
    set_seed(args.seed)
    data = load_data(manifest)
    device = torch.device("cpu")
    sample = data["train"][0]
    model = GNNMHAv2(in_channels=sample.x.shape[1], hidden_channels=256, num_classes=2,
                     num_heads=8, num_layers=4, dropout=0.15, edge_dim=sample.edge_attr.shape[-1]).to(device)
    loaders = {name: DataLoader(items, batch_size=64, shuffle=name == "train") for name, items in data.items()}
    counts = Counter(int(item.y.item()) for item in data["train"])
    weights = torch.tensor([len(data["train"]) / (2 * counts[i]) for i in range(2)], dtype=torch.float32).to(device)
    criterion = nn.CrossEntropyLoss(weight=weights, label_smoothing=0.05)
    optimizer = AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    scheduler = OneCycleLR(optimizer, max_lr=1e-3, epochs=args.epochs, steps_per_epoch=len(loaders["train"]), pct_start=0.1)
    best, best_epoch, stale, history = -1.0, 0, 0, []
    started = time.time()
    for epoch in range(1, args.epochs + 1):
        model.train()
        for batch in loaders["train"]:
            batch = batch.to(device)
            optimizer.zero_grad()
            logits = model(batch.x, batch.edge_index, batch.batch, edge_attr=batch.edge_attr)
            loss = criterion(logits, batch.y)
            loss.backward()
            optimizer.step()
            scheduler.step()
        validation, _ = evaluate(model, loaders["val"], device, manifest["split_sample_ids"]["val"])
        history.append({"epoch": epoch, "validation_macro_f1": validation["macro_f1"]})
        if validation["macro_f1"] > best:
            best, best_epoch, stale = validation["macro_f1"], epoch, 0
            torch.save(model.state_dict(), args.output_dir / "best_model.pt")
        else:
            stale += 1
            if stale >= args.patience:
                break
    model.load_state_dict(torch.load(args.output_dir / "best_model.pt", map_location=device, weights_only=True))
    metrics, rows = evaluate(model, loaders["test"], device, manifest["split_sample_ids"]["test"])
    payload = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "purpose": "Fresh Stage-A binary model under frozen weak-label manifest",
        "label_protocol": manifest["label_policy"], "seed": args.seed, "device": str(device),
        "python": platform.python_version(), "torch": torch.__version__,
        "manifest": str(args.manifest.relative_to(ROOT)), "manifest_sha256": digest(args.manifest),
        "hyperparameters": {"epochs_requested": args.epochs, "epochs_completed": len(history), "best_epoch": best_epoch, "batch_size": 64, "hidden_channels": 256, "layers": 4, "heads": 8, "dropout": 0.15},
        "elapsed_seconds": time.time() - started, "metrics": metrics, "history": history,
    }
    (args.output_dir / "metrics.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    (args.output_dir / "test_predictions.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    (args.output_dir / "sha256sums.txt").write_text("".join(f"{digest(p)}  {p.name}\n" for p in sorted(args.output_dir.iterdir()) if p.is_file() and p.name != "sha256sums.txt"), encoding="utf-8")
    print(json.dumps({"output": str(args.output_dir), "metrics": metrics, "elapsed_seconds": payload["elapsed_seconds"]}, indent=2))


if __name__ == "__main__":
    main()
