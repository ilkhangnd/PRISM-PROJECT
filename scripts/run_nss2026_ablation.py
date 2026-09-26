#!/usr/bin/env python3
"""Run reproducible NSS 2026 GNNMHAv2 Ablation Study on the frozen random split.

Ablations:
1. no_edge_attr: GNNMHAv2 without edge attributes (edge_dim=0)
2. no_jk: GNNMHAv2 without JumpingKnowledge (last layer only, jk_mode='none')
3. ce_loss: Class-weighted Cross-Entropy loss instead of Focal Loss
4. mean_pool: Mean pooling only instead of dual attention+mean pooling
5. layers_2: L=2 layers instead of 4
6. layers_3: L=3 layers instead of 4
7. heads_4: K=4 heads instead of 8
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import random
import statistics
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


def load_frozen_data(split_path: Path) -> tuple[dict[str, list], dict[str, list[str]]]:
    frozen = json.loads(split_path.read_text(encoding="utf-8"))
    requested = frozen["random_stratified"]["sample_ids"]
    data = load_canonical_data()
    by_sample_id = {str(graph.sample_id): graph for graph in data}
    result = {}
    for partition, identifiers in requested.items():
        missing = [i for i in identifiers if i not in by_sample_id]
        if missing:
            raise ValueError(f"{partition}: {len(missing)} sample IDs absent")
        result[partition] = [by_sample_id[i] for i in identifiers]
    return result, requested


def class_weights(train_data: list) -> torch.Tensor:
    counts = Counter(int(graph.y.item()) for graph in train_data)
    total = len(train_data)
    weights = torch.tensor([(total / (5 * counts[idx])) ** 0.5 for idx in range(5)], dtype=torch.float32)
    return weights / weights.sum() * 5


def compute_top_k_accuracy(probabilities: list[list[float]], true_labels: list[int], k: int = 2) -> float:
    correct = 0
    for probs, true in zip(probabilities, true_labels):
        top_k = np.argsort(probs)[-k:]
        if true in top_k:
            correct += 1
    return correct / len(true_labels)


def evaluate(model: nn.Module, loader: DataLoader, device: torch.device, sample_ids: list[str], pass_edge_attr: bool = True) -> tuple[dict, list[dict]]:
    model.eval()
    true, predicted, probabilities = [], [], []
    with torch.no_grad():
        for batch in loader:
            batch = batch.to(device)
            edge_attr = getattr(batch, "edge_attr", None) if pass_edge_attr else None
            logits = model(batch.x, batch.edge_index, batch.batch, edge_attr=edge_attr)
            probs = torch.softmax(logits, dim=1).cpu().tolist()
            probabilities.extend(probs)
            predicted.extend(logits.argmax(dim=1).cpu().tolist())
            true.extend(batch.y.cpu().tolist())

    report = classification_report(true, predicted, labels=list(range(5)), target_names=LABELS, output_dict=True, zero_division=0)
    metrics = {
        "accuracy": accuracy_score(true, predicted),
        "top_2_accuracy": compute_top_k_accuracy(probabilities, true, k=2),
        "macro_precision": precision_score(true, predicted, average="macro", zero_division=0),
        "macro_recall": recall_score(true, predicted, average="macro", zero_division=0),
        "macro_f1": f1_score(true, predicted, average="macro", zero_division=0),
        "classification_report": report,
    }
    rows = [
        {"sample_id": s_id, "true_label": int(t), "predicted_label": int(p), "probabilities": pr}
        for s_id, t, p, pr in zip(sample_ids, true, predicted, probabilities)
    ]
    return metrics, rows


def train_single_ablation(
    variant_name: str,
    seed: int,
    data: dict[str, list],
    identifiers: dict[str, list[str]],
    output_dir: Path,
    epochs: int = 35,
    patience: int = 15,
) -> dict:
    set_seed(seed)
    device = torch.device("cpu")
    sample = data["train"][0]

    # Configure variant
    in_dim = sample.x.shape[1]
    hidden_dim = 256
    num_layers = 4
    num_heads = 8
    dropout = 0.15
    edge_dim = sample.edge_attr.shape[-1]
    jk_mode = "cat"
    pooling = "dual"
    use_focal = True
    pass_edge_attr = True

    if variant_name == "no_edge_attr":
        edge_dim = 0
        pass_edge_attr = False
    elif variant_name == "no_jk":
        jk_mode = "none"
    elif variant_name == "ce_loss":
        use_focal = False
    elif variant_name == "mean_pool":
        pooling = "mean"
    elif variant_name == "layers_2":
        num_layers = 2
    elif variant_name == "layers_3":
        num_layers = 3
    elif variant_name == "heads_4":
        num_heads = 4
    elif variant_name == "full":
        pass
    else:
        raise ValueError(f"Unknown variant: {variant_name}")

    model = GNNMHAv2(
        in_channels=in_dim,
        hidden_channels=hidden_dim,
        num_classes=5,
        num_heads=num_heads,
        num_layers=num_layers,
        dropout=dropout,
        edge_dim=edge_dim,
        jk_mode=jk_mode,
        pooling=pooling,
    ).to(device)

    loaders = {
        name: DataLoader(items, batch_size=64, shuffle=name == "train") for name, items in data.items()
    }
    weights = class_weights(data["train"]).to(device)

    if use_focal:
        class FocalLoss(nn.Module):
            def forward(self, logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
                ce = F.cross_entropy(logits, targets, reduction="none", label_smoothing=0.05)
                return (weights[targets] * (1 - torch.exp(-ce)).pow(2) * ce).mean()
        criterion = FocalLoss()
    else:
        criterion = nn.CrossEntropyLoss(weight=weights, label_smoothing=0.05)

    optimizer = AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    scheduler = OneCycleLR(optimizer, max_lr=1e-3, epochs=epochs, steps_per_epoch=len(loaders["train"]), pct_start=0.1)

    best_val_f1, best_epoch, stale = -1.0, 0, 0
    t0 = time.time()
    for epoch in range(1, epochs + 1):
        model.train()
        for batch in loaders["train"]:
            batch = batch.to(device)
            optimizer.zero_grad()
            e_attr = getattr(batch, "edge_attr", None) if pass_edge_attr else None
            logits = model(batch.x, batch.edge_index, batch.batch, edge_attr=e_attr)
            loss = criterion(logits, batch.y)
            loss.backward()
            optimizer.step()
            scheduler.step()

        val_metrics, _ = evaluate(model, loaders["val"], device, identifiers["val"], pass_edge_attr=pass_edge_attr)
        if val_metrics["macro_f1"] > best_val_f1:
            best_val_f1 = val_metrics["macro_f1"]
            best_epoch = epoch
            stale = 0
            torch.save(model.state_dict(), output_dir / "best_model.pt")
        else:
            stale += 1
            if stale >= patience:
                break

    elapsed = time.time() - t0
    model.load_state_dict(torch.load(output_dir / "best_model.pt", map_location=device, weights_only=True))
    test_metrics, rows = evaluate(model, loaders["test"], device, identifiers["test"], pass_edge_attr=pass_edge_attr)

    payload = {
        "variant": variant_name,
        "seed": seed,
        "best_epoch": best_epoch,
        "elapsed_seconds": elapsed,
        "metrics": test_metrics,
    }
    (output_dir / "metrics.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    (output_dir / "test_predictions.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return payload


def main():
    parser = argparse.ArgumentParser(description="NSS 2026 GNNMHAv2 Ablation Suite")
    parser.add_argument("--variants", nargs="+", default=["no_edge_attr", "no_jk", "ce_loss", "mean_pool", "layers_2", "layers_3", "heads_4"])
    parser.add_argument("--seeds", type=int, nargs="+", default=[42, 43, 44, 45, 46])
    parser.add_argument("--output-root", type=Path, default=ROOT / "artifacts/nss2026/ablation")
    parser.add_argument("--split-manifest", type=Path, default=ROOT / "artifacts/nss2026/frozen_splits.json")
    args = parser.parse_args()

    data, identifiers = load_frozen_data(args.split_manifest.resolve())
    args.output_root.mkdir(parents=True, exist_ok=True)

    summary = {}

    # 1. Load full model from Phase 1 runs
    full_runs = []
    full_root = ROOT / "artifacts/nss2026/runs/random/gnnmhav2"
    for seed in args.seeds:
        seed_dir = full_root / f"seed_{seed}"
        m = json.loads((seed_dir / "metrics.json").read_text(encoding="utf-8"))
        rows = [json.loads(line) for line in (seed_dir / "test_predictions.jsonl").read_text(encoding="utf-8").splitlines()]
        top2 = compute_top_k_accuracy([r["probabilities"] for r in rows], [r["true_label"] for r in rows], k=2)
        full_runs.append({
            "variant": "full",
            "seed": seed,
            "metrics": {
                "macro_f1": m["metrics"]["macro_f1"],
                "accuracy": m["metrics"]["accuracy"],
                "top_2_accuracy": top2,
            },
        })
    summary["full"] = full_runs

    for variant in args.variants:
        summary[variant] = []
        for seed in args.seeds:
            out_dir = args.output_root / variant / f"seed_{seed}"
            if (out_dir / "metrics.json").exists():
                print(f"[SKIP] {variant} seed_{seed} already exists")
                payload = json.loads((out_dir / "metrics.json").read_text(encoding="utf-8"))
            else:
                out_dir.mkdir(parents=True, exist_ok=True)
                print(f"\n[RUN] Ablation variant: {variant} | seed: {seed}")
                payload = train_single_ablation(variant, seed, data, identifiers, out_dir)
                print(f"[DONE] {variant} seed_{seed} -> Macro-F1: {payload['metrics']['macro_f1']:.4f}, Top-2: {payload['metrics']['top_2_accuracy']:.4f}")
            summary[variant].append(payload)

    # Summarize results
    results = {}
    full_f1_mean = statistics.mean([r["metrics"]["macro_f1"] for r in summary["full"]])
    for variant, runs in summary.items():
        f1s = [r["metrics"]["macro_f1"] for r in runs]
        top2s = [r["metrics"]["top_2_accuracy"] for r in runs]
        accs = [r["metrics"]["accuracy"] for r in runs]
        f1_mean = statistics.mean(f1s)
        delta = None if variant == "full" else (f1_mean - full_f1_mean)
        results[variant] = {
            "macro_f1_mean": f1_mean,
            "macro_f1_std": statistics.stdev(f1s) if len(f1s) > 1 else 0.0,
            "delta_f1": delta,
            "top_2_acc_mean": statistics.mean(top2s),
            "accuracy_mean": statistics.mean(accs),
        }

    out_file = args.output_root / "ablation_summary.json"
    out_file.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    # Generate Markdown table
    md_lines = [
        "# NSS 2026 GNNMHAv2 Ablation Study Summary",
        "",
        "| Variant | Macro-F1 (mean ± std) | $\\Delta$ | Top-2 Accuracy |",
        "| --- | ---: | ---: | ---: |",
    ]
    name_map = {
        "full": "Full model",
        "no_edge_attr": "-- edge attributes",
        "no_jk": "-- jumping knowledge",
        "ce_loss": "focal $\\rightarrow$ cross-entropy",
        "mean_pool": "attention+mean $\\rightarrow$ mean pooling",
        "layers_2": "$L=2$",
        "layers_3": "$L=3$",
        "heads_4": "$K=4$",
    }
    for v_key, label in name_map.items():
        if v_key in results:
            r = results[v_key]
            delta_str = "--" if r["delta_f1"] is None else f"{r['delta_f1']:+.4f}"
            md_lines.append(
                f"| {label} | {r['macro_f1_mean']:.4f} ± {r['macro_f1_std']:.4f} | {delta_str} | {r['top_2_acc_mean']:.4f} |"
            )

    md_file = args.output_root / "ablation_summary.md"
    md_file.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    print(f"\nSaved ablation summary to {out_file} and {md_file}")


if __name__ == "__main__":
    main()
