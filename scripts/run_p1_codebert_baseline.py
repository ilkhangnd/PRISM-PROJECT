#!/usr/bin/env python3
"""
PRISM P1-I: CodeBERT Baseline Training & Evaluation on the Canonical 5-Class Corpus.

Evaluates microsoft/codebert-base on the identical frozen splits (random_stratified, lineage_disjoint)
and corpus manifest (12,991 functions) as the GNN architectures.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import accuracy_score, classification_report, f1_score, precision_score, recall_score
from torch.optim import AdamW
from torch.utils.data import DataLoader, Dataset
from transformers import AutoModelForSequenceClassification, AutoTokenizer, get_linear_schedule_with_warmup

ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = ROOT / "artifacts/nss2026/corpus_manifest.json"
SPLIT_PATH = ROOT / "artifacts/nss2026/frozen_splits.json"

LABELS = ["reentrancy", "integer_overflow", "access_control", "unchecked_return", "front_running"]


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def extract_function_code(source: str, func_name: str) -> str:
    """Extract callable function source code snippet using bracket-depth matching."""
    short_name = func_name.split(".")[-1] if "." in func_name else func_name
    if short_name.startswith("slitherConstructor") or short_name in ("fallback", "receive"):
        return source[:1000]

    pattern = rf"(function\s+{re.escape(short_name)}\s*\([^)]*\)[^{{]*\{{)"
    m = re.search(pattern, source)
    if not m and short_name == "constructor":
        m = re.search(r"(constructor\s*\([^)]*\)[^{]*\{)", source)
    if not m:
        return source[:1000]

    start_pos = m.start()
    depth = 0
    in_str = False
    for i in range(m.end() - 1, len(source)):
        c = source[i]
        if c == '"' and (i == 0 or source[i - 1] != "\\"):
            in_str = not in_str
        elif not in_str:
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return source[start_pos : i + 1]
    return source[start_pos : start_pos + 1000]


class CodeTextDataset(Dataset):
    def __init__(self, records: List[Dict[str, Any]], tokenizer: Any, max_length: int = 256):
        self.records = records
        self.tokenizer = tokenizer
        self.max_length = max_length
        self._cached_texts: List[str] = []

        file_cache: Dict[str, str] = {}
        for r in records:
            p_str = r["source_file"]
            if p_str not in file_cache:
                p = ROOT / p_str
                if p.exists():
                    file_cache[p_str] = p.read_text(encoding="utf-8", errors="ignore")
                else:
                    file_cache[p_str] = ""
            src = file_cache[p_str]
            fn_code = extract_function_code(src, r["function_name"])
            self._cached_texts.append(fn_code)

    def __len__(self) -> int:
        return len(self.records)

    def __getitem__(self, idx: int) -> Dict[str, Any]:
        text = self._cached_texts[idx]
        item = self.records[idx]
        encoding = self.tokenizer(
            text,
            truncation=True,
            max_length=self.max_length,
            padding="max_length",
            return_tensors="pt"
        )
        return {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "label": torch.tensor(item["canonical_label_id"], dtype=torch.long),
            "sample_id": item["sample_id"]
        }


def main():
    parser = argparse.ArgumentParser(description="P1-I: CodeBERT Baseline on Canonical Smart Contract Corpus")
    parser.add_argument("--split", choices=("random", "lineage"), default="random")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--learning-rate", type=float, default=2e-5)
    parser.add_argument("--max-length", type=int, default=256)
    parser.add_argument("--device", type=str, default="auto")
    parser.add_argument("--eval-only", action="store_true", help="Evaluate existing checkpoint")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()

    set_seed(args.seed)

    if args.device == "auto":
        if torch.backends.mps.is_available():
            device = torch.device("mps")
        elif torch.cuda.is_available():
            device = torch.device("cuda")
        else:
            device = torch.device("cpu")
    else:
        device = torch.device(args.device)

    print(f"Using device: {device}")

    # Output directory
    default_out = ROOT / f"artifacts/nss2026/runs/{args.split}/codebert/seed_{args.seed}"
    out_dir = (args.output_dir or default_out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # Load Manifest & Frozen Splits
    with MANIFEST_PATH.open(encoding="utf-8") as f:
        corpus = json.load(f)
    records_by_id = {r["sample_id"]: r for r in corpus["records"]}

    with SPLIT_PATH.open(encoding="utf-8") as f:
        splits = json.load(f)

    split_key = "random_stratified" if args.split == "random" else "lineage_disjoint"
    split_info = splits[split_key]
    train_ids = split_info["sample_ids"]["train"]
    val_ids = split_info["sample_ids"]["val"]
    test_ids = split_info["sample_ids"]["test"]

    train_records = [records_by_id[i] for i in train_ids]
    val_records = [records_by_id[i] for i in val_ids]
    test_records = [records_by_id[i] for i in test_ids]

    print(f"Loaded split '{args.split}': train={len(train_records)}, val={len(val_records)}, test={len(test_records)}")

    # Load Model & Tokenizer
    model_name = "microsoft/codebert-base"
    print(f"Loading {model_name}...")
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=5)
    model.to(device)

    # Datasets & DataLoaders
    train_ds = CodeTextDataset(train_records, tokenizer, max_length=args.max_length)
    val_ds = CodeTextDataset(val_records, tokenizer, max_length=args.max_length)
    test_ds = CodeTextDataset(test_records, tokenizer, max_length=args.max_length)

    train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=args.batch_size, shuffle=False)
    test_loader = DataLoader(test_ds, batch_size=args.batch_size, shuffle=False)

    best_model_path = out_dir / "best_model.pt"

    if not args.eval_only:
        optimizer = AdamW(model.parameters(), lr=args.learning_rate, weight_decay=0.01)
        total_steps = len(train_loader) * args.epochs
        scheduler = get_linear_schedule_with_warmup(optimizer, num_warmup_steps=int(total_steps * 0.1), num_training_steps=total_steps)

        best_val_f1 = -1.0
        start_time = time.time()

        for epoch in range(1, args.epochs + 1):
            model.train()
            train_loss = 0.0
            for step, batch in enumerate(train_loader):
                optimizer.zero_grad()
                input_ids = batch["input_ids"].to(device)
                attention_mask = batch["attention_mask"].to(device)
                labels = batch["label"].to(device)

                outputs = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)
                loss = outputs.loss
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()
                scheduler.step()
                train_loss += loss.item()

            train_loss /= len(train_loader)

            # Validation
            model.eval()
            val_preds, val_truth = [], []
            with torch.no_grad():
                for batch in val_loader:
                    input_ids = batch["input_ids"].to(device)
                    attention_mask = batch["attention_mask"].to(device)
                    logits = model(input_ids=input_ids, attention_mask=attention_mask).logits
                    preds = logits.argmax(dim=-1).cpu().tolist()
                    val_preds.extend(preds)
                    val_truth.extend(batch["label"].tolist())

            val_f1 = f1_score(val_truth, val_preds, average="macro", zero_division=0)
            val_acc = accuracy_score(val_truth, val_preds)
            print(f"Epoch {epoch}/{args.epochs} | Train Loss: {train_loss:.4f} | Val Acc: {val_acc:.4f} | Val Macro-F1: {val_f1:.4f}")

            if val_f1 > best_val_f1:
                best_val_f1 = val_f1
                torch.save(model.state_dict(), best_model_path)
                print(f"  -> Saved best model checkpoint to {best_model_path}")

        print(f"Training completed in {(time.time() - start_time) / 60:.2f} mins.")

    # Test Evaluation
    if best_model_path.exists():
        print(f"Loading best checkpoint from {best_model_path} for final evaluation...")
        model.load_state_dict(torch.load(best_model_path, map_location=device))

    model.eval()
    test_preds, test_truth, test_probs, test_sids = [], [], [], []
    with torch.no_grad():
        for batch in test_loader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            logits = model(input_ids=input_ids, attention_mask=attention_mask).logits
            probs = torch.softmax(logits, dim=-1).cpu().tolist()
            preds = logits.argmax(dim=-1).cpu().tolist()

            test_preds.extend(preds)
            test_probs.extend(probs)
            test_truth.extend(batch["label"].tolist())
            test_sids.extend(batch["sample_id"])

    report = classification_report(test_truth, test_preds, labels=list(range(5)), target_names=LABELS, output_dict=True, zero_division=0)
    test_metrics = {
        "schema_version": "1.0",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "model": "microsoft/codebert-base",
        "split": args.split,
        "seed": args.seed,
        "accuracy": accuracy_score(test_truth, test_preds),
        "macro_precision": precision_score(test_truth, test_preds, average="macro", zero_division=0),
        "macro_recall": recall_score(test_truth, test_preds, average="macro", zero_division=0),
        "macro_f1": f1_score(test_truth, test_preds, average="macro", zero_division=0),
        "classification_report": report,
        "per_class_f1": {name: report[name]["f1-score"] for name in LABELS}
    }

    # Save metrics.json
    metrics_file = out_dir / "metrics.json"
    metrics_file.write_text(json.dumps(test_metrics, indent=2))
    print(f"Test Metrics written to {metrics_file}")
    print(f"Test Accuracy: {test_metrics['accuracy']:.4f}, Macro-F1: {test_metrics['macro_f1']:.4f}")

    # Save test_predictions.jsonl
    preds_file = out_dir / "test_predictions.jsonl"
    with preds_file.open("w", encoding="utf-8") as f:
        for sid, y, pred, p in zip(test_sids, test_truth, test_preds, test_probs):
            row = {"sample_id": sid, "true_label": y, "predicted_label": pred, "probabilities": p}
            f.write(json.dumps(row) + "\n")
    print(f"Test predictions written to {preds_file}")


if __name__ == "__main__":
    main()
