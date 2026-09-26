"""
GNN Trainer — Training loop with early stopping and metrics logging.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import torch
import torch.nn as nn
from torch.optim import Adam
from torch.optim.lr_scheduler import ReduceLROnPlateau

logger = logging.getLogger(__name__)


@dataclass
class TrainConfig:
    """Training configuration."""

    epochs: int = 200
    learning_rate: float = 0.001
    weight_decay: float = 0.0001
    patience: int = 20
    model_save_path: str = "models/gnn_mha/best_model.pt"


class GNNTrainer:
    """Handles training, validation, and evaluation of GNN models."""

    def __init__(self, model: nn.Module, config: TrainConfig | None = None):
        self.model = model
        self.config = config or TrainConfig()
        self.device = torch.device(
            "cuda" if torch.cuda.is_available() else "mps" if torch.backends.mps.is_available() else "cpu"
        )
        self.model.to(self.device)
        self.optimizer = Adam(model.parameters(), lr=self.config.learning_rate, weight_decay=self.config.weight_decay)
        self.scheduler = ReduceLROnPlateau(self.optimizer, mode="min", patience=5, factor=0.5)
        self.criterion = nn.CrossEntropyLoss()

    def train_epoch(self, train_loader) -> float:
        """Run one training epoch."""
        self.model.train()
        total_loss = 0

        for batch in train_loader:
            batch = batch.to(self.device)
            self.optimizer.zero_grad()
            out = self.model(batch.x, batch.edge_index, batch.batch)
            loss = self.criterion(out, batch.y)
            loss.backward()
            self.optimizer.step()
            total_loss += loss.item() * batch.num_graphs

        return total_loss / len(train_loader.dataset)

    @torch.no_grad()
    def evaluate(self, loader) -> dict:
        """Evaluate model on a data loader."""
        self.model.eval()
        correct, total, total_loss = 0, 0, 0

        all_preds, all_labels = [], []
        for batch in loader:
            batch = batch.to(self.device)
            out = self.model(batch.x, batch.edge_index, batch.batch)
            loss = self.criterion(out, batch.y)
            total_loss += loss.item() * batch.num_graphs
            pred = out.argmax(dim=1)
            correct += (pred == batch.y).sum().item()
            total += batch.num_graphs
            all_preds.extend(pred.cpu().tolist())
            all_labels.extend(batch.y.cpu().tolist())

        return {"loss": total_loss / total, "accuracy": correct / total, "predictions": all_preds, "labels": all_labels}

    def train(self, train_loader, val_loader) -> dict:
        """Full training loop with early stopping."""
        best_val_loss = float("inf")
        patience_counter = 0
        history = {"train_loss": [], "val_loss": [], "val_accuracy": []}

        for epoch in range(1, self.config.epochs + 1):
            train_loss = self.train_epoch(train_loader)
            val_metrics = self.evaluate(val_loader)

            history["train_loss"].append(train_loss)
            history["val_loss"].append(val_metrics["loss"])
            history["val_accuracy"].append(val_metrics["accuracy"])

            self.scheduler.step(val_metrics["loss"])

            if val_metrics["loss"] < best_val_loss:
                best_val_loss = val_metrics["loss"]
                patience_counter = 0
                self.save_model(self.config.model_save_path)
            else:
                patience_counter += 1

            if epoch % 10 == 0:
                logger.info(
                    f"Epoch {epoch}: train_loss={train_loss:.4f}, "
                    f"val_loss={val_metrics['loss']:.4f}, val_acc={val_metrics['accuracy']:.4f}"
                )

            if patience_counter >= self.config.patience:
                logger.info(f"Early stopping at epoch {epoch}")
                break

        return history

    def save_model(self, path: str) -> None:
        """Save model checkpoint."""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        torch.save(self.model.state_dict(), path)

    def load_model(self, path: str) -> None:
        """Load model from checkpoint."""
        self.model.load_state_dict(torch.load(path, map_location=self.device))
