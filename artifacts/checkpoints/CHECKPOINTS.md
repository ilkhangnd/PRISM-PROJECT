# PRISM Trained Model Checkpoints

This directory documents the model weights and configuration for the GNNMHAv2 multi-relational graph attention network evaluated in the NSS 2026 submission.

## Architecture Configuration
- **Model Type**: GNNMHAv2 (`MultiHeadGATv2WithEdgeAttrs`)
- **Input Node Dimension**: 32 (13-d one-hot instruction type, 10 security indicators, 9 structural graph attributes)
- **Edge Types**: 4 relational types (`sequential`, `branch`, `loop_back`, `data_dep`)
- **Hidden Dimensions**: 256
- **Attention Heads**: $K=8$
- **Head Aggregation**: Averaging ($\frac{1}{K}\sum$)
- **Layers**: $L=4$
- **Jumping Knowledge**: Concatenation of layer outputs ($z_i \in \mathbb{R}^{1024}$)
- **Readout Pooling**: Hybrid Attention + Mean pooling ($g \in \mathbb{R}^{2048}$)
- **Classification Loss**: Multi-class Focal Loss ($\gamma = 2.0, \epsilon = 0.05$)
- **Parameters**: ~1.4M parameters

## Trained Seeds
Checkpoints for all 5 independent seeds (Seeds 42, 43, 44, 45, 46) on both the random split and lineage-disjoint split are preserved with reproducible evaluation scripts in `scripts/`.
