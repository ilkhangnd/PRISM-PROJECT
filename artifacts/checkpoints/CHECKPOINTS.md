# PRISM Trained Model Checkpoints

This directory documents the model weights and configuration for the GNNMHAv2 multi-relational graph attention network evaluated in the NSS 2026 submission.

## Architecture Configuration
- **Model Type**: GNNMHAv2 (`MultiHeadGATv2WithEdgeAttrs`)
- **Input Node Dimension**: 13 (syntactic and data-flow SSA node features)
- **Edge Types**: 4 relational types (AST, CFG, DFG, Call graph)
- **Hidden Dimensions**: 64
- **Attention Heads**: $K=8$
- **Head Aggregation**: Averaging ($\frac{1}{K}\sum$)
- **Layers**: $L=2$
- **Jumping Knowledge**: Concatenation of layer outputs
- **Readout Pooling**: Hybrid Attention + Mean pooling
- **Classification Loss**: Multi-class Focal Loss ($\gamma = 2.0$)
- **Parameters**: ~187,000 parameters

## Trained Seeds
Checkpoints for all 5 independent seeds (Seeds 42, 43, 44, 45, 46) on both the random split and lineage-disjoint split are preserved with reproducible evaluation scripts in `../scripts/`.
