# NSS 2026 GNNMHAv2 Ablation Study Summary

| Variant | Macro-F1 (mean ± std) | $\Delta$ | Top-2 Accuracy |
| --- | ---: | ---: | ---: |
| Full model | 0.7595 ± 0.0019 | -- | 0.8086 |
| -- edge attributes | 0.7603 ± 0.0011 | +0.0008 | 0.8085 |
| -- jumping knowledge | 0.7597 ± 0.0018 | +0.0002 | 0.8117 |
| focal $\rightarrow$ cross-entropy | 0.7584 ± 0.0012 | -0.0010 | 0.8097 |
| attention+mean $\rightarrow$ mean pooling | 0.7596 ± 0.0029 | +0.0001 | 0.8115 |
| $L=2$ | 0.7611 ± 0.0016 | +0.0016 | 0.8079 |
| $L=3$ | 0.7588 ± 0.0025 | -0.0007 | 0.8069 |
| $K=4$ | 0.7588 ± 0.0017 | -0.0007 | 0.8089 |
