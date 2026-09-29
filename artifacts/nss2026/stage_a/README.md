# Stage-A Multi-Seed Metrics Provenance

The canonical fresh Stage-A runs are in `../stage_a_fresh/seed_*/`. Each seed directory contains a trained checkpoint, `metrics.json`, test predictions, and SHA-256 checksums for the binary gate's held-out test split ($n=3{,}669$: 3,132 vulnerable functions and 537 safe functions).

## Provenance Disclosure
- **Status:** Fresh five-seed execution, seeds 42--46.
- **Protocol:** Frozen stratified 70/15/15 binary split over 24,454 graphs; labels 0--7 are vulnerable and label 8 is safe. The manifest is `../stage_a_manifest.json`.
- **Aggregate values reported in Section 5.1:**
  - Accuracy: $88.62 \pm 0.24\%$
  - Vulnerable recall: $87.82 \pm 0.32\%$
  - Safe specificity: $93.26 \pm 0.61\%$
- **Legacy files:** `seed_*/metrics.json` in this directory are retained only as explicitly labelled reconstructed summaries. They are not the canonical source for the manuscript.
