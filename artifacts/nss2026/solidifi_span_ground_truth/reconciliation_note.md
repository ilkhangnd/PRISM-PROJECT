# SolidiFI Span Ground Truth Reconciliation Note

## 1. Summary of Reconciliation
- **Previous Manuscript / To-Do Citation**: `4,928` uniquely mapped spans out of 9,369 injection spans.
- **Recomputed & Frozen Dataset Count**: `4,947` uniquely mapped spans out of 9,369 injection spans (`artifacts/nss2026/solidifi_span_ground_truth/unique_span_positive_rows.csv`).
- **Discrepancy**: Exactly `+19` spans ($4,947 - 4,928 = 19$).

## 2. Root Cause Analysis of the 19-Span Delta
1. **Methodology Difference**:
   - The initial draft count of `4,928` was generated using an AST-based Slither extraction script during early exploratory phases. Because SolidiFI contracts span legacy Solidity versions (`^0.4.24`, `^0.5.0`), AST compilation silently failed or skipped a handful of contracts due to pragma/compiler incompatibilities on modern toolchains.
   - The reproducible script `scripts/build_solidifi_span_ground_truth.py` utilizes a compiler-agnostic lexical brace-depth extractor with full block and line comment stripping. It processes 100% of all 350 BugLog CSVs and 350 `.sol` contracts without dropping legacy files.
2. **Span Attribution**:
   - Total published BugLog injection rows: **9,369** across 350 BugLogs.
   - Uniquely mapped to exactly one callable function/constructor: **4,947** (52.80%).
   - Unmapped (e.g., contract-level state variable declarations, structs, interface headers): **4,422** (47.20%).
   - Mathematical identity: $4,947 + 4,422 = 9,369$.

## 3. Data Integrity & Provenance Checksums
- **Script**: `scripts/build_solidifi_span_ground_truth.py`
- **Output CSV**: `artifacts/nss2026/solidifi_span_ground_truth/unique_span_positive_rows.csv`
  - SHA-256: `a2765cd506d8bc8ed6dc5fac1c9103de73298fca2947adcc7a625cba910fa924`
  - Row count: 4,947
- **Summary JSON**: `artifacts/nss2026/solidifi_span_ground_truth/summary.json`
- **Paper Synchronization**: `paper/main.tex` line 181 reflects `4,947/9,369`.
