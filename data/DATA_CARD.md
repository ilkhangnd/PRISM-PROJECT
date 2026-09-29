# PRISM Dataset Card (V2 Hierarchical Feature Representation)

**Date Generated:** 2026-08-30T16:20:35.779321+00:00  
**Total Samples Enumerate:** 24,454 graphs  
**Unique Graphs:** 1,485  
**Structural Duplicates (pre-filtered):** 22,969  
**Base Project / Contract Families:** 1,142  

---

## 1. Dataset Breakdown & Provenance

| Dataset Source | License | Total Graphs | Unique Families | Node Dim | Edge Dim | Upstream Repository |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **SmartBugs** | MIT | 1,179 | 125 | 32 | 4 | `https://github.com/smartbugs/smartbugs-wild` |
| **SolidiFI** | GPL-3.0 | 19,568 | 42 | 32 | 4 | `https://github.com/dependents/Solidifi-Benchmark` |
| **LISA-Bench** | Apache-2.0 | 3,707 | 975 | 32 | 4 | `https://github.com/lisa-benchmark/lisa-contracts` |
| **Total Corpus** | Multi-license | **24,454** | **1,142** | **32** | **4** | Combined Canonical Corpus |

---

## 2. Label Taxonomy & Class Distribution

| Class ID | Vulnerability Class | Canonical Top-5 | Corpus Frequency | Description & SWC Mapping |
| :---: | :--- | :---: | :---: | :--- |
| **0** | `reentrancy` | Yes | 2,737 | SWC-107: State updates after low-level external calls |
| **1** | `integer_overflow` | Yes | 3,014 | SWC-101: Unchecked arithmetic wrap-around in Solidity <0.8 |
| **2** | `access_control` | Yes | 5,773 | SWC-105/106: Unprotected state-mutating external functions |
| **3** | `unchecked_return` | Yes | 29 | SWC-104: Ignored boolean return from `send()` / `call()` |
| **4** | `front_running` | Yes | 1,440 | SWC-114: Transaction-ordering dependence (TOD / Front-running) |
| **5-9** | `other_extended` | Extended | 11,461 | Timestamp dependence (SWC-116), Delegatecall, Tx.Origin, and Clean baseline graphs |

---

## 3. Sample-Level Manifest & Deduplication

The complete sample-level manifest is available at [`data/sample_manifest.csv`](data/sample_manifest.csv).  
Each entry explicitly details:
- **`sample_id`**: Globally unique graph identifier.
- **`project_or_base_family`**: Group identifier used to enforce zero-leakage group splitting.
- **`graph_hash`**: SHA-256 fingerprint computed across all node features and edge adjacency tensors.
- **`dedupe_decision`**: Verification flag indicating unique graph or duplicate identifier.
- **`split_assignment`**: Assigned split partition (`train`, `val`, `test`).
