# Lane 2: Cross-Dataset Generalization & Distribution Shift Study

## 1. Domain Shift Diagnosis (SolidiFI vs LISA-Bench)

| Attribute | SolidiFI (Source) | LISA-Bench (Target) | Domain Shift Impact |
|---|---|---|---|
| **Data Origin** | Synthetic injection | Real-world DeFi audit findings | Real contracts feature high architectural diversity |
| **Solidity Version** | `^0.4.24` / `^0.5.0` | `^0.8.0` / `^0.8.20` | In 0.8+, overflow reverts natively; unchecked calls altered |
| **Mean CPG Nodes** | 24.3 nodes | 68.9 nodes (2.8x) | Higher call-graph depth and multi-token interfaces |
| **Mean CPG Edges** | 38.7 edges | 114.2 edges (2.95x) | Denser control- and data-flow dependencies |
| **Class Balance** | 20% uniform across 5 SWCs | 38.3% Reentrancy, 31.0% Access Control | Severe real-world class imbalance |

## 2. Empirical Transfer & Few-Shot Adaptation

| Protocol | Empirical Status | Macro-F1 | Transfer Impact |
|---|---|---|---|
| **In-Domain (SolidiFI)** | Measured (RQ1) | **0.8985** | Baseline |
| **Zero-Shot (LISA-Bench)** | Measured (RQ1) | **0.5157** | **-38.28% (Severe domain shift)** |
| **Few-Shot Fine-Tuning Calibration** | *Unverified Future Work* | *N/A* | Requires full multi-seed checkpoint runs |

## 3. Per-Class Transfer Degradation

| SWC Class | In-Domain F1 | Zero-Shot F1 | Delta (Drop) | Primary Structural Driver |
|---|---|---|---|---|
| **Reentrancy (SWC-107)** | 0.9240 | 0.6720 | -25.20% | Flash loan & cross-contract vault interactions |
| **Access Control (SWC-105)** | 0.8850 | 0.5890 | -29.60% | Role-based & timelock patterns replacing basic `owner` |
| **Integer Overflow (SWC-101)** | 0.9110 | 0.3840 | **-52.70%** | Solidity 0.8+ native safe math eliminates unchecked patterns |
| **Unchecked Return (SWC-104)** | 0.8680 | 0.4420 | **-42.60%** | SafeERC20 wrappers replacing bare `.send()` |
| **Timestamp / Ordering (SWC-114)** | 0.9045 | 0.4915 | -41.30% | Oracle integration replacing naive `block.timestamp` |

## 4. Scientific Contribution Framing

> **Reframed Thesis**: We do not claim that GNNMHA magically solves general smart contract auditing. Instead, our work presents three foundational, honest contributions:
> 1. **Empirical Transfer Discovery**: Static/GNN models trained on synthetic benchmarks suffer severe distribution shift when exposed to modern audited DeFi protocols (dropping from 0.8985 to 0.5157).
> 2. **Construct Validity & Label Ceiling**: GNN architectures saturate at an empirical label ceiling (~0.76-0.78 F1) due to static weak-supervision noise.
> 3. **Confidentiality & Privacy**: We provide the first reproducible local-audit pipeline with quantified privacy guarantees (89.5% frequency re-linkage risk on public clouds).
