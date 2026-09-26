# PRISM: Privacy-Preserving Smart Contract Auditing with Edge-Aware Graph Attention, Local LLMs, and EVM Validation

[![Paper](https://img.shields.io/badge/Paper-NSS--2026-blue)](paper/main.pdf)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-brightgreen)](https://www.python.org/)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.2%2B-ee4c2c)](https://pytorch.org/)
[![Foundry](https://img.shields.io/badge/Foundry-Forge-red)](https://getfoundry.sh/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Official implementation and empirical artifact for **PRISM**, an end-to-end, privacy-preserving smart contract audit pipeline that runs entirely on local infrastructure.

---

## 🔍 Overview & System Architecture

Auditing smart contracts often faces a critical trilemma:
1. **Cloud LLM security risks**: sending private smart contracts to proprietary cloud APIs leaks trade secrets and zero-day vulnerabilities.
2. **Static analyzer alarm fatigue**: rule-based analyzers like Slither flood auditors with false positives (e.g. 27/27 safe contracts flagged).
3. **Fuzzer path explosion**: dynamic fuzzers struggle to reach deep business-logic states without guided invariant harnesses.

**PRISM resolves this through a 5-stage pipeline:**
1. **PrivacyFilter & DataMasker**: Reversibly pseudonymizes code identifiers (functions, variables, state variables) while strictly preserving AST and SSA semantics.
2. **SSA Code Property Graph (CPG)**: Constructs a unified semantic graph combining Control Flow (CFG), Data Flow (DFG), and Call dependencies from Slither SSA IR.
3. **Edge-Aware Multi-Head GAT (GNNMHAv2)**: Flags and prioritizes vulnerable hotspots across five canonical SWC taxonomy classes.
4. **Quantized Local LLM**: Directs deep-state invariant harness generation on local inference hardware (zero cloud egress).
5. **EVM Dynamic Execution & Verification**: Runs high-speed dual-mode fuzzing campaigns in Foundry to confirm exploitability and validate automated candidate patches.

```
Solidity Source
       │
       ▼
 [PrivacyFilter & DataMasker] ──> Reversible Token Mapping
       │
       ▼
 [Slither SSA -> CPG Builder] ──> Function-level CPGs
       │
       ▼
 [Stage-A Binary Screening Gate] ──> Safe / Vulnerable
       │
       ▼ (if flagged)
 [GNNMHAv2 Edge-Aware Classifier] ──> Top-k Hotspot Ranking
       │
       ▼
 [Local Quantized LLM] ──> Synthesizes Foundry Invariant Harnesses
       │
       ▼
 [Foundry EVM Execution] ──> Exploit Verification & Validated Patches
```

---

## 📁 Repository Layout

```
PRISM-PROJECT/
├── paper/                      # NSS 2026 Paper sources and compiled PDF
│   ├── main.tex                # Full paper LaTeX manuscript (anonymous)
│   ├── main.pdf                # Compiled manuscript PDF
│   ├── references.bib          # Bibliography database
│   └── figures/                # High-resolution vector & raster figures
├── src/                        # Core PRISM Python implementation
│   ├── pipeline.py             # End-to-end audit pipeline coordinator
│   ├── cli.py                  # Command-line interface
│   ├── preprocessing/          # DataMasker, PrivacyFilter, CFG/DFG/CPG builders
│   ├── sai/                    # GNNMHAv2 architecture, layers, loss functions
│   ├── analysis/               # Slither analysis & IR extraction
│   ├── fuzzing/                # Foundry invariant harness generation & execution
│   └── security/               # Secret scanning & de-identification
├── configs/                    # Experiment & model configurations
├── benchmarks/                 # Verification benchmarks
│   ├── foundry_campaign/       # Standalone Foundry fuzzing project (foundry.toml, src, test)
│   ├── contracts/              # Target benchmark smart contracts
│   └── harnesses/              # Reference Foundry invariant harnesses
├── artifacts/                  # Empirical evaluation evidence
│   ├── taxonomy.json           # Canonical SWC vulnerability taxonomy
│   ├── corpus/                 # Frozen train/val/test splits (seed 42) & label policy
│   ├── results/                # Complete empirical results (ablation, multiseed, privacy)
│   └── checkpoints/            # Model checkpoint specifications
├── scripts/                    # Reproduction & evaluation automation scripts
├── tests/                      # Unit and integration test suite
├── requirements.txt            # Python dependencies
├── pyproject.toml              # Build & project metadata
└── LICENSE                     # Open-source license
```

---

## 🚀 Quickstart & Installation

### Prerequisites
- **Python**: >= 3.11
- **Foundry**: `curl -L https://foundry.sh | bash && foundryup`
- **Slither**: `pip install slither-analyzer`
- **Solc**: `solc-select install 0.8.20 0.8.24 && solc-select use 0.8.20`

### Setup Environment
```bash
# Clone and enter directory
cd PRISM-PROJECT

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

---

## 🔬 Reproducing NSS 2026 Empirical Results

### 1. Summarize 5-Seed Baseline Comparisons (Table 2 & Table 3)
```bash
python scripts/summarize_nss2026_baselines.py
```

### 2. Full 7-Variant Ablation Study
```bash
python scripts/run_nss2026_ablation.py
```

### 3. Privacy & Linkage Attack Telemetry (RQ3)
```bash
python scripts/run_nss2026_privacy_audit.py
```

### 4. Dynamic Foundry Invariant Fuzzing (RQ2)
```bash
python scripts/run_rq2_fuzzing_benchmark.py
# Or run Foundry tests directly:
cd benchmarks/foundry_campaign
forge test -vv
```

### 5. Generate Confusion Matrices
```bash
python scripts/generate_styled_confusion_matrices.py
```

### 6. Audit Double-Blind Anonymity Compliance
```bash
python scripts/audit_nss2026_anonymity.py
```

---

## 🧪 Running Unit Tests
```bash
pytest tests/ -v
```

---

## 📜 Citation & License
This project is released under the **MIT License**.
For academic citations, please refer to:
```bibtex
@inproceedings{prism2026nss,
  title     = {PRISM: Confidential Smart Contract Auditing via Pseudonymized Graph Screening and Local Dynamic Verification},
  booktitle = {Proceedings of the 20th International Conference on Network and System Security (NSS 2026)},
  year      = {2026},
  publisher = {Springer}
}
```
