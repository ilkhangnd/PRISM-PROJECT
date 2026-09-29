# PRISM: Confidential Smart Contract Auditing with Pseudonymized Graph Screening

[![Paper](https://img.shields.io/badge/Paper-NSS--2026-blue)](paper/main.pdf)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-brightgreen)](https://www.python.org/)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.2%2B-ee4c2c)](https://pytorch.org/)
[![Foundry](https://img.shields.io/badge/Foundry-Forge-red)](https://getfoundry.sh/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Official implementation and empirical artifact for **PRISM**, a local-first smart-contract auditing prototype. PRISM combines reversible pseudonymization, graph-based function screening, local LLM hypotheses, and versioned Foundry reference-harness validation. It does not claim automated harness synthesis or benchmark-wide end-to-end dynamic performance.

---

## 🔍 Overview & System Architecture

Auditing smart contracts often faces a critical trilemma:
1. **Cloud LLM security risks**: sending private smart contracts to proprietary cloud APIs leaks trade secrets and zero-day vulnerabilities.
2. **Static analyzer alarm fatigue**: rule-based analyzers like Slither flood auditors with false positives (e.g. 27/27 safe contracts flagged).
3. **Fuzzer path explosion**: dynamic fuzzers struggle to reach deep business-logic states without guided invariant harnesses.

**PRISM is organized as the following local stages:**
1. **PrivacyFilter & DataMasker**: Reversibly pseudonymize user-defined identifiers and remove configured secrets before learned analysis.
2. **SSA Code Property Graph (CPG)**: Construct typed function-level graphs from Slither SSA IR.
3. **Stage-A gate and GNN ranker**: Screen and prioritize functions across five SWC classes.
4. **Local LLM audit**: Produce masked-code hypotheses. These hypotheses are not treated as confirmed findings.
5. **Foundry reference-harness validation**: Execute pre-authored, versioned invariant and exploit tests for scoped canonical cases. This branch is independent of LLM output.

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
 [GNNMHAv2 Classifier] ──> Hotspot Ranking
       │
       ├──────────────► [Local LLM] ──> Unconfirmed hypotheses
       │
       └──────────────► [Foundry reference harnesses] ──> Scoped execution evidence
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

### Evidence scope

- The 57-contract experiment measures the static filtering cascade and pseudonymization utility.
- The five canonical contracts have pre-authored Foundry reference harnesses. Their 300 seeded runs and the five-case integrated trace are reproducible execution evidence.
- No artifact in this repository establishes general-purpose harness synthesis, 57-contract end-to-end recall/specificity, or LLM-generated repair performance. See [`research/04-results/LANE2_EVIDENCE_STATUS.md`](research/04-results/LANE2_EVIDENCE_STATUS.md).

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

### 5. Reproduce the scoped five-case integration trace
```bash
python scripts/run_nss2026_reference_e2e.py \
  --with-llm --llm-compact --llm-max-tokens 128 \
  --llm-timeout-seconds 105 --llm-request-timeout-seconds 90 \
  --route-via-gnn --seed 42 --fuzz-runs 10000 \
  --output artifacts/nss2026/e2e_reference/reproduction_run
```
This command requires a locally running Ollama instance with the configured model, Slither, a local `solc`, and Foundry. It uses pre-authored harnesses and records all stage outcomes without substituting mock LLM output.

### 6. Generate Confusion Matrices
```bash
python scripts/generate_styled_confusion_matrices.py
```

### 7. Audit Double-Blind Anonymity Compliance
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
  title     = {PRISM: Confidential Smart Contract Auditing with Pseudonymized Graph Screening},
  booktitle = {Proceedings of the 20th International Conference on Network and System Security (NSS 2026)},
  year      = {2026},
  publisher = {Springer}
}
```
