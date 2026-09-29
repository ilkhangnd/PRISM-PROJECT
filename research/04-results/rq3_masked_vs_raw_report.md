# PRISM RQ3 Masked vs. Raw LLM Semantic Audit Report (P1-F)

**Date**: 2026-09-29T06:43:50.654031+00:00  
**LLM Evaluated**: `deepseek-coder-v2:latest` via local Ollama  
**Dataset**: 57 canonical benchmark contracts (30 vulnerable, 27 clean)  

## Key Results & Nuanced Breakdown
- **Hypothesis Jaccard Similarity (All 57 pairs)**: **0.4561**
- **Hypothesis Jaccard Similarity (49 Non-Empty pairs)**: **0.3673**
- **Vulnerable Recall ($n=30$)**:
  - Raw Code: **30/30 (100.0%)**
  - Masked Code: **13/30 (43.3%)**
- **Safe Specificity ($n=27$)**:
  - Raw Code: **11/27 (40.7%)**
  - Masked Code: **19/27 (70.4%)**
- **Overall Agreement**: Raw **71.9%** $\to$ Masked **56.1%** ($\Delta = -15.8$ points)

## Scientific Takeaway
1. **Taxonomy Guidance vs False Alarms**: Structured SWC taxonomy guidance enables the local LLM to capture 30/30 (100.0%) vulnerable raw contracts, but triggers spurious alarms on safe contracts (40.7% specificity). This empirical finding validates PRISM's dynamic verification tier to weed out false positives.
2. **Impact of Pseudonymization**: Identifier masking renames business variables (`owner`, `balances`), reducing zero-shot text recall on synthetic snippets to 43.3% (13/30), while filtering out noisy alarms on safe contracts (70.4% specificity). For EVM built-ins like `block.timestamp` and external `.call`, predictions remain identical ($J=1.00$).

## Paste-ready Text for RQ3 (Slot S4)
> *Under taxonomy-guided auditing across the five SWC classes, raw-code recall on the 30 vulnerable contracts reaches 30/30 (100.0%) with 11/27 (40.7%) safe specificity. On pseudonymized code, masked recall achieves 13/30 (43.3%) while safe specificity increases to 19/27 (70.4%). Across all 57 contracts, hypotheses agree with mean Jaccard similarity 0.46 (0.37 on non-empty pairs).*
