# Lane 2: LLM Hypothesis-to-Verification Upgrade Report

**Model**: `deepseek-coder-v2:latest` (digest `63fb193b3a9b`, local Ollama execution, seed=42, temp=0.0)  
**Evaluation Set**: 10 contracts balanced across all 5 SWC classes and safe CEI implementations.

## Prompt & Schema Ablation Comparison (Corrected Multi-Schema Evaluator)

| Configuration | Valid JSON (%) | Avg Latency (s) | Recall (TPR) | Specificity (TNR) | F1-Score |
|---|---|---|---|---|---|
| `config_1_raw_full_zero_shot` | 100.0% | 3.22s | 60.0% | 80.0% | 0.6667 |
| `config_2_masked_full_guided` | 100.0% | 6.56s | 100.0% | 0.0% | 0.6667 |
| `config_3_raw_targeted_guided` | 100.0% | 8.74s | 100.0% | 60.0% | 0.8333 |
| `config_4_masked_targeted_guided` | 100.0% | 12.29s | 100.0% | 20.0% | 0.7143 |

## Key Findings & Construct Validity:
1. **Structured Decoding Mode**: Native Ollama `format='json'` with schema enforcement achieves **100.0% valid JSON rate** with zero parser crashes.
2. **Guided Schema Effect**: Guided schema with SWC taxonomy boosts vulnerability recall to **100.0%** across targeted candidate regions.
3. **CEI Specificity Hazard**: LLMs in isolation exhibit false-positive hallucinations on safe contracts (e.g., classifying Checks-Effects-Interactions implementations as reentrancy).
4. **Multi-Stage Architecture Justification**: Confirms that local LLMs should strictly serve as an **explanation/hypothesis generator**, while **Foundry dynamic execution** provides the empirical oracle.