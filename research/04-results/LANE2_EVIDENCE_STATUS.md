# Lane 2 evidence status

The files listed below are retained for development only. They are not part of
the NSS 2026 supplementary evidence and must not be cited as empirical results.

* `artifacts/results/e2e_pipeline_coverage_57.*` is a coverage ledger derived
  from existing static-cascade and case-study records. It is not a 57-contract
  execution trace.
* `artifacts/nss2026/function_gold_truth/*` is a scripted semantic review
  prototype. It is not an independently completed two-annotator study.
* `artifacts/results/lane2_llm_ablation_results.json` is an exploratory,
  hand-selected ten-contract prompt study. Its baseline evaluator and protocol
  require correction before any comparative recall claim.
* `artifacts/results/lane2_repair_benchmark_30.json` establishes compilation
  and textual-diff checks only. Dynamic validation is available only for the
  five pre-existing reference-harness cases.
* `artifacts/results/lane2_cross_dataset_generalization.json` is a planning
  scaffold with hard-coded values, not a reproduced calibration experiment.

The submission evidence remains the artifacts and claims cited in `paper/main.tex`:
the 57-contract static cascade, five reference harnesses over 300 seeded runs,
the raw-versus-masked LLM audit, and the five canonical patch validations.
