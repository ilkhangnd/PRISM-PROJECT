# PRISM RQ2 Fuzzing & Execution Artifacts

## Canonical Phase-2 Benchmark
The primary execution benchmark reported in RQ2 (Section 5.2 of the manuscript) covers 30 PRNG seeds (seeds 101 to 130) across 5 canonical SWC vulnerability classes:
1. `SimpleDAO` (SWC-107, Reentrancy)
2. `TokenSale` (SWC-101, Integer Overflow)
3. `UnprotectedVault` (SWC-105, Access Control)
4. `UncheckedBank` (SWC-104, Unchecked Return Value)
5. `TimestampLock` (SWC-114, Timestamp Dependence)

### Output Files:
- Canonical dataset: `artifacts/rq2_fuzzing_results.json` (and synchronized at `artifacts/results/rq2_fuzzing_results.json`)
- Comprehensive campaign report: `research/04-results/rq2_fuzzing_campaign_report.md`
- Runner script: `scripts/run_rq2_fuzzing_benchmark.py`
- Test workspace: `artifacts/fuzzing_runs/benchmark_workspace/`

## Note on Historical/Pilot Files
Early development iterations initially experimented with an out-of-taxonomy lottery contract before the RQ2 benchmark was rigorously standardized to `TimestampLock` for full 5/5 SWC core taxonomy alignment. All current manuscript tables and primary result JSONs reflect `TimestampLock`.
