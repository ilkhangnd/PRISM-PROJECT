# PRISM RQ5 Patch Verification Artifacts

## Scope: Empirical Case Study (5 Contracts)
This directory contains the experimental verification ladder for RQ5 (Section 5.5 of the manuscript).
As explicitly stated in Section 5.5 and Section 6 (*Threats to Validity*), automated patch synthesis across arbitrary contracts is open future work; RQ5 evaluates template-based repairs on a 5-contract case study:
- `SimpleDAO` (reentrancy)
- `TokenSale` (integer overflow)
- `UnprotectedVault` (access control)
- `UncheckedBank` (unchecked return)
- `WeakLottery` (timestamp dependence pattern)

Each patch was verified through the five-step validation ladder:
1. Compilation validity (`solc 0.8.30`)
2. Minimality (<25% AST line delta)
3. Exploit harness regression / negation
4. Invariant fuzzing pass (10,000 iterations)
5. Preservation of ABI selectors and storage layout

## Relationship to RQ2 Benchmark
In RQ2, execution reliability on SWC-114 was standardized to `TimestampLock.sol` with 30 PRNG seeds. For the patch verification ladder (RQ5), the 5 template repair instances recorded here are preserved for exact reproduction of the reported AST and EVM checks.
