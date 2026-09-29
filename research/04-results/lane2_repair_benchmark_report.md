# Lane 2: Expanded Multi-Contract Patch Verification Report

**Scope**: All 30 vulnerable contracts in the PRISM benchmark covering 5 SWC vulnerability classes.

## Summary Metrics & Explicit Claim Boundaries
- **Static Syntax Compilation (`solc 0.8.30`)**: **30/30 (100.0%) PASS**
- **Textual & Diff Minimality (<45% edit ratio or ≤4 lines)**: **30/30 (100.0%) PASS**
- **Dynamic Exploit Rejection (Foundry Invariant & Fuzzing)**: **5/5 (100.0%) PASS (strictly limited to the 5 canonical reference cases from RQ5)**
- **Remaining 25 Synthetic Contracts**: Patches verified for static syntax and minimality; dynamic execution verification is **open / unmeasured** pending automated harness synthesis.

## Per-Contract Repair Ladder Status

| Contract | SWC Class | solc 0.8.30 | Diff Minimality | Edit Ratio | Invariant / Harness Verification |
|---|---|---|---|---|---|
| `VulnAccessControl_0.sol` | `access_control` | PASS | PASS | 0.111 | `template_available_synthesis_open` |
| `VulnAccessControl_1.sol` | `access_control` | PASS | PASS | 0.111 | `template_available_synthesis_open` |
| `VulnAccessControl_2.sol` | `access_control` | PASS | PASS | 0.111 | `template_available_synthesis_open` |
| `VulnAccessControl_3.sol` | `access_control` | PASS | PASS | 0.111 | `template_available_synthesis_open` |
| `VulnAccessControl_4.sol` | `access_control` | PASS | PASS | 0.111 | `template_available_synthesis_open` |
| `VulnOverflow_0.sol` | `integer_overflow` | PASS | PASS | 0.364 | `template_available_synthesis_open` |
| `VulnOverflow_1.sol` | `integer_overflow` | PASS | PASS | 0.364 | `template_available_synthesis_open` |
| `VulnOverflow_2.sol` | `integer_overflow` | PASS | PASS | 0.364 | `template_available_synthesis_open` |
| `VulnOverflow_3.sol` | `integer_overflow` | PASS | PASS | 0.364 | `template_available_synthesis_open` |
| `VulnOverflow_4.sol` | `integer_overflow` | PASS | PASS | 0.364 | `template_available_synthesis_open` |
| `VulnReentrancy_0.sol` | `reentrancy` | PASS | PASS | 0.083 | `template_available_synthesis_open` |
| `VulnReentrancy_1.sol` | `reentrancy` | PASS | PASS | 0.083 | `template_available_synthesis_open` |
| `VulnReentrancy_2.sol` | `reentrancy` | PASS | PASS | 0.083 | `template_available_synthesis_open` |
| `VulnReentrancy_3.sol` | `reentrancy` | PASS | PASS | 0.083 | `template_available_synthesis_open` |
| `VulnReentrancy_4.sol` | `reentrancy` | PASS | PASS | 0.083 | `template_available_synthesis_open` |
| `VulnTimestamp_0.sol` | `front_running` | PASS | PASS | 0.3 | `template_available_synthesis_open` |
| `VulnTimestamp_1.sol` | `front_running` | PASS | PASS | 0.3 | `template_available_synthesis_open` |
| `VulnTimestamp_2.sol` | `front_running` | PASS | PASS | 0.3 | `template_available_synthesis_open` |
| `VulnTimestamp_3.sol` | `front_running` | PASS | PASS | 0.3 | `template_available_synthesis_open` |
| `VulnTimestamp_4.sol` | `front_running` | PASS | PASS | 0.3 | `template_available_synthesis_open` |
| `VulnUncheckedReturn_0.sol` | `unchecked_return` | PASS | PASS | 0.429 | `template_available_synthesis_open` |
| `VulnUncheckedReturn_1.sol` | `unchecked_return` | PASS | PASS | 0.429 | `template_available_synthesis_open` |
| `VulnUncheckedReturn_2.sol` | `unchecked_return` | PASS | PASS | 0.429 | `template_available_synthesis_open` |
| `VulnUncheckedReturn_3.sol` | `unchecked_return` | PASS | PASS | 0.429 | `template_available_synthesis_open` |
| `VulnUncheckedReturn_4.sol` | `unchecked_return` | PASS | PASS | 0.429 | `template_available_synthesis_open` |
| `SimpleDAO.sol` | `reentrancy` | PASS | PASS | 0.032 | `exploit_blocked` |
| `TokenSale.sol` | `integer_overflow` | PASS | PASS | 0.105 | `exploit_blocked` |
| `UnsafeWallet.sol` | `access_control` | PASS | PASS | 0.024 | `exploit_blocked` |
| `VulnerableBank.sol` | `reentrancy` | PASS | PASS | 0.027 | `exploit_blocked` |
| `WeakRandom.sol` | `front_running` | PASS | PASS | 0.048 | `exploit_blocked` |