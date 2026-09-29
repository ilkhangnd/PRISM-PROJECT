# P0-E: Benchmark-Wide End-to-End Execution Campaign (57 Contracts)

## 1. Executive Summary
- **Total Benchmark Contracts**: **57**
- **Compilation Success Rate (solc 0.8.30)**: **57/57 (100.0%)**
- **Dynamic Assertion-Bearing Execution Rate**: **57/57 (100.0%)**
- **Vulnerability Confirmation (Exploit Traced & Asserted)**: **30/30 (100.0%)**
- **Safety Invariant Enforcement (Refuted/Reverted)**: **27/27 (100.0%)**
- **Total Execution Campaign Time**: **20.90 seconds**

## 2. Per-Contract Execution Table
| Contract | Ground Truth | Category | Harness Origin | Solc Compilation | Forge Execution | Dynamic Verification Status | Latency |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `SafeAccessControl_0.sol` | Safe | `safe` | `synthesized_assertion_bearing_harness` | PASS | PASS | `safety_confirmed_by_invariant` | 341.9ms |
| `SafeAccessControl_1.sol` | Safe | `safe` | `synthesized_assertion_bearing_harness` | PASS | PASS | `safety_confirmed_by_invariant` | 417.59ms |
| `SafeAccessControl_2.sol` | Safe | `safe` | `synthesized_assertion_bearing_harness` | PASS | PASS | `safety_confirmed_by_invariant` | 382.93ms |
| `SafeAccessControl_3.sol` | Safe | `safe` | `synthesized_assertion_bearing_harness` | PASS | PASS | `safety_confirmed_by_invariant` | 364.21ms |
| `SafeAccessControl_4.sol` | Safe | `safe` | `synthesized_assertion_bearing_harness` | PASS | PASS | `safety_confirmed_by_invariant` | 442.78ms |
| `SafeOverflow_0.sol` | Safe | `safe` | `synthesized_assertion_bearing_harness` | PASS | PASS | `safety_confirmed_by_invariant` | 385.85ms |
| `SafeOverflow_1.sol` | Safe | `safe` | `synthesized_assertion_bearing_harness` | PASS | PASS | `safety_confirmed_by_invariant` | 357.58ms |
| `SafeOverflow_2.sol` | Safe | `safe` | `synthesized_assertion_bearing_harness` | PASS | PASS | `safety_confirmed_by_invariant` | 357.0ms |
| `SafeOverflow_3.sol` | Safe | `safe` | `synthesized_assertion_bearing_harness` | PASS | PASS | `safety_confirmed_by_invariant` | 380.7ms |
| `SafeOverflow_4.sol` | Safe | `safe` | `synthesized_assertion_bearing_harness` | PASS | PASS | `safety_confirmed_by_invariant` | 347.15ms |
| `SafeReentrancy_0.sol` | Safe | `safe` | `canonical_reference_harness` | PASS | PASS | `safety_confirmed_by_invariant` | 366.91ms |
| `SafeReentrancy_1.sol` | Safe | `safe` | `canonical_reference_harness` | PASS | PASS | `safety_confirmed_by_invariant` | 350.49ms |
| `SafeReentrancy_2.sol` | Safe | `safe` | `canonical_reference_harness` | PASS | PASS | `safety_confirmed_by_invariant` | 365.83ms |
| `SafeReentrancy_3.sol` | Safe | `safe` | `canonical_reference_harness` | PASS | PASS | `safety_confirmed_by_invariant` | 391.33ms |
| `SafeReentrancy_4.sol` | Safe | `safe` | `canonical_reference_harness` | PASS | PASS | `safety_confirmed_by_invariant` | 384.62ms |
| `SafeTimestamp_0.sol` | Safe | `safe` | `synthesized_assertion_bearing_harness` | PASS | PASS | `safety_confirmed_by_invariant` | 388.91ms |
| `SafeTimestamp_1.sol` | Safe | `safe` | `synthesized_assertion_bearing_harness` | PASS | PASS | `safety_confirmed_by_invariant` | 370.71ms |
| `SafeTimestamp_2.sol` | Safe | `safe` | `synthesized_assertion_bearing_harness` | PASS | PASS | `safety_confirmed_by_invariant` | 373.16ms |
| `SafeTimestamp_3.sol` | Safe | `safe` | `synthesized_assertion_bearing_harness` | PASS | PASS | `safety_confirmed_by_invariant` | 353.81ms |
| `SafeTimestamp_4.sol` | Safe | `safe` | `synthesized_assertion_bearing_harness` | PASS | PASS | `safety_confirmed_by_invariant` | 353.09ms |
| `SafeUncheckedReturn_0.sol` | Safe | `safe` | `synthesized_assertion_bearing_harness` | PASS | PASS | `safety_confirmed_by_invariant` | 366.95ms |
| `SafeUncheckedReturn_1.sol` | Safe | `safe` | `synthesized_assertion_bearing_harness` | PASS | PASS | `safety_confirmed_by_invariant` | 399.84ms |
| `SafeUncheckedReturn_2.sol` | Safe | `safe` | `synthesized_assertion_bearing_harness` | PASS | PASS | `safety_confirmed_by_invariant` | 358.43ms |
| `SafeUncheckedReturn_3.sol` | Safe | `safe` | `synthesized_assertion_bearing_harness` | PASS | PASS | `safety_confirmed_by_invariant` | 446.4ms |
| `SafeUncheckedReturn_4.sol` | Safe | `safe` | `synthesized_assertion_bearing_harness` | PASS | PASS | `safety_confirmed_by_invariant` | 365.49ms |
| `VulnAccessControl_0.sol` | Vulnerable | `access_control` | `synthesized_assertion_bearing_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 346.2ms |
| `VulnAccessControl_1.sol` | Vulnerable | `access_control` | `synthesized_assertion_bearing_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 354.55ms |
| `VulnAccessControl_2.sol` | Vulnerable | `access_control` | `synthesized_assertion_bearing_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 337.69ms |
| `VulnAccessControl_3.sol` | Vulnerable | `access_control` | `synthesized_assertion_bearing_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 389.24ms |
| `VulnAccessControl_4.sol` | Vulnerable | `access_control` | `synthesized_assertion_bearing_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 357.88ms |
| `VulnOverflow_0.sol` | Vulnerable | `integer_overflow` | `synthesized_assertion_bearing_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 341.0ms |
| `VulnOverflow_1.sol` | Vulnerable | `integer_overflow` | `synthesized_assertion_bearing_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 373.22ms |
| `VulnOverflow_2.sol` | Vulnerable | `integer_overflow` | `synthesized_assertion_bearing_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 441.17ms |
| `VulnOverflow_3.sol` | Vulnerable | `integer_overflow` | `synthesized_assertion_bearing_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 404.23ms |
| `VulnOverflow_4.sol` | Vulnerable | `integer_overflow` | `synthesized_assertion_bearing_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 378.54ms |
| `VulnReentrancy_0.sol` | Vulnerable | `reentrancy` | `synthesized_assertion_bearing_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 405.15ms |
| `VulnReentrancy_1.sol` | Vulnerable | `reentrancy` | `synthesized_assertion_bearing_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 345.41ms |
| `VulnReentrancy_2.sol` | Vulnerable | `reentrancy` | `synthesized_assertion_bearing_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 343.49ms |
| `VulnReentrancy_3.sol` | Vulnerable | `reentrancy` | `synthesized_assertion_bearing_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 344.79ms |
| `VulnReentrancy_4.sol` | Vulnerable | `reentrancy` | `synthesized_assertion_bearing_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 359.7ms |
| `VulnTimestamp_0.sol` | Vulnerable | `front_running` | `synthesized_assertion_bearing_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 343.09ms |
| `VulnTimestamp_1.sol` | Vulnerable | `front_running` | `synthesized_assertion_bearing_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 342.5ms |
| `VulnTimestamp_2.sol` | Vulnerable | `front_running` | `synthesized_assertion_bearing_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 345.73ms |
| `VulnTimestamp_3.sol` | Vulnerable | `front_running` | `synthesized_assertion_bearing_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 346.12ms |
| `VulnTimestamp_4.sol` | Vulnerable | `front_running` | `synthesized_assertion_bearing_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 343.52ms |
| `VulnUncheckedReturn_0.sol` | Vulnerable | `unchecked_return` | `synthesized_assertion_bearing_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 361.85ms |
| `VulnUncheckedReturn_1.sol` | Vulnerable | `unchecked_return` | `synthesized_assertion_bearing_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 346.05ms |
| `VulnUncheckedReturn_2.sol` | Vulnerable | `unchecked_return` | `synthesized_assertion_bearing_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 352.07ms |
| `VulnUncheckedReturn_3.sol` | Vulnerable | `unchecked_return` | `synthesized_assertion_bearing_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 379.16ms |
| `VulnUncheckedReturn_4.sol` | Vulnerable | `unchecked_return` | `synthesized_assertion_bearing_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 343.48ms |
| `SafeBank.sol` | Safe | `safe` | `canonical_reference_harness` | PASS | PASS | `safety_confirmed_by_invariant` | 346.73ms |
| `SafeMathContract.sol` | Safe | `safe` | `synthesized_assertion_bearing_harness` | PASS | PASS | `safety_confirmed_by_invariant` | 346.27ms |
| `SimpleDAO.sol` | Vulnerable | `reentrancy` | `canonical_reference_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 345.43ms |
| `TokenSale.sol` | Vulnerable | `integer_overflow` | `canonical_reference_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 366.54ms |
| `UnsafeWallet.sol` | Vulnerable | `access_control` | `canonical_reference_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 335.44ms |
| `VulnerableBank.sol` | Vulnerable | `reentrancy` | `canonical_reference_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 345.02ms |
| `WeakRandom.sol` | Vulnerable | `front_running` | `canonical_reference_harness` | PASS | PASS | `exploit_confirmed_by_assertion` | 351.05ms |