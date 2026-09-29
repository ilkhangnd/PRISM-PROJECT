# PRISM End-to-End Pipeline Coverage Across 57 Benchmark Contracts

## 1. Executive Summary & Verification Boundaries
- Total Benchmark Contracts: 57
- Safe Contracts (27/57):
  - Cleared by Stage-1 static filtering: 21/27
  - Composite Safe Specificity: 27/27 (21/27 cleared statically at Stage 1 + 6/6 remaining safe reentrancy alarms refuted via Stage-3 Foundry safe replay; dynamic execution strictly limited to the 6 mutex-guarded contracts, not benchmark-wide)
- Vulnerable Contracts (30/57):
  - Retained by Stage-2 static filtering: 18/30
  - Missed by Slither taxonomy mapping: 12/30
  - Execution-confirmed via reference harnesses (RQ2/RQ5): 5 canonical contracts
  - Automated 57-contract harness generation: open (not measured)

## 2. Per-Contract Coverage Table
| Contract Name | Ground Truth | Category | Stage 0 (Slither) | Stage 1 (Taxonomy) | Stage 2 (Impact) | Stage 3 (Foundry Replay) | Pipeline Coverage Status |
|---|:---:|:---:|:---:|:---:|:---:|:---:|---|
| `SafeAccessControl_0.sol` | Safe | -- | flagged | cleared | cleared | cleared | `safe_cleared_by_static_filter` |
| `SafeAccessControl_1.sol` | Safe | -- | flagged | cleared | cleared | cleared | `safe_cleared_by_static_filter` |
| `SafeAccessControl_2.sol` | Safe | -- | flagged | cleared | cleared | cleared | `safe_cleared_by_static_filter` |
| `SafeAccessControl_3.sol` | Safe | -- | flagged | cleared | cleared | cleared | `safe_cleared_by_static_filter` |
| `SafeAccessControl_4.sol` | Safe | -- | flagged | cleared | cleared | cleared | `safe_cleared_by_static_filter` |
| `SafeOverflow_0.sol` | Safe | -- | flagged | cleared | cleared | cleared | `safe_cleared_by_static_filter` |
| `SafeOverflow_1.sol` | Safe | -- | flagged | cleared | cleared | cleared | `safe_cleared_by_static_filter` |
| `SafeOverflow_2.sol` | Safe | -- | flagged | cleared | cleared | cleared | `safe_cleared_by_static_filter` |
| `SafeOverflow_3.sol` | Safe | -- | flagged | cleared | cleared | cleared | `safe_cleared_by_static_filter` |
| `SafeOverflow_4.sol` | Safe | -- | flagged | cleared | cleared | cleared | `safe_cleared_by_static_filter` |
| `SafeReentrancy_0.sol` | Safe | -- | flagged | flagged_reentrancy | retained_high_impact | refuted_via_foundry_safe_replay | `safe_alarm_refuted_by_execution` |
| `SafeReentrancy_1.sol` | Safe | -- | flagged | flagged_reentrancy | retained_high_impact | refuted_via_foundry_safe_replay | `safe_alarm_refuted_by_execution` |
| `SafeReentrancy_2.sol` | Safe | -- | flagged | flagged_reentrancy | retained_high_impact | refuted_via_foundry_safe_replay | `safe_alarm_refuted_by_execution` |
| `SafeReentrancy_3.sol` | Safe | -- | flagged | flagged_reentrancy | retained_high_impact | refuted_via_foundry_safe_replay | `safe_alarm_refuted_by_execution` |
| `SafeReentrancy_4.sol` | Safe | -- | flagged | flagged_reentrancy | retained_high_impact | refuted_via_foundry_safe_replay | `safe_alarm_refuted_by_execution` |
| `SafeTimestamp_0.sol` | Safe | -- | flagged | cleared | cleared | cleared | `safe_cleared_by_static_filter` |
| `SafeTimestamp_1.sol` | Safe | -- | flagged | cleared | cleared | cleared | `safe_cleared_by_static_filter` |
| `SafeTimestamp_2.sol` | Safe | -- | flagged | cleared | cleared | cleared | `safe_cleared_by_static_filter` |
| `SafeTimestamp_3.sol` | Safe | -- | flagged | cleared | cleared | cleared | `safe_cleared_by_static_filter` |
| `SafeTimestamp_4.sol` | Safe | -- | flagged | cleared | cleared | cleared | `safe_cleared_by_static_filter` |
| `SafeUncheckedReturn_0.sol` | Safe | -- | flagged | cleared | cleared | cleared | `safe_cleared_by_static_filter` |
| `SafeUncheckedReturn_1.sol` | Safe | -- | flagged | cleared | cleared | cleared | `safe_cleared_by_static_filter` |
| `SafeUncheckedReturn_2.sol` | Safe | -- | flagged | cleared | cleared | cleared | `safe_cleared_by_static_filter` |
| `SafeUncheckedReturn_3.sol` | Safe | -- | flagged | cleared | cleared | cleared | `safe_cleared_by_static_filter` |
| `SafeUncheckedReturn_4.sol` | Safe | -- | flagged | cleared | cleared | cleared | `safe_cleared_by_static_filter` |
| `VulnAccessControl_0.sol` | Vulnerable | SWC-105 | flagged | flagged_in_taxonomy | retained_high_confidence | statically_retained | `statically_flagged_harness_open` |
| `VulnAccessControl_1.sol` | Vulnerable | SWC-105 | flagged | flagged_in_taxonomy | retained_high_confidence | statically_retained | `statically_flagged_harness_open` |
| `VulnAccessControl_2.sol` | Vulnerable | SWC-105 | flagged | flagged_in_taxonomy | retained_high_confidence | statically_retained | `statically_flagged_harness_open` |
| `VulnAccessControl_3.sol` | Vulnerable | SWC-105 | flagged | flagged_in_taxonomy | retained_high_confidence | statically_retained | `statically_flagged_harness_open` |
| `VulnAccessControl_4.sol` | Vulnerable | SWC-105 | flagged | flagged_in_taxonomy | retained_high_confidence | statically_retained | `statically_flagged_harness_open` |
| `VulnOverflow_0.sol` | Vulnerable | SWC-101 | flagged | flagged_in_taxonomy | retained_high_confidence | statically_retained | `statically_flagged_harness_open` |
| `VulnOverflow_1.sol` | Vulnerable | SWC-101 | flagged | missed_no_detector | missed | missed | `vulnerability_missed_by_slither` |
| `VulnOverflow_2.sol` | Vulnerable | SWC-101 | flagged | flagged_in_taxonomy | retained_high_confidence | statically_retained | `statically_flagged_harness_open` |
| `VulnOverflow_3.sol` | Vulnerable | SWC-101 | flagged | missed_no_detector | missed | missed | `vulnerability_missed_by_slither` |
| `VulnOverflow_4.sol` | Vulnerable | SWC-101 | flagged | flagged_in_taxonomy | retained_high_confidence | statically_retained | `statically_flagged_harness_open` |
| `VulnReentrancy_0.sol` | Vulnerable | SWC-107 | flagged | flagged_in_taxonomy | retained_high_confidence | statically_retained | `statically_flagged_harness_open` |
| `VulnReentrancy_1.sol` | Vulnerable | SWC-107 | flagged | flagged_in_taxonomy | retained_high_confidence | statically_retained | `statically_flagged_harness_open` |
| `VulnReentrancy_2.sol` | Vulnerable | SWC-107 | flagged | flagged_in_taxonomy | retained_high_confidence | statically_retained | `statically_flagged_harness_open` |
| `VulnReentrancy_3.sol` | Vulnerable | SWC-107 | flagged | flagged_in_taxonomy | retained_high_confidence | statically_retained | `statically_flagged_harness_open` |
| `VulnReentrancy_4.sol` | Vulnerable | SWC-107 | flagged | flagged_in_taxonomy | retained_high_confidence | statically_retained | `statically_flagged_harness_open` |
| `VulnTimestamp_0.sol` | Vulnerable | SWC-114 | flagged | flagged_in_taxonomy | retained_high_confidence | statically_retained | `statically_flagged_harness_open` |
| `VulnTimestamp_1.sol` | Vulnerable | SWC-114 | flagged | flagged_in_taxonomy | retained_high_confidence | statically_retained | `statically_flagged_harness_open` |
| `VulnTimestamp_2.sol` | Vulnerable | SWC-114 | flagged | flagged_in_taxonomy | retained_high_confidence | statically_retained | `statically_flagged_harness_open` |
| `VulnTimestamp_3.sol` | Vulnerable | SWC-114 | flagged | flagged_in_taxonomy | retained_high_confidence | statically_retained | `statically_flagged_harness_open` |
| `VulnTimestamp_4.sol` | Vulnerable | SWC-114 | flagged | flagged_in_taxonomy | retained_high_confidence | statically_retained | `statically_flagged_harness_open` |
| `VulnUncheckedReturn_0.sol` | Vulnerable | SWC-104 | flagged | missed_no_detector | missed | missed | `vulnerability_missed_by_slither` |
| `VulnUncheckedReturn_1.sol` | Vulnerable | SWC-104 | flagged | missed_no_detector | missed | missed | `vulnerability_missed_by_slither` |
| `VulnUncheckedReturn_2.sol` | Vulnerable | SWC-104 | flagged | missed_no_detector | missed | missed | `vulnerability_missed_by_slither` |
| `VulnUncheckedReturn_3.sol` | Vulnerable | SWC-104 | flagged | missed_no_detector | missed | missed | `vulnerability_missed_by_slither` |
| `VulnUncheckedReturn_4.sol` | Vulnerable | SWC-104 | flagged | missed_no_detector | missed | missed | `vulnerability_missed_by_slither` |
| `SafeBank.sol` | Safe | -- | flagged | flagged_reentrancy | retained_high_impact | refuted_via_foundry_safe_replay | `safe_alarm_refuted_by_execution` |
| `SafeMathContract.sol` | Safe | -- | flagged | cleared | cleared | cleared | `safe_cleared_by_static_filter` |
| `SimpleDAO.sol` | Vulnerable | SWC-107 | flagged | flagged_in_taxonomy | retained_high_confidence | confirmed_via_reference_harness | `execution_confirmed_reference_harness` |
| `TokenSale.sol` | Vulnerable | SWC-101 | flagged | flagged_in_taxonomy | retained_high_confidence | confirmed_via_reference_harness | `execution_confirmed_reference_harness` |
| `UnsafeWallet.sol` | Vulnerable | SWC-105 | flagged | flagged_in_taxonomy | retained_high_confidence | confirmed_via_reference_harness | `execution_confirmed_reference_harness` |
| `VulnerableBank.sol` | Vulnerable | SWC-107 | flagged | flagged_in_taxonomy | retained_high_confidence | confirmed_via_reference_harness | `execution_confirmed_reference_harness` |
| `WeakRandom.sol` | Vulnerable | SWC-114 | flagged | flagged_in_taxonomy | retained_high_confidence | confirmed_via_reference_harness | `execution_confirmed_reference_harness` |
