// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title OverflowBank
 * @notice Arithmetic edge cases simulated in unchecked blocks (SWC-101).
 */
contract OverflowBank {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    function deposit(uint256 amount) external payable {
        require(msg.value == amount, "Value mismatch");
        balances[msg.sender] += amount;
        totalDeposits += amount;
    }

    function batchTransfer(address[] calldata recipients, uint256 value) external {
        uint256 count = recipients.length;
        require(count > 0, "No recipients");

        // Vulnerability: Unchecked multiplication overflow bypasses balance check
        uint256 totalNeeded;
        unchecked {
            totalNeeded = count * value;
        }

        require(balances[msg.sender] >= totalNeeded, "Insufficient balance");

        balances[msg.sender] -= totalNeeded;
        for (uint256 i = 0; i < count; i++) {
            balances[recipients[i]] += value;
        }
    }
}
