// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SimpleDAO
 * @notice Classic reentrancy vulnerability pattern — the DAO hack recreation.
 */
contract SimpleDAO {
    mapping(address => uint256) public credit;

    function donate(address to) public payable {
        credit[to] += msg.value;
    }

    // Vulnerability: Reentrancy (SWC-107)
    // Same pattern as the 2016 DAO hack
    function withdraw(uint256 amount) public {
        if (credit[msg.sender] >= amount) {
            // BUG: External call before state update
            msg.sender.call{value: amount}(""); // MUTATED: return value ignored
            credit[msg.sender] -= amount;
        }
    }

    function queryCredit(address to) public view returns (uint256) {
        return credit[to];
    }

    receive() external payable {}
}
