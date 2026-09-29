// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract SafeOverflow_1 {
    mapping(address => uint) balances;
    function transfer(address to, uint amount) public {
        // Safe math natively in 0.8.0
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
