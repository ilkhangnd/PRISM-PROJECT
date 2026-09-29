// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract VulnOverflow_4 {
    mapping(address => uint) balances;
    function transfer(address to, uint amount) public {
        unchecked {
            balances[msg.sender] -= amount;
            balances[to] += amount;
        }
    }
}
