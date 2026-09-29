// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract VulnReentrancy_1 {
    mapping(address => uint) balances;
    function withdraw() public {
        uint amount = balances[msg.sender];
        require(amount > 0);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;
    }
}
