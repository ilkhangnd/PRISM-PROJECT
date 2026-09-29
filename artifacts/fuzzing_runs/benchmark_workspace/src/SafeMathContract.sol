// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SafeMathContract {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function transfer(address to, uint256 amount) public {
        // Safe from underflow because solidity 0.8.x has built-in overflow/underflow checks
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
