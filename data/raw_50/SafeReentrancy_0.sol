// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract SafeReentrancy_0 {
    mapping(address => uint) balances;
    bool locked;
    modifier noReentrant() {
        require(!locked);
        locked = true;
        _;
        locked = false;
    }
    function withdraw() public noReentrant {
        uint amount = balances[msg.sender];
        require(amount > 0);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0; // State updated after, but locked
    }
}
