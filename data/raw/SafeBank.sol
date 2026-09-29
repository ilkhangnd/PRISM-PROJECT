// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SafeBank {
    mapping(address => uint256) public balances;
    bool internal locked;

    modifier noReentrant() {
        require(!locked, "No re-entrancy");
        locked = true;
        _;
        locked = false;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 _amount) public noReentrant {
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Transfer failed");

        // State update AFTER external call (violates CEI but protected by modifier)
        balances[msg.sender] -= _amount;
    }
}
