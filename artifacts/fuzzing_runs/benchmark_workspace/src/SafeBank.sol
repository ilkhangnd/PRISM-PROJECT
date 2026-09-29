// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

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

contract AttackSafeBank {
    SafeBank public target;
    uint256 public attackCount = 0;
    bool public attackSuccess = false;

    constructor(address _target) {
        target = SafeBank(payable(_target));
    }

    function attack() external payable {
        target.deposit{value: msg.value}();
        target.withdraw(msg.value);
    }

    receive() external payable {
        attackCount++;
        if (address(target).balance >= 1 ether && attackCount < 3) {
            try target.withdraw(1 ether) {
                attackSuccess = true;
            } catch {
                attackSuccess = false;
            }
        }
    }
}
