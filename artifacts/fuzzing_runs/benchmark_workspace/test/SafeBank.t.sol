// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/SafeBank.sol";

interface Vm {
    function deal(address who, uint256 newBalance) external;
}

contract SafeBankTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    SafeBank bank;
    AttackSafeBank attacker;

    function setUp() public {
        bank = new SafeBank();
        attacker = new AttackSafeBank(address(bank));
        vm.deal(address(bank), 10 ether);
        vm.deal(address(attacker), 1 ether);
    }

    function testReentrancyRefuted() public {
        uint256 bankBalBefore = address(bank).balance;
        attacker.attack{value: 1 ether}();
        require(address(bank).balance == 10 ether, "Bank solvency invariant preserved");
        require(!attacker.attackSuccess(), "Reentrancy exploit refuted by noReentrant mutex");
    }

    function testRandomFuzz(uint256 rawAmount) public {
        uint256 amount = (rawAmount % 2 ether) + 1;
        vm.deal(address(this), amount);
        bank.deposit{value: amount}();
        bank.withdraw(amount);
        require(address(bank).balance == 10 ether, "Solvency preserved under fuzzing");
    }

    receive() external payable {}
}
