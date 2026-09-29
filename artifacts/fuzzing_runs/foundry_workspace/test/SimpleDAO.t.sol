// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/SimpleDAO.sol";

interface Vm {
    function deal(address who, uint256 newBalance) external;
}

contract SimpleDAOTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    SimpleDAO dao;
    AttackDAO attacker;

    function setUp() public {
        dao = new SimpleDAO();
        attacker = new AttackDAO(address(dao));
        vm.deal(address(dao), 10 ether);
        vm.deal(address(attacker), 2 ether);
    }

    function testReentrancyExploitTriggers() public {
        uint256 daoBalBefore = address(dao).balance;
        require(daoBalBefore == 10 ether, "Setup failed");

        attacker.attack{value: 1 ether}();

        uint256 daoBalAfter = address(dao).balance;
        // Exploit drained more than 1 ether deposited
        require(daoBalAfter < 9 ether, "Reentrancy exploit verified");
    }

    function testFuzzDepositWithdraw(uint96 amount) public {
        if (amount == 0 || amount > 100 ether) return;
        vm.deal(address(this), amount);
        dao.deposit{value: amount}();
        require(dao.balances(address(this)) == amount, "Balance mismatch");
        dao.withdraw();
        require(dao.balances(address(this)) == 0, "Withdrawal failed");
    }

    receive() external payable {}
}
