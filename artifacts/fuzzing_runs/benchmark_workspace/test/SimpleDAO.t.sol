// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/SimpleDAO.sol";

interface Vm {
    function deal(address who, uint256 newBalance) external;
    function prank(address who) external;
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

    // [Mode B: PRISM Guided Exploit Generator]
    // Synthesizes smart contract attacker with recursive fallback hook to break Solvency Invariant
    function testGuidedExploit() public {
        uint256 daoBalBefore = address(dao).balance;
        require(daoBalBefore == 10 ether, "Setup failed");
        attacker.attack{value: 1 ether}();
        uint256 daoBalAfter = address(dao).balance;
        // Solvency Invariant Violation: DAO balance drained illegally
        require(daoBalAfter < 9 ether, "Solvency invariant violated by guided exploit");
    }

    // [Mode A: Baseline Unconstrained Random Fuzzing]
    // Unconstrained random EOA calls (deposit & withdraw) across state space
    function testRandomFuzz(uint256 rawAmount, uint8 action) public {
        uint256 amount = rawAmount % 2 ether;
        if (amount == 0) return;
        address randomUser = address(uint160(uint256(keccak256(abi.encodePacked(rawAmount, action)))));
        vm.deal(randomUser, amount);
        
        vm.prank(randomUser);
        dao.deposit{value: amount}();
        vm.prank(randomUser);
        dao.withdraw();
        
        // Invariant: Solvency preserved under unconstrained random EOA interactions
        require(address(dao).balance == 10 ether, "Solvency invariant holds under random EOA");
    }

    receive() external payable {}
}
