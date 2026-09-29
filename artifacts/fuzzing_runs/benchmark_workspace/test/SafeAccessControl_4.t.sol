// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/SafeAccessControl_4.sol";

interface Vm {
    function prank(address who) external;
}

contract SafeAccessControl_4Test {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    SafeAccessControl_4 target;
    address attacker = address(0xBEEF);

    function setUp() public {
        target = new SafeAccessControl_4();
    }

    function testUnauthorizedAccessReverts() public {
        vm.prank(attacker);
        (bool success, ) = address(target).call(abi.encodeWithSignature("setOwner(address)", attacker));
        require(!success, "Access control enforced: unauthorized setOwner must revert");
        require(target.owner() != attacker, "Ownership preserved");
    }
}
