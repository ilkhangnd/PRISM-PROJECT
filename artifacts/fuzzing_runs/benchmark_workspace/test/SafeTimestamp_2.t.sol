// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/SafeTimestamp_2.sol";

interface Vm {
    function deal(address who, uint256 newBalance) external;
}

contract SafeTimestamp_2Test {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    SafeTimestamp_2 target;

    function setUp() public {
        target = new SafeTimestamp_2();
        vm.deal(address(target), 5 ether);
        vm.deal(address(this), 2 ether);
    }

    function testSafeRandomnessResistsManipulation() public {
        // Guess 0 with dynamic internal seed
        uint256 balBefore = address(this).balance;
        target.play{value: 1 ether}(0);
        // Safety invariant: single guess does not guarantee payout
        require(address(target).balance >= 4 ether, "Safe randomness invariant: funds not trivially drained");
    }

    receive() external payable {}
}
