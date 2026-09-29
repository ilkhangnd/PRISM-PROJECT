// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TimestampLock {
    address public owner;
    uint256 public unlockTime;
    bool public unlocked;

    constructor() payable {
        owner = msg.sender;
        unlockTime = block.timestamp + 1 days;
    }

    // SWC-114: Vulnerability - state transition relies on block.timestamp comparison
    function claimEarlyReward() public {
        require(!unlocked, "Already unlocked");
        require(block.timestamp >= unlockTime, "Lock period active");
        unlocked = true;
        payable(msg.sender).transfer(address(this).balance);
    }

    receive() external payable {}
}
