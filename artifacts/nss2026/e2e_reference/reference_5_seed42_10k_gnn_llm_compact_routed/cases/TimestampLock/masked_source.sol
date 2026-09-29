// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract prism_Type_0001 {
    address public prism_v_0004;
    uint256 public prism_v_0002;
    bool public prism_v_0003;

    constructor() payable {
        prism_v_0004 = msg.sender;
        prism_v_0002 = block.timestamp + 1 days;
    }

    // SWC-114: Vulnerability - state transition relies on block.timestamp comparison
    function prism_v_0000() public {
        require(!prism_v_0003, "Already unlocked");
        require(block.timestamp >= prism_v_0002, "Lock period active");
        prism_v_0003 = true;
        payable(msg.sender).transfer(address(this).balance);
    }

    receive() external payable {}
}
