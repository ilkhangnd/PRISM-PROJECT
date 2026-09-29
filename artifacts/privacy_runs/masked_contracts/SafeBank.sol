// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract prism_Type_0002 {
    mapping(address => uint256) public prism_v_0001;
    bool internal prism_v_0007;

    modifier prism_v_0000() {
        require(!prism_v_0007, "No re-entrancy");
        prism_v_0007 = true;
        _;
        prism_v_0007 = false;
    }

    function prism_v_0004() public payable {
        prism_v_0001[msg.sender] += msg.value;
    }

    function prism_v_0003(uint256 prism_v_0005) public prism_v_0000 {
        require(prism_v_0001[msg.sender] >= prism_v_0005, "Insufficient balance");
        
        (bool prism_v_0006, ) = msg.sender.call{value: prism_v_0005}("");
        require(prism_v_0006, "Transfer failed");

        // State update AFTER external call (violates CEI but protected by modifier)
        prism_v_0001[msg.sender] -= prism_v_0005;
    }
}
