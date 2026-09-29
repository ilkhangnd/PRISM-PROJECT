// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SimpleDAO
 * @notice Classic reentrancy vulnerability pattern — the DAO hack recreation.
 */
contract prism_Type_0001 {
    mapping(address => uint256) public prism_v_0004;

    function prism_v_0006(address prism_v_0007) public payable {
        prism_v_0004[prism_v_0007] += msg.value;
    }

    // Vulnerability: Reentrancy (SWC-107)
    // Same pattern as the 2016 DAO hack
    function prism_v_0002(uint256 prism_v_0005) public {
        if (prism_v_0004[msg.sender] >= prism_v_0005) {
            // BUG: External call before state update
            (bool prism_v_0003, ) = msg.sender.call{value: prism_v_0005}("");
            require(prism_v_0003);
            prism_v_0004[msg.sender] -= prism_v_0005;
        }
    }

    function prism_v_0000(address prism_v_0007) public view returns (uint256) {
        return prism_v_0004[prism_v_0007];
    }

    receive() external payable {}
}
