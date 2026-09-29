// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TokenSale
 * @notice Contains integer overflow vulnerability pattern.
 */
contract prism_Type_0002 {
    mapping(address => uint256) public prism_v_0004;
    uint256 public constant prism_Type_0000 = 1 ether;

    function prism_v_0009(uint256 prism_v_0003) public payable {
        // Vulnerability: Integer overflow in multiplication (SWC-101)
        // In Solidity <0.8.0 this would overflow silently
        // In 0.8.x+ it reverts, but unchecked blocks can reintroduce it
        uint256 prism_v_0007;
        unchecked {
            // BUG: Can overflow in unchecked block
            prism_v_0007 = prism_v_0003 * prism_Type_0000;
        }
        require(msg.value >= prism_v_0007, "Not enough ETH");
        prism_v_0004[msg.sender] += prism_v_0003;
    }

    function prism_v_0008(uint256 prism_v_0003) public {
        require(prism_v_0004[msg.sender] >= prism_v_0003, "Not enough tokens");
        prism_v_0004[msg.sender] -= prism_v_0003;
        uint256 prism_v_0005 = prism_v_0003 * prism_Type_0000;
        (bool prism_v_0006, ) = msg.sender.call{value: prism_v_0005}("");
        require(prism_v_0006, "Transfer failed");
    }

    function prism_v_0001() public view returns (uint256) {
        return prism_v_0004[msg.sender];
    }

    receive() external payable {}
}
