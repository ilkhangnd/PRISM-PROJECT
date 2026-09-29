// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract prism_Type_0000 {
    mapping(address => uint256) public prism_v_0001;

    function prism_v_0002() public payable {
        prism_v_0001[msg.sender] += msg.value;
    }

    function transfer(address prism_v_0004, uint256 prism_v_0003) public {
        // Safe from underflow because solidity 0.8.x has built-in overflow/underflow checks
        prism_v_0001[msg.sender] -= prism_v_0003;
        prism_v_0001[prism_v_0004] += prism_v_0003;
    }
}
