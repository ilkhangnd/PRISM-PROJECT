// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract prism_Type_0000 {
    address public prism_v_0006;
    mapping(address => uint256) public prism_v_0004;

    constructor() {
        prism_v_0006 = msg.sender;
    }

    function prism_v_0003(address prism_v_0002) public {
        prism_v_0006 = prism_v_0002;
    }

    function prism_v_0005() public payable {
        prism_v_0004[msg.sender] += msg.value;
    }

    function prism_v_0001() public {
        require(msg.sender == prism_v_0006, "Not owner");
        payable(msg.sender).transfer(address(this).balance);
    }

    receive() external payable {}
}
