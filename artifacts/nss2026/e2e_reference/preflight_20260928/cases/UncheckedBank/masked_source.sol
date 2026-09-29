// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract prism_Type_0001 {
    mapping(address => uint256) public prism_v_0004;

    function prism_v_0005() public payable {
        prism_v_0004[msg.sender] += msg.value;
    }

    function prism_v_0000(address payable prism_v_0003, uint256 prism_v_0006) public {
        require(prism_v_0004[msg.sender] >= prism_v_0006, "Insufficient balance");
        prism_v_0004[msg.sender] -= prism_v_0006;
        prism_v_0003.send(prism_v_0006);
    }

    receive() external payable {}
}

contract prism_Type_0002 {
    receive() external payable {
        revert("Rejecting Ether");
    }
}
