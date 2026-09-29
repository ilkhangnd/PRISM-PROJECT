// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract prism_Type_0002 {
    mapping(address => uint256) public balanceOf;
    uint256 constant prism_Type_0000 = 1 ether;

    function prism_v_0005(uint256 prism_v_0001) public payable {
        unchecked {
            uint256 prism_v_0003 = prism_v_0001 * prism_Type_0000;
            require(msg.value == prism_v_0003, "Incorrect value");
        }
        balanceOf[msg.sender] += prism_v_0001;
    }

    function prism_v_0004() public {
        payable(msg.sender).transfer(address(this).balance);
    }

    receive() external payable {}
}
