// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract prism_Type_0000 {
    function prism_v_0001() public payable {
        require(msg.value == 1 ether);
        if (block.timestamp % 2 == 0) {
            payable(msg.sender).transfer(2 ether);
        }
    }
}
