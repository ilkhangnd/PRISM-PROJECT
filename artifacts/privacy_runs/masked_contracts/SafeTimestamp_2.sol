// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract prism_Type_0000 {
    uint private prism_v_0003;
    function prism_v_0002(uint prism_v_0001) public payable {
        require(msg.value == 1 ether);
        prism_v_0003 += 1;
        if (uint(keccak256(abi.encodePacked(prism_v_0003, msg.sender))) % 2 == prism_v_0001) {
            payable(msg.sender).transfer(2 ether);
        }
    }
}
