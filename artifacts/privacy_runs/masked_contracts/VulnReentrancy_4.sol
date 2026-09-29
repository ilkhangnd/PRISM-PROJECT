// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract prism_Type_0000 {
    mapping(address => uint) prism_v_0001;
    function prism_v_0002() public {
        uint prism_v_0004 = prism_v_0001[msg.sender];
        require(prism_v_0004 > 0);
        (bool prism_v_0003, ) = msg.sender.call{value: prism_v_0004}("");
        require(prism_v_0003);
        prism_v_0001[msg.sender] = 0;
    }
}
