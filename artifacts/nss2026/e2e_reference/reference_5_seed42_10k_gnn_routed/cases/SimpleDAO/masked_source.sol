// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract prism_Type_0002 {
    mapping(address => uint256) public prism_v_0003;

    function prism_v_0006() public payable {
        prism_v_0003[msg.sender] += msg.value;
    }

    function prism_v_0004() public {
        uint256 prism_v_0010 = prism_v_0003[msg.sender];
        require(prism_v_0010 > 0, "No balance");
        (bool prism_v_0009, ) = msg.sender.call{value: prism_v_0010}("");
        require(prism_v_0009, "Failed to send Ether");
        prism_v_0003[msg.sender] = 0;
    }

    receive() external payable {}
}

contract prism_Type_0001 {
    prism_Type_0002 public prism_v_0008;
    uint256 public prism_v_0000 = 0;

    constructor(address prism_v_0005) {
        prism_v_0008 = prism_Type_0002(payable(prism_v_0005));
    }

    function prism_v_0007() external payable {
        require(msg.value >= 1 ether, "Need 1 ether");
        prism_v_0008.prism_v_0006{value: 1 ether}();
        prism_v_0008.prism_v_0004();
    }

    receive() external payable {
        prism_v_0000++;
        if (address(prism_v_0008).balance >= 1 ether && prism_v_0000 < 3) {
            prism_v_0008.prism_v_0004();
        }
    }
}
