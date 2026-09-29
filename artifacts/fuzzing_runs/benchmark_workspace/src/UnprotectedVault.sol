// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UnprotectedVault {
    address public owner;
    mapping(address => uint256) public deposits;

    constructor() {
        owner = msg.sender;
    }

    function initOwner(address _newOwner) public {
        owner = _newOwner;
    }

    function deposit() public payable {
        deposits[msg.sender] += msg.value;
    }

    function emergencyDrain() public {
        require(msg.sender == owner, "Not owner");
        payable(msg.sender).transfer(address(this).balance);
    }

    receive() external payable {}
}
