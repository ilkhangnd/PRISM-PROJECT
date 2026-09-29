// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract SafeAccessControl_2 {
    address public owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function setOwner(address newOwner) public onlyOwner {
        owner = newOwner;
    }
}
