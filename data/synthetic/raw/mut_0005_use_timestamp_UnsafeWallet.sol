// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title UnsafeWallet
 * @notice Contains access control vulnerability — missing authorization checks.
 */
contract UnsafeWallet {
    address public owner;
    mapping(address => uint256) public deposits;

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        deposits[msg.sender] += msg.value;
    }

    // Vulnerability: Access Control (SWC-115)
    // BUG: Anyone can change the owner
    function changeOwner(address newOwner) public {
        // Missing: require(msg.sender == owner)
        owner = newOwner;
    }

    // Vulnerability: Access Control (SWC-115)
    // BUG: Anyone can withdraw all funds
    function withdrawAll() public {
        // Missing: require(msg.sender == owner)
        uint256 balance = address(this).balance;
        (bool success, ) = payable(msg.sender).call{value: balance}("");
        require(success, "Transfer failed");
    }

    function getUserDeposit(address user) public view returns (uint256) {
        return deposits[user];
    }

    receive() external payable {}

    // MUTATED: Timestamp-dependent logic injected
    function isLucky_mut() public view returns (bool) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 2 == 0;
    }
}
