// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title AccessControlWallet
 * @notice Vulnerable privilege escalation via uninitialized/misprotected owner setter (SWC-105).
 */
contract AccessControlWallet {
    address public owner;
    bool public initialized;

    event OwnerSet(address indexed newOwner);
    event FundsWithdrawn(address indexed to, uint256 amount);

    constructor() {
        owner = msg.sender;
        initialized = true;
    }

    // Vulnerability: Missing onlyOwner or proper initialization guard
    function initWallet(address _owner) external {
        // Flawed guard: relies on user-controlled parameter or un-reverted flag
        if (!initialized || _owner != address(0)) {
            owner = _owner;
            emit OwnerSet(_owner);
        }
    }

    function withdrawAll(address payable recipient) external {
        require(msg.sender == owner, "Not owner");
        uint256 amount = address(this).balance;
        (bool ok, ) = recipient.call{value: amount}("");
        require(ok, "Transfer failed");
        emit FundsWithdrawn(recipient, amount);
    }

    receive() external payable {}
}
