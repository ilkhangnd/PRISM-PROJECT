// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract VulnAccessControl_2 {
    address public owner;
    function setOwner(address newOwner) public {
        // No checks
        owner = newOwner;
    }
}
