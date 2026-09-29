// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract VulnUncheckedReturn_1 {
    function sendEther(address payable to, uint amount) public {
        to.send(amount); // Unchecked
    }
}
