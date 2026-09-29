// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract SafeUncheckedReturn_0 {
    function sendEther(address payable to, uint amount) public {
        bool success = to.send(amount);
        require(success, "Failed");
    }
}
