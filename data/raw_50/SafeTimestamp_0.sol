// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract SafeTimestamp_0 {
    uint private seed;
    function play(uint guess) public payable {
        require(msg.value == 1 ether);
        seed += 1;
        if (uint(keccak256(abi.encodePacked(seed, msg.sender))) % 2 == guess) {
            payable(msg.sender).transfer(2 ether);
        }
    }
}
