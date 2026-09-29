// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract WeakLottery {
    address public winner;
    uint256 public prizePool;

    function guess(uint256 secret) public payable {
        require(msg.value == 0.1 ether, "Entry fee 0.1 ETH");
        prizePool += msg.value;
        uint256 luckyNumber = uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao))) % 100;
        if (secret == luckyNumber) {
            winner = msg.sender;
            payable(msg.sender).transfer(address(this).balance);
            prizePool = 0;
        }
    }

    receive() external payable {}
}
