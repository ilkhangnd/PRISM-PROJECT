// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title WeakRandom
 * @notice Contains timestamp dependence vulnerability — predictable randomness.
 */
contract WeakRandom {
    uint256 public jackpot;
    address public lastWinner;

    constructor() payable {
        jackpot = msg.value;
    }

    function play() public payable {
        require(msg.value >= 0.1 ether, "Minimum bet is 0.1 ETH");
        jackpot += msg.value;

        // Vulnerability: Timestamp Dependence (SWC-116)
        // BUG: block.timestamp is manipulable by miners
        uint256 random = uint256(
            keccak256(abi.encodePacked(block.timestamp, msg.sender))
        );

        if (random % 10 == 0) {
            lastWinner = msg.sender;
            uint256 prize = jackpot;
            jackpot = 0;
            msg.sender.call{value: prize}(""); // MUTATED: return value ignored
        }
    }

    function getJackpot() public view returns (uint256) {
        return jackpot;
    }

    receive() external payable {
        jackpot += msg.value;
    }
}
