// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TokenSale {
    mapping(address => uint256) public balanceOf;
    uint256 constant PRICE_PER_TOKEN = 1 ether;

    function buy(uint256 numTokens) public payable {
        unchecked {
            uint256 totalCost = numTokens * PRICE_PER_TOKEN;
            require(msg.value == totalCost, "Incorrect value");
        }
        balanceOf[msg.sender] += numTokens;
    }

    function withdraw() public {
        payable(msg.sender).transfer(address(this).balance);
    }

    receive() external payable {}
}
