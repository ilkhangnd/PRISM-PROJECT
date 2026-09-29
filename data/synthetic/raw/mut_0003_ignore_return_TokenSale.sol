// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TokenSale
 * @notice Contains integer overflow vulnerability pattern.
 */
contract TokenSale {
    mapping(address => uint256) public balances;
    uint256 public constant PRICE_PER_TOKEN = 1 ether;

    function buy(uint256 numTokens) public payable {
        // Vulnerability: Integer overflow in multiplication (SWC-101)
        // In Solidity <0.8.0 this would overflow silently
        // In 0.8.x+ it reverts, but unchecked blocks can reintroduce it
        uint256 cost;
        unchecked {
            // BUG: Can overflow in unchecked block
            cost = numTokens * PRICE_PER_TOKEN;
        }
        require(msg.value >= cost, "Not enough ETH");
        balances[msg.sender] += numTokens;
    }

    function sell(uint256 numTokens) public {
        require(balances[msg.sender] >= numTokens, "Not enough tokens");
        balances[msg.sender] -= numTokens;
        uint256 revenue = numTokens * PRICE_PER_TOKEN;
        msg.sender.call{value: revenue}(""); // MUTATED: return value ignored
    }

    function getBalance() public view returns (uint256) {
        return balances[msg.sender];
    }

    receive() external payable {}
}
