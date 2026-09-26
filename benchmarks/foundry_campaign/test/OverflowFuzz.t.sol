// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/OverflowBank.sol";

contract OverflowFuzzTest {
    OverflowBank public bank;

    function setUp() public {
        bank = new OverflowBank();
    }

    // Guided Fuzzing: Focused on boundary multiplication values
    function testGuidedOverflow(uint256 value, uint8 recipientCount) public {
        recipientCount = uint8(bound(uint256(recipientCount), 2, 20));
        // Boundary value: (type(uint256).max / recipientCount) + 1 wraps to (recipientCount - 1 - rem) <= 20 wei
        value = (type(uint256).max / recipientCount) + 1;

        address[] memory recipients = new address[](recipientCount);
        for (uint256 i = 0; i < recipientCount; i++) {
            recipients[i] = address(uint160(i + 100));
        }

        // Deposit small amount
        bank.deposit{value: 1 ether}(1 ether);

        // Attempt exploit: totalNeeded overflows to near 0, bypassing balance check
        bank.batchTransfer(recipients, value);

        // Invariant: Recipient must never receive more tokens than total backed deposit (1 ether)
        require(bank.balances(recipients[0]) <= 1 ether, "INVARIANT_VIOLATION: Unbacked tokens minted via overflow");
    }

    // Random Fuzzing: Uniform search space across full 2^256 range with identical invariant oracle
    function testRandomOverflow(uint256 randomVal, uint8 count) public {
        count = uint8(bound(uint256(count), 1, 20));
        address[] memory recipients = new address[](count);
        for (uint256 i = 0; i < count; i++) {
            recipients[i] = address(uint160(i + 1));
        }
        try bank.deposit{value: 1 ether}(1 ether) {} catch {}
        try bank.batchTransfer(recipients, randomVal) {} catch {}

        // Identical Invariant: Recipient must never receive more tokens than total backed deposit (1 ether)
        require(bank.balances(recipients[0]) <= 1 ether, "INVARIANT_VIOLATION: Unbacked tokens minted via overflow");
    }

    function bound(uint256 x, uint256 min, uint256 max) internal pure returns (uint256) {
        if (min >= max) return min;
        return min + (x % (max - min + 1));
    }

    receive() external payable {}
}
