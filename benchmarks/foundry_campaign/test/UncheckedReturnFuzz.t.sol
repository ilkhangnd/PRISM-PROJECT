// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/UncheckedReturnVault.sol";

contract FailingERC20 {
    mapping(address => uint256) public balanceOf;

    function transfer(address, uint256) external pure returns (bool) {
        return false; // Silently fails by returning false without revert
    }

    function transferFrom(address, address, uint256) external pure returns (bool) {
        return false; // Silently fails by returning false
    }
}

contract UncheckedReturnFuzzTest {
    UncheckedReturnVault public vault;
    FailingERC20 public badToken;

    function setUp() public {
        vault = new UncheckedReturnVault();
        badToken = new FailingERC20();
    }

    // Guided Fuzzing: Injects failing token and verifies balance consistency
    function testGuidedUncheckedReturn(uint256 depositAmt) public {
        depositAmt = bound(depositAmt, 1, 1000 ether);

        // User deposits failing token
        vault.deposit(address(badToken), depositAmt);

        // Invariant: Vault should not credit user balance if actual transfer failed
        require(vault.userBalances(address(this)) == 0, "INVARIANT_VIOLATION: Phantom balance credited on failed transfer");
    }

    // Random Fuzzing: General token address fuzzing with identical invariant oracle
    function testRandomUncheckedReturn(address token, uint256 amount) public {
        amount = bound(amount, 1, 1000 ether);
        if (token != address(badToken)) {
            try vault.deposit(token, amount) {} catch {}
        }

        // Identical Invariant: Vault should not credit user balance if actual transfer failed
        require(vault.userBalances(address(this)) == 0, "INVARIANT_VIOLATION: Phantom balance credited on failed transfer");
    }

    function bound(uint256 x, uint256 min, uint256 max) internal pure returns (uint256) {
        if (min >= max) return min;
        return min + (x % (max - min + 1));
    }
}
