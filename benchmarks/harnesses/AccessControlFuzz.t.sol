// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/AccessControlWallet.sol";

contract AccessControlFuzzTest {
    AccessControlWallet public wallet;

    function setUp() public {
        wallet = new AccessControlWallet();
        payable(address(wallet)).transfer(5 ether);
    }

    // Guided Fuzzing: Attacker hijacks owner and drains funds
    function testGuidedAccessControl(address newOwner) public {
        if (newOwner == address(0) || newOwner == address(this)) newOwner = address(0xdead);

        // Attacker invokes unshielded initWallet
        wallet.initWallet(newOwner);

        // Invariant: Owner should remain deployer
        require(wallet.owner() == address(this), "INVARIANT_VIOLATION: Ownership hijacked");
    }

    // Random Fuzzing: General exploration with identical invariant oracle
    function testRandomAccessControl(address randUser, uint8 action) public {
        if (randUser == address(0) || randUser == address(this)) randUser = address(0xbeef);

        if (action % 2 == 0) {
            try wallet.initWallet(randUser) {} catch {}
        } else {
            try wallet.withdrawAll(payable(randUser)) {} catch {}
        }

        // Identical Invariant: Owner should remain deployer
        require(wallet.owner() == address(this), "INVARIANT_VIOLATION: Ownership hijacked");
    }

    receive() external payable {}
}
