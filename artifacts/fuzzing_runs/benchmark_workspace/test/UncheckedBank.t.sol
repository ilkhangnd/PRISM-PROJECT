// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/UncheckedBank.sol";

interface Vm {
    function deal(address who, uint256 newBalance) external;
    function prank(address who) external;
}

contract UncheckedBankTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    UncheckedBank bank;
    RejectEther rejecter;

    function setUp() public {
        bank = new UncheckedBank();
        rejecter = new RejectEther();
        vm.deal(address(this), 5 ether);
        bank.deposit{value: 2 ether}();
    }

    // [Mode B: PRISM Guided Exploit Generator]
    // Deploys rejecting recipient to trigger silent failure of .send()
    function testGuidedExploit() public {
        uint256 balBefore = bank.balances(address(this));
        bank.transferViaSend(payable(address(rejecter)), 1 ether);
        uint256 balAfter = bank.balances(address(this));
        // Accounting Invariant Violation: Balance deducted despite transfer failure
        require(balAfter == balBefore - 1 ether, "Balance deducted illegally");
        require(address(rejecter).balance == 0, "Ether never reached recipient (unchecked return bug)");
    }

    // [Mode A: Baseline Unconstrained Random Fuzzing]
    // Unconstrained standard EOA transfers
    function testRandomFuzz(uint256 rawAmount) public {
        uint256 amount = (rawAmount % 1 ether) + 1;
        address eoaUser = address(0xCAFE);
        uint256 balBefore = bank.balances(address(this));
        if (balBefore >= amount) {
            bank.transferViaSend(payable(eoaUser), amount);
            // Invariant: Balance correctly reflects successful transfer
            require(bank.balances(address(this)) == balBefore - amount, "Accounting invariant holds");
        }
    }

    receive() external payable {}
}
