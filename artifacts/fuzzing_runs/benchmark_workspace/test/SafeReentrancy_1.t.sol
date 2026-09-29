// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/SafeReentrancy_1.sol";

interface Vm {
    function deal(address who, uint256 newBalance) external;
}

contract SafeReentrancy_1Test {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    SafeReentrancy_1 target;

    function setUp() public {
        target = new SafeReentrancy_1();
        vm.deal(address(target), 5 ether);
    }

    function testReentrancyRefuted() public {
        (bool success, ) = address(target).call(abi.encodeWithSignature("withdraw()"));
        require(!success, "Unauthorized withdraw without balance must revert");
        require(address(target).balance == 5 ether, "Target balance preserved");
    }

    receive() external payable {}
}
