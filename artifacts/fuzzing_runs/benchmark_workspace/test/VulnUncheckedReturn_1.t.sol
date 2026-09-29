// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/VulnUncheckedReturn_1.sol";

interface Vm {
    function deal(address who, uint256 newBalance) external;
}

contract RejectingReceiver_VulnUncheckedReturn_1 {
    receive() external payable {
        revert("Reject ether");
    }
}

contract VulnUncheckedReturn_1Test {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    VulnUncheckedReturn_1 target;
    RejectingReceiver_VulnUncheckedReturn_1 receiver;

    function setUp() public {
        target = new VulnUncheckedReturn_1();
        receiver = new RejectingReceiver_VulnUncheckedReturn_1();
        vm.deal(address(target), 5 ether);
    }

    function testUncheckedReturnExploit() public {
        // sendEther fails silently without reverting
        (bool success, ) = address(target).call(abi.encodeWithSignature("sendEther(address,uint256)", payable(address(receiver)), 1 ether));
        require(success, "Unchecked return exploit confirmed: silent send failure was not detected");
    }
}
