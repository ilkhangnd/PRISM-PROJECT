// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/VulnUncheckedReturn_4.sol";

interface Vm {
    function deal(address who, uint256 newBalance) external;
}

contract RejectingReceiver_VulnUncheckedReturn_4 {
    receive() external payable {
        revert("Reject ether");
    }
}

contract VulnUncheckedReturn_4Test {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    VulnUncheckedReturn_4 target;
    RejectingReceiver_VulnUncheckedReturn_4 receiver;

    function setUp() public {
        target = new VulnUncheckedReturn_4();
        receiver = new RejectingReceiver_VulnUncheckedReturn_4();
        vm.deal(address(target), 5 ether);
    }

    function testUncheckedReturnExploit() public {
        // sendEther fails silently without reverting
        (bool success, ) = address(target).call(abi.encodeWithSignature("sendEther(address,uint256)", payable(address(receiver)), 1 ether));
        require(success, "Unchecked return exploit confirmed: silent send failure was not detected");
    }
}
