// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/SafeUncheckedReturn_0.sol";

interface Vm {
    function deal(address who, uint256 newBalance) external;
}

contract RejectingReceiver_SafeUncheckedReturn_0 {
    receive() external payable {
        revert("Reject ether");
    }
}

contract SafeUncheckedReturn_0Test {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    SafeUncheckedReturn_0 target;
    RejectingReceiver_SafeUncheckedReturn_0 receiver;

    function setUp() public {
        target = new SafeUncheckedReturn_0();
        receiver = new RejectingReceiver_SafeUncheckedReturn_0();
        vm.deal(address(target), 5 ether);
    }

    function testSafeSendRevertsOnFailure() public {
        // sendEther requires return value, so failing recipient causes transaction revert
        (bool success, ) = address(target).call(abi.encodeWithSignature("sendEther(address,uint256)", payable(address(receiver)), 1 ether));
        require(!success, "Safe return value check enforced: send failure was caught and reverted");
        require(address(target).balance == 5 ether, "Target balance preserved");
    }
}
