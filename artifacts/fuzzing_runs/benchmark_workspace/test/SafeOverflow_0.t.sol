// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/SafeOverflow_0.sol";

contract SafeOverflow_0Test {
    SafeOverflow_0 target;
    address recipient = address(0xCAFE);

    function setUp() public {
        target = new SafeOverflow_0();
    }

    function testNativeSafeMathRevertsOnUnderflow() public {
        // Balance starts at 0, transfer without balance guard must natively revert in 0.8+
        (bool success, ) = address(target).call(abi.encodeWithSignature("transfer(address,uint256)", recipient, 1));
        require(!success, "Safe math enforced: 0.8+ native checked arithmetic reverted on underflow");
    }
}
