// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/SafeOverflow_4.sol";

contract SafeOverflow_4Test {
    SafeOverflow_4 target;
    address recipient = address(0xCAFE);

    function setUp() public {
        target = new SafeOverflow_4();
    }

    function testNativeSafeMathRevertsOnUnderflow() public {
        // Balance starts at 0, transfer without balance guard must natively revert in 0.8+
        (bool success, ) = address(target).call(abi.encodeWithSignature("transfer(address,uint256)", recipient, 1));
        require(!success, "Safe math enforced: 0.8+ native checked arithmetic reverted on underflow");
    }
}
