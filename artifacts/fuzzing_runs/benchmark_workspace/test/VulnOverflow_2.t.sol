// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/VulnOverflow_2.sol";

contract VulnOverflow_2Test {
    VulnOverflow_2 target;
    address recipient = address(0xCAFE);

    function setUp() public {
        target = new VulnOverflow_2();
    }

    function testUnderflowExploit() public {
        // Balance starts at 0, transfer without balance guard inside unchecked {}
        (bool success, ) = address(target).call(abi.encodeWithSignature("transfer(address,uint256)", recipient, 1));
        require(success, "Underflow exploit confirmed: unchecked arithmetic allowed underflow without reverting");
    }
}
