// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UncheckedBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function transferViaSend(address payable recipient, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        bool sent = recipient.send(amount);
        require(sent, "Send failed"); // PRISM FIX: Checked Return
    }

    receive() external payable {}
}

contract RejectEther {
    receive() external payable {
        revert("Rejecting Ether");
    }
}
