// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ReentrancyVault
 * @notice Classic stateful reentrancy vulnerability (SWC-107).
 */
contract ReentrancyVault {
    mapping(address => uint256) public balances;
    bool public locked;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    function deposit() external payable {
        require(msg.value > 0, "Zero deposit");
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "No balance");

        // Vulnerability: State updated AFTER external call
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0;
        emit Withdrawn(msg.sender, bal);
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {}
}
