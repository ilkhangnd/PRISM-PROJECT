// MUTATED: Access control removed
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableBank
 * @notice A deliberately vulnerable contract for testing PRISM's detection capabilities.
 * @dev Contains: Reentrancy, Access Control, Integer Overflow patterns.
 */
contract VulnerableBank {
    mapping(address => uint256) public balances;
    address public owner;
    bool private locked;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    modifier () {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // Vulnerability: Reentrancy (SWC-107)
    // The external call happens before the state update
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // BUG: External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update happens AFTER the external call
        balances[msg.sender] -= amount;

        emit Withdrawal(msg.sender, amount);
    }

    function deposit() public payable {
        require(msg.value > 0, "Must deposit something");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // Vulnerability: Missing Access Control (SWC-115)
    // Anyone can call this function to drain the contract
    function emergencyWithdraw() public {
        // BUG: No access control — should be onlyOwner
        uint256 balance = address(this).balance;
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
    }

    // Vulnerability: Unchecked Return Value (SWC-104)
    function unsafeTransfer(address payable to, uint256 amount) public onlyOwner {
        // BUG: Return value not checked
        to.send(amount);
    }

    // Vulnerability: Timestamp Dependence (SWC-116)
    function timeLock() public view returns (bool) {
        // BUG: Using block.timestamp for critical logic
        return block.timestamp % 2 == 0;
    }

    function getBalance() public view returns (uint256) {
        return balances[msg.sender];
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}
