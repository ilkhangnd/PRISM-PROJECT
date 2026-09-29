// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableBank
 * @notice A deliberately vulnerable contract for testing PRISM's detection capabilities.
 * @dev Contains: Reentrancy, Access Control, Integer Overflow patterns.
 */
contract prism_Type_0002 {
    mapping(address => uint256) public prism_v_0006;
    address public prism_v_0014;
    bool private prism_v_0012;

    event prism_Type_0011(address indexed prism_v_0015, uint256 prism_v_0013);
    event prism_Type_0003(address indexed prism_v_0015, uint256 prism_v_0013);

    constructor() {
        prism_v_0014 = msg.sender;
    }

    modifier prism_v_0005() {
        require(msg.sender == prism_v_0014, "Not owner");
        _;
    }

    // Vulnerability: Reentrancy (SWC-107)
    // The external call happens before the state update
    function prism_v_0008(uint256 prism_v_0013) public {
        require(prism_v_0006[msg.sender] >= prism_v_0013, "Insufficient balance");

        // BUG: External call before state update
        (bool prism_v_0010, ) = msg.sender.call{value: prism_v_0013}("");
        require(prism_v_0010, "Transfer failed");

        // State update happens AFTER the external call
        prism_v_0006[msg.sender] -= prism_v_0013;

        emit prism_Type_0003(msg.sender, prism_v_0013);
    }

    function prism_v_0009() public payable {
        require(msg.value > 0, "Must deposit something");
        prism_v_0006[msg.sender] += msg.value;
        emit prism_Type_0011(msg.sender, msg.value);
    }

    // Vulnerability: Missing Access Control (SWC-115)
    // Anyone can call this function to drain the contract
    function prism_v_0000() public {
        // BUG: No access control — should be onlyOwner
        uint256 balance = address(this).balance;
        (bool prism_v_0010, ) = msg.sender.call{value: balance}("");
        require(prism_v_0010, "Transfer failed");
    }

    // Vulnerability: Unchecked Return Value (SWC-104)
    function prism_v_0001(address payable prism_v_0016, uint256 prism_v_0013) public prism_v_0005 {
        // BUG: Return value not checked
        prism_v_0016.send(prism_v_0013);
    }

    // Vulnerability: Timestamp Dependence (SWC-116)
    function prism_v_0007() public view returns (bool) {
        // BUG: Using block.timestamp for critical logic
        return block.timestamp % 2 == 0;
    }

    function prism_v_0004() public view returns (uint256) {
        return prism_v_0006[msg.sender];
    }

    receive() external payable {
        prism_v_0006[msg.sender] += msg.value;
    }
}
