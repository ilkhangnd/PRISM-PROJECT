// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Token {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/**
 * @title UncheckedReturnVault
 * @notice Vulnerable to unhandled low-level call / token return boolean (SWC-104).
 */
contract UncheckedReturnVault {
    mapping(address => uint256) public userBalances;

    function deposit(address token, uint256 amount) external {
        // Vulnerability: Low-level call return value not checked
        token.call(abi.encodeWithSelector(IERC20Token.transferFrom.selector, msg.sender, address(this), amount));
        userBalances[msg.sender] += amount;
    }

    function withdraw(address token, uint256 amount) external {
        require(userBalances[msg.sender] >= amount, "Exceeds balance");
        userBalances[msg.sender] -= amount;

        // Vulnerability: Ignored return value allows silent transfer failures
        token.call(abi.encodeWithSelector(IERC20Token.transfer.selector, msg.sender, amount));
    }
}
