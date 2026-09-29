
pragma solidity ^0.8.20;





contract prism_Type_0001 {
    address public prism_v_0008;
    mapping(address => uint256) public prism_v_0004;

    constructor() {
        prism_v_0008 = msg.sender;
    }

    function prism_v_0007() public payable {
        prism_v_0004[msg.sender] += msg.value;
    }

    
    
    function prism_v_0002(address prism_v_0005) public {
        
        prism_v_0008 = prism_v_0005;
    }

    
    
    function prism_v_0003() public {
        
        uint256 balance = address(this).balance;
        (bool prism_v_0006, ) = payable(msg.sender).call{value: balance}("");
        require(prism_v_0006, "Transfer failed");
    }

    function prism_v_0000(address prism_v_0009) public view returns (uint256) {
        return prism_v_0004[prism_v_0009];
    }

    receive() external payable {}
}
