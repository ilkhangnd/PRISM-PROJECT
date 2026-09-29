
pragma solidity ^0.8.20;





contract prism_Type_0001 {
    mapping(address => uint256) public prism_v_0005;

    function prism_v_0006(address prism_v_0007) public payable {
        prism_v_0005[prism_v_0007] += msg.value;
    }

    
    
    function prism_v_0002(uint256 prism_v_0004) public {
        if (prism_v_0005[msg.sender] >= prism_v_0004) {
            
            (bool prism_v_0003, ) = msg.sender.call{value: prism_v_0004}("");
            require(prism_v_0003);
            prism_v_0005[msg.sender] -= prism_v_0004;
        }
    }

    function prism_v_0000(address prism_v_0007) public view returns (uint256) {
        return prism_v_0005[prism_v_0007];
    }

    receive() external payable {}
}
