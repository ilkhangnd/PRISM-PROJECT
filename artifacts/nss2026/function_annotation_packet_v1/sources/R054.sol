
pragma solidity ^0.8.20;





contract prism_Type_0002 {
    mapping(address => uint256) public prism_v_0004;
    uint256 public constant prism_Type_0000 = 1 ether;

    function prism_v_0009(uint256 prism_v_0003) public payable {
        
        
        
        uint256 prism_v_0007;
        unchecked {
            
            prism_v_0007 = prism_v_0003 * prism_Type_0000;
        }
        require(msg.value >= prism_v_0007, "Not enough ETH");
        prism_v_0004[msg.sender] += prism_v_0003;
    }

    function prism_v_0008(uint256 prism_v_0003) public {
        require(prism_v_0004[msg.sender] >= prism_v_0003, "Not enough tokens");
        prism_v_0004[msg.sender] -= prism_v_0003;
        uint256 prism_v_0006 = prism_v_0003 * prism_Type_0000;
        (bool prism_v_0005, ) = msg.sender.call{value: prism_v_0006}("");
        require(prism_v_0005, "Transfer failed");
    }

    function prism_v_0001() public view returns (uint256) {
        return prism_v_0004[msg.sender];
    }

    receive() external payable {}
}
