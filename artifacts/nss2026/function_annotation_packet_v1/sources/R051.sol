
pragma solidity ^0.8.0;

contract prism_Type_0003 {
    mapping(address => uint256) public prism_v_0002;
    bool internal prism_v_0007;

    modifier prism_v_0000() {
        require(!prism_v_0007, "No re-entrancy");
        prism_v_0007 = true;
        _;
        prism_v_0007 = false;
    }

    function prism_v_0006() public payable {
        prism_v_0002[msg.sender] += msg.value;
    }

    function prism_v_0001(uint256 prism_v_0005) public prism_v_0000 {
        require(prism_v_0002[msg.sender] >= prism_v_0005, "Insufficient balance");
        
        (bool prism_v_0004, ) = msg.sender.call{value: prism_v_0005}("");
        require(prism_v_0004, "Transfer failed");

        
        prism_v_0002[msg.sender] -= prism_v_0005;
    }
}
