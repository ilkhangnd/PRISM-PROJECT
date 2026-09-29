
pragma solidity ^0.8.0;
contract prism_Type_0000 {
    mapping(address => uint) prism_v_0003;
    bool prism_v_0006;
    modifier prism_v_0001() {
        require(!prism_v_0006);
        prism_v_0006 = true;
        _;
        prism_v_0006 = false;
    }
    function prism_v_0002() public prism_v_0001 {
        uint prism_v_0005 = prism_v_0003[msg.sender];
        require(prism_v_0005 > 0);
        (bool prism_v_0004, ) = msg.sender.call{value: prism_v_0005}("");
        require(prism_v_0004);
        prism_v_0003[msg.sender] = 0; 
    }
}
