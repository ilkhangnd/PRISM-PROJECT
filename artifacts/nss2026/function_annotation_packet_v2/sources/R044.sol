
pragma solidity ^0.8.0;
contract prism_Type_0000 {
    function prism_v_0001(address payable prism_v_0004, uint prism_v_0003) public {
        bool prism_v_0002 = prism_v_0004.send(prism_v_0003);
        require(prism_v_0002, "Failed");
    }
}
