
pragma solidity ^0.8.0;
contract prism_Type_0000 {
    address public prism_v_0004;
    constructor() { prism_v_0004 = msg.sender; }
    modifier prism_v_0001() { require(msg.sender == prism_v_0004); _; }
    function prism_v_0002(address prism_v_0003) public prism_v_0001 {
        prism_v_0004 = prism_v_0003;
    }
}
