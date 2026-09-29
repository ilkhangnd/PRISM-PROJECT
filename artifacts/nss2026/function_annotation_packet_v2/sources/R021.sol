
pragma solidity ^0.8.0;
contract prism_Type_0000 {
    mapping(address => uint) prism_v_0001;
    function transfer(address prism_v_0003, uint prism_v_0002) public {
        unchecked {
            prism_v_0001[msg.sender] -= prism_v_0002;
            prism_v_0001[prism_v_0003] += prism_v_0002;
        }
    }
}
