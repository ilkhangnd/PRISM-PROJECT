
pragma solidity ^0.8.20;





contract prism_Type_0002 {
    uint256 public prism_v_0004;
    address public prism_v_0001;

    constructor() payable {
        prism_v_0004 = msg.value;
    }

    function prism_v_0007() public payable {
        require(msg.value >= 0.1 ether, "Minimum bet is 0.1 ETH");
        prism_v_0004 += msg.value;

        
        
        uint256 prism_v_0005 = uint256(
            keccak256(abi.encodePacked(block.timestamp, msg.sender))
        );

        if (prism_v_0005 % 10 == 0) {
            prism_v_0001 = msg.sender;
            uint256 prism_v_0006 = prism_v_0004;
            prism_v_0004 = 0;
            (bool prism_v_0003, ) = msg.sender.call{value: prism_v_0006}("");
            require(prism_v_0003, "Transfer failed");
        }
    }

    function prism_v_0000() public view returns (uint256) {
        return prism_v_0004;
    }

    receive() external payable {
        prism_v_0004 += msg.value;
    }
}
