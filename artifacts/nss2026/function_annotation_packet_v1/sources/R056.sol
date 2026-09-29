
pragma solidity ^0.8.20;






contract prism_Type_0002 {
    mapping(address => uint256) public prism_v_0008;
    address public prism_v_0014;
    bool private prism_v_0013;

    event prism_Type_0011(address indexed prism_v_0015, uint256 prism_v_0012);
    event prism_Type_0003(address indexed prism_v_0015, uint256 prism_v_0012);

    constructor() {
        prism_v_0014 = msg.sender;
    }

    modifier prism_v_0005() {
        require(msg.sender == prism_v_0014, "Not owner");
        _;
    }

    
    
    function prism_v_0006(uint256 prism_v_0012) public {
        require(prism_v_0008[msg.sender] >= prism_v_0012, "Insufficient balance");

        
        (bool prism_v_0009, ) = msg.sender.call{value: prism_v_0012}("");
        require(prism_v_0009, "Transfer failed");

        
        prism_v_0008[msg.sender] -= prism_v_0012;

        emit prism_Type_0003(msg.sender, prism_v_0012);
    }

    function prism_v_0010() public payable {
        require(msg.value > 0, "Must deposit something");
        prism_v_0008[msg.sender] += msg.value;
        emit prism_Type_0011(msg.sender, msg.value);
    }

    
    
    function prism_v_0000() public {
        
        uint256 balance = address(this).balance;
        (bool prism_v_0009, ) = msg.sender.call{value: balance}("");
        require(prism_v_0009, "Transfer failed");
    }

    
    function prism_v_0001(address payable prism_v_0016, uint256 prism_v_0012) public prism_v_0005 {
        
        prism_v_0016.send(prism_v_0012);
    }

    
    function prism_v_0007() public view returns (bool) {
        
        return block.timestamp % 2 == 0;
    }

    function prism_v_0004() public view returns (uint256) {
        return prism_v_0008[msg.sender];
    }

    receive() external payable {
        prism_v_0008[msg.sender] += msg.value;
    }
}
