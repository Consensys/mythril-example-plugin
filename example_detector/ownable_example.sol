pragma solidity 0.6.11;

contract Ownable {
    address public owner;
    modifier onlyOwner {
        require(msg.sender == this.owner());
        _;
    }

    function kill() public onlyOwner {
        selfdestruct(msg.sender);
    }

    function transferOwnership(address newOwner) public {
        owner = newOwner;
    }
}
