// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

// This is a standard and fully functional ERC20 contract
contract FinTestToken is ERC20, Ownable {
    constructor(uint256 initialSupply) ERC20("FinTestToken", "FTT") {
        _mint(msg.sender, initialSupply);
    }

    // Function to mint new tokens
    function mint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }

    // Function to burn tokens
    function burn(address from, uint256 amount) public onlyOwner {
        _burn(from, amount);
    }
}