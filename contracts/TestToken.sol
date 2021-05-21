// SPDX-License-Identifier: MIT
// Note: This contract is explicitly for ERC20 mock testing for hardhat.

pragma solidity >=0.8.4;

import "@openzeppelin/contracts/utils/Context.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract TestToken is Context,ERC20 {
    constructor (address _addr) ERC20("TestToken", "TTKN") {
        _mint(_addr, 10000 * (10 ** uint256(decimals())));
    }
}
