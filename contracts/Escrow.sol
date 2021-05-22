// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/utils/Address.sol";

contract Escrow is Initializable {

  using SafeERC20 for IERC20;
  using Address for address payable;

  address public constant NATIVE_ASSET = address(0x0); // mock address that represents the native asset of the chain
  string public constant KEY_REPORTER = "reporter";

  INotary public notary;
  mapping (bytes32 => uint256) public balances; // keccak256(report root, payment token address) => balance

  event Deposit(bytes32 indexed reportRoot, address indexed from, address paymentToken, uint256 amount);
  event Withdrawal(bytes32 indexed reportRoot, address indexed to, address paymentToken, uint256 amount);

  function initialize(address _notary) external initializer {
    notary = _notary;
  }

  function getBalance(bytes32 reportRoot, address paymentToken) public view returns (uint256) {
    return balances[_getBalanceID(reportRoot, paymentToken)];
  }

  function _getBalanceID(bytes32 reportRoot, address paymentToken) internal pure returns (bytes32) {
    return keccak256(abi.encode(reportRoot, paymentToken));
  }

  function deposit(bytes32 reportRoot, address paymentToken, uint256 amount) external payable {
    require(amount > 0, "Bug Report Escrow: Amount must be larger than zero");
    require(notary.reports(reportRoot).timestamp != 0, "Bug Report Escrow: Report not submitted");
    uint256 storage balance = balances[_getBalanceID(reportRoot, paymentToken)];
    balance = balance + amount;
    emit Deposit(reportRoot, msg.sender, paymentToken, amount);
    if (paymentToken == NATIVE_ASSET) {
      require(msg.value == amount, "Bug Report Escrow: Insufficient funds sent");
    } else {
      require(msg.value == 0, "Bug Report Escrow: Native asset sent for ERC20 payment");
      IERC20(paymentToken).safeTransferFrom(msg.sender, address(this), amount);
    }
  }

  // Note: future versions may only allow EOAs to call this fn
  function withdraw(bytes32 reportRoot, address paymentToken, uint256 amount, bytes32 salt, address reporter, bytes32[] calldata merkleProof) external {
    uint256 storage balance = balances[_getBalanceID(reportRoot, paymentToken)];
    balance = balance - amount;
    emit Withdrawal(reportRoot, reporter, paymentToken, amount);
    notary.disclose(reportRoot, KEY_REPORTER, salt, abi.encode(reporter), merkleProof);
    if (paymentToken == NATIVE_ASSET) {
      payable(reporter).sendValue(amount);
    } else {
      IERC20(paymentToken).safeTransfer(reporter, amount);
    }
  }
