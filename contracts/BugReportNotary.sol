pragma solidity >=0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";

// to be proxied by https://github.com/OpenZeppelin/openzeppelin-contracts/blob/7f6a1666fac8ecff5dd467d0938069bc221ea9e0/contracts/proxy/transparent/TransparentUpgradeableProxy.sol

contract BugReportNotary is Initializable {

  using SafeERC20 for IERC20;

  address public constant nativeAsset = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE; // mock address that represents the native asset of the chain 

  /*
  enum Status {
    NULL,
    SUBMITTED, // bug has been submitted to immunefi
    MORE_INFO_REQUESTED, // signal that we need more info and communication didn't stop on our side
    UNDER_REVIEW, // being confirmed by Immunefi
    VALIDATED, // issue's existance confirmed by Immunefi, sent to project, and advance paid out
    IN_TRIAGE, // project has acknowledged the report, and we're waiting on a verdict
    // VERDICTS
    REJECTED,
    ACCEPTED,
    DUPLICATE
  }*/

  struct BugReport {
    address reporter; // bug's reporter
    bytes32 contentHash; // hash of contents of report or root of merkle tree
    uint256 statusBitField; // report's statuses as bit field
  }

  uint256 public lastReportID;
  mapping (uint256 => BugReport) public reports;
  mapping (bytes32 => uint256) public balances;
  mapping (address => bool) public operators;

  event ReportSubmitted(address indexed reporter, uint256 reportID);
  event ReportUpdated(uint256 indexed reportID, uint256 prevStatusBitField, uint256 newStatusBitField);
  event ReportDisclosure(uint256 indexed reportID, bytes data);
  event Payment(uint256 indexed reportID, address paymentToken, uint256 amount);
  event Deposit(address indexed depositor, address paymentToken, uint256 amount);
  event Withdrawal (address indexed to, address paymentToken, uint amount);

  //ACCESS CONTROL
  modifier onlyOperator {
    require(operators[msg.sender], "Bug Report Notary: Not Authorized");
    _;
  }

  function updateOperator(address user, bool isOperator) external onlyOperator {
    _updateOperator(user, isOperator);
  }

  function _updateOperator(address user, bool isOperator) internal {
    operators[user] = isOperator;
  }

  function initialize(address initOperator) external initializer {
    _updateOperator(initOperator, true);
  }

  // NOTARY FUNCTIONS
  function submit(bytes32 contentHash, address reporter) external onlyOperator {
    lastReportID++;
    reports[lastReportID] = BugReport(reporter, contentHash, 1);
    emit ReportSubmitted(reporter, lastReportID);
  }

  function updateReport(uint256 reportID, uint256 newStatus) public onlyOperator {
    emit ReportUpdated(reportID, reports[reportID].statusBitField, newStatus);
    reports[reportID].statusBitField = newStatus;
  }

  function reportHasStatus(uint256 reportID, uint8 statusType) external view returns (bool) {
    return reports[reportID].statusBitField >> statusType & 1 == 1;
  }

  function setReportStatus(uint256 reportID, uint8 statusType, bool toggle) external onlyOperator {
    uint newStatus = reports[reportID].statusBitField;
    if (toggle) {
      newStatus |= 1 << statusType;
    } else {
      newStatus &= ~(1 << statusType);
    }
    updateReport(reportID, newStatus);
  }

  // on-chain disclosure
  function disclose(uint256 reportID, bytes calldata report, bytes32[] calldata merkleProof) external onlyOperator {
    bytes32 currHash = keccak256(report); // leaf node
    for (uint256 i = 0; i < merkleProof.length; i++) {
      bytes32 proofSegment = merkleProof[i];

      if (currHash <= proofSegment) {
        currHash = keccak256(abi.encodePacked(currHash, proofSegment));
      } else {
        currHash = keccak256(abi.encodePacked(proofSegment, currHash));
      }
    }
    require(currHash == reports[lastReportID].contentHash, "Bug Report Notary: Report does not match content hash.");
    emit ReportDisclosure(reportID, report);
  }

  // PAYMENT FUNCTIONS

  function deposit(address paymentToken, uint256 amount) public payable {
    if (paymentToken == nativeAsset) {
      require(msg.value == amount);
    } else {
      require(msg.value == 0);
      IERC20(paymentToken).safeTransferFrom(msg.sender, address(this), amount);
    }
    Deposit(msg.sender, paymentToken, amount);
  }

  function depositAndPayReporter(uint256 reportID, address paymentToken, uint256 amount) public payable {
    deposit(paymentToken, amount);
    _payReporter(reportID, paymentToken, amount);
  }

  function getBalance(address user, address paymentToken) public view returns (uint256){
    return balances[keccak256(abi.encodePacked(user, paymentToken))];
  }

  function getBalance(bytes32 balanceID) public view returns (uint256) {
    return balances[balanceID];
  }

  function _modifyBalance(bytes32 balanceID, uint256 newAmount) internal {
    balances[balanceID] = newAmount;
  }

  function payReporter(uint256 reportID, address paymentToken, uint256 amount) public onlyOperator {
    _payReporter(reportID, paymentToken, amount);
  }

  function _payReporter(uint256 reportID, address paymentToken, uint256 amount) internal {
    bytes32 balanceID = keccak256(abi.encodePacked(reports[reportID].reporter, paymentToken));
    uint currBalance = getBalance(balanceID);
    _modifyBalance(balanceID, currBalance + amount);
    emit Payment(reportID, paymentToken, amount);
  }

  function updateReportAndPay(uint256 reportID, uint256 newStatus, address paymentToken, uint256 amount) public onlyOperator {
    updateReport(reportID, newStatus);
    _payReporter(reportID, paymentToken, amount);
  }

  function withdraw(address paymentToken, uint amount) public {
    bytes32 balanceID = keccak256(abi.encodePacked(msg.sender, paymentToken));
    uint currBalance = getBalance(balanceID);
    _modifyBalance(balanceID, currBalance - amount);
    if (paymentToken == nativeAsset) {
      (bool sent, ) = payable(msg.sender).call{value: amount}("");
      require(sent, "Bug Report Notary: Failed to send native asset");
    } else {
      IERC20(paymentToken).safeTransfer(msg.sender, amount);
    }
    emit Withdrawal(msg.sender, paymentToken, amount);
  }
}