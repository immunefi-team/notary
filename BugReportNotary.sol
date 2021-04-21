pragma solidity >=0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";

contract BugReportNotary is Initializable {

  using SafeERC20 for IERC20;

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
  }

  struct BugReport {
    bytes32 contentHash; // hash of content's of report
    address reporter; // bug's reporter
    Status status; // report's status
    bool disclosed; // whether or not the details of the vuln are public yet
  }

  uint256 public lastReportID;
  mapping (uint256 => BugReport) public reports;
  mapping (bytes32 => uint256) public balances;
  mapping (address => bool) public operators;

  event ReportSubmitted(address indexed reporter, uint256 reportID);
  event ReportUpdated(uint256 indexed reportID, Status prevStatus, Status newStatus);
  event ReportDisclosed(uint256 indexed reportID, bytes data);
  event PaymentMade(uint256 indexed reportID, address paymentToken, uint256 amount);
  event Withdrawal (address indexed to, address paymentToken, uint amount);

  //ACCESS CONTROL
  modifier onlyOperator {
    require(operators[msg.sender]);
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
    reports[lastReportID] = BugReport(contentHash, reporter, Status.SUBMITTED, false);
    emit ReportSubmitted(reporter, lastReportID);
  }

  function updateReport(uint256 reportID, Status newStatus) public onlyOperator {
    emit ReportUpdated(reportID, reports[reportID].status, newStatus);
    reports[reportID].status = newStatus;
  }

  function disclose(uint256 reportID, bytes calldata report) external onlyOperator {
    require(keccak256(report) == reports[lastReportID].contentHash);
    reports[lastReportID].disclosed = true;
    emit ReportDisclosed(reportID, report);
  }

  // PAYMENT FUNCTIONS

  function updateReportAndPay(uint256 reportID, Status newStatus, address paymentToken, uint256 amount) public onlyOperator {
    updateReport(reportID, newStatus);
    _payReporter(reportID, paymentToken, amount);
  }

  // allows projects to pay bug hunters without going through us
  function depositAndPayReporter(uint256 reportID, address paymentToken, uint256 amount) public {
    IERC20(paymentToken).safeTransferFrom(msg.sender, address(this), amount);
    _payReporter(reportID, paymentToken, amount);
  }

  function getBalance(address user, address token) public view returns (uint256){
    return balances[keccak256(abi.encodePacked(user, token))];
  }

  function getBalance(bytes32 balanceID) public view returns (uint256) {
    return balances[balanceID];
  }

  function _modifyBalance(bytes32 balanceID, uint256 newAmount) internal {
    balances[balanceID] = newAmount;
  }

  function payReporter(uint256 reportID, address token, uint256 amount) public onlyOperator {
    _payReporter(reportID, token, amount);
  }

  function _payReporter(uint256 reportID, address token, uint256 amount) internal {
    bytes32 balanceID = keccak256(abi.encodePacked(reports[reportID].reporter, token));
    uint currBalance = getBalance(balanceID);
    _modifyBalance(balanceID, currBalance + amount);
    emit PaymentMade(reportID, token, amount);
  }

  function withdraw(address token, uint amount) public {
    bytes32 balanceID = keccak256(abi.encodePacked(msg.sender, token));
    uint currBalance = getBalance(balanceID);
    _modifyBalance(balanceID, currBalance - amount);
    IERC20(token).safeTransfer(msg.sender, amount);
    emit Withdrawal(msg.sender, token, amount);
  }
}