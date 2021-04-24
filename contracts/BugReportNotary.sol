pragma solidity >=0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

contract BugReportNotary is Initializable, AccessControl {

  using SafeERC20 for IERC20;

  address public constant nativeAsset = address(0x0); // mock address that represents the native asset of the chain 
  bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

  struct BugReport {
    address reporter; // bug's reporter
    bytes32 contentHash; // hash of contents of report or root of merkle tree
    uint256 statusBitField; // report's statuses as bit field
  }

  uint256 public lastReportID;
  mapping (uint256 => BugReport) public reports;
  mapping (bytes32 => uint256) public balances;

  event ReportSubmitted(address indexed reporter, uint256 reportID);
  event ReportUpdated(uint256 indexed reportID, uint256 prevStatusBitField, uint256 newStatusBitField);
  event ReportDisclosure(uint256 indexed reportID, bytes data);
  event Payment(uint256 indexed reportID, address paymentToken, uint256 amount);
  event Deposit(address indexed depositor, address paymentToken, uint256 amount);
  event Withdrawal (address indexed to, address paymentToken, uint amount);

  //ACCESS CONTROL
  function initialize(address initAdmin) external initializer {
    _setupRole(DEFAULT_ADMIN_ROLE, initAdmin);
    _setupRole(OPERATOR_ROLE, initAdmin);
  }

  // NOTARY FUNCTIONS
  function submit(bytes32 contentHash, address reporter) external onlyRole(OPERATOR_ROLE) {
    lastReportID++;
    reports[lastReportID] = BugReport(reporter, contentHash, 1);
    emit ReportSubmitted(reporter, lastReportID);
  }

  function updateReport(uint256 reportID, uint256 newStatusBitField) public onlyRole(OPERATOR_ROLE) {
    uint256 prevStatusBitField = reports[reportID].statusBitField;
    reports[reportID].statusBitField = newStatusBitField;
    emit ReportUpdated(reportID, prevStatusBitField, newStatusBitField);
  }

  function reportHasStatus(uint256 reportID, uint8 statusType) external view returns (bool) {
    return reports[reportID].statusBitField >> statusType & 1 == 1;
  }

  function setReportStatus(uint256 reportID, uint8 statusType, bool toggle) external onlyRole(OPERATOR_ROLE) {
    uint newStatus = reports[reportID].statusBitField;
    if (toggle) {
      newStatus |= 1 << statusType;
    } else {
      newStatus &= ~(1 << statusType);
    }
    updateReport(reportID, newStatus);
  }

  // on-chain disclosure
  function disclose(uint256 reportID, bytes calldata report, bytes32[] calldata merkleProof) external onlyRole(OPERATOR_ROLE) {
    bytes32 currHash = keccak256(report); // leaf node
    for (uint256 i = 0; i < merkleProof.length; i++) {
      bytes32 proofSegment = merkleProof[i];

      if (currHash <= proofSegment) {
        currHash = keccak256(abi.encodePacked(currHash, proofSegment));
      } else {
        currHash = keccak256(abi.encodePacked(proofSegment, currHash));
      }
    }
    require(currHash == reports[reportID].contentHash, "Bug Report Notary: Report does not match content hash.");
    emit ReportDisclosure(reportID, report);
  }

  // PAYMENT FUNCTIONS
  function deposit(address paymentToken, uint256 amount) public payable {
    require(amount > 0, "Bug Report Notary: amount must be greater than 0.");
    if (paymentToken == nativeAsset) {
      require(msg.value == amount);
    } else {
      require(msg.value == 0);
      IERC20(paymentToken).safeTransferFrom(msg.sender, address(this), amount);
    }
    Deposit(msg.sender, paymentToken, amount);
  }

  function getBalance(address user, address paymentToken) public view returns (uint256){
    return balances[_getBalanceID(user, paymentToken)];
  }

  function getBalance(bytes32 balanceID) public view returns (uint256) {
    return balances[balanceID];
  }
  
  function _getBalanceID(address user, address paymentToken) internal pure returns (bytes32) {
    return keccak256(abi.encodePacked(user, paymentToken));
  }

  function _modifyBalance(bytes32 balanceID, uint256 newAmount) internal {
    balances[balanceID] = newAmount;
  }

  function payReporter(uint256 reportID, address paymentToken, uint256 amount) public onlyRole(OPERATOR_ROLE) {
    bytes32 balanceID = _getBalanceID(msg.sender, paymentToken);
    uint currBalance = getBalance(balanceID);
    _modifyBalance(balanceID, currBalance + amount);
    emit Payment(reportID, paymentToken, amount);
  }

  function withdraw(address paymentToken, uint amount) public {
    bytes32 balanceID = _getBalanceID(msg.sender, paymentToken);
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