pragma solidity >=0.8.4;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

import "hardhat/console.sol";

contract BugReportNotary is Initializable, AccessControl {

  using SafeERC20 for IERC20;

  address public constant nativeAsset = address(0x0); // mock address that represents the native asset of the chain 
  bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

  struct Attestation {
    uint192 _reserved;
    uint32 blockHeight;
    bytes32 attestation;
  }

  struct Disclosure {
    uint192 _reserved;
    uint32 blockHeight;
  }

  mapping (bytes32 => uint256) public reports; // report root => block.number
  mapping (bytes32 => uint256) public balances; // keccak256(report root, payment token address) => balance
  mapping (bytes32 => uint256) public reportStatuses; // keccak256(report root, triager address) => report's statuses (bit field) as reported by triager
  mapping (bytes32 => Attestation) public attestations; // keccak256(reportStatusID, key) => Attestation
  mapping (bytes32 => Disclosure) public disclosures; // keccak256(report root, key) => Disclosure

  event ReportSubmitted(bytes32 indexed reportRoot, uint256 seenAtBlock);
  event ReportUpdated(address indexed triager, bytes32 indexed reportRoot, uint256 newStatusBitField);
  event ReportDisclosure(bytes32 indexed reportRoot, string indexed key, bytes value, bytes32 salt);
  event Payment(bytes32 indexed reportRoot, address indexed from, address paymentToken, uint256 amount);
  event Withdrawal(bytes32 indexed reportRoot, address indexed to, address paymentToken, uint256 amount);

  //ACCESS CONTROL
  function initialize(address initAdmin) external initializer {
    _setupRole(DEFAULT_ADMIN_ROLE, initAdmin);
    _setupRole(OPERATOR_ROLE, initAdmin);
  }

  // NOTARY FUNCTIONS
  function submit(bytes32 reportRoot) external onlyRole(OPERATOR_ROLE) {
    require(reports[reportRoot] == 0);
    uint256 blockNo = block.number;
    reports[reportRoot] = blockNo;
    emit ReportSubmitted(reportRoot, blockNo);
  }

  function _getReportStatusID(bytes32 reportRoot, address triager) internal pure returns (bytes32) {
    return keccak256(abi.encode(reportRoot, triager));
  }

  function attest(bytes32 reportRoot, uint256 firstStatus, bytes32 commitment) external onlyRole(OPERATOR_ROLE) {
    require(reportStatuses[_getReportStatusID(reportRoot, msg.sender)] == 0);
    _updateReport(reportRoot, firstStatus);
  }

  function checkAttestation(bytes32 reportRoot, bytes value, bytes32 salt, bytes32[] calldata merkleProof) onlyRole(OPERATOR_ROLE) {
    _checkProof(reportRoot, "description", value, data, salt, merkleProof);
  }

  function updateReport(bytes32 reportRoot, uint256 newStatusBitField) external onlyRole(OPERATOR_ROLE) {
    bytes32 reportStatusID = _getReportStatusID(reportRoot, msg.sender);
    require(reportStatuses[reportStatusID] != 0);
    _updateReport(reportRoot, newStatusBitField);
  }

  function _updateReport(bytes32 reportRoot, uint256 newStatusBitField) internal {
    require(newStatusBitField != 0);
    reportStatuses[_getReportStatusID(reportRoot, msg.sender)] = newStatusBitField;
    emit ReportUpdated(msg.sender, reportRoot, newStatusBitField);
  }

  function reportHasStatus(uint256 reportRoot, address triager, uint8 statusType) external view returns (bool) {
    return reportStatuses[_getReportStatusID(reportRoot, triager)] >> statusType & 1 == 1;
  }

   function disclose(uint256 reportRoot, string key, bytes calldata data, bytes32 salt, bytes32[] calldata merkleProof) external onlyRole(OPERATOR_ROLE) {
     _checkProof(reportRoot, key, data, merkleProof);
    emit ReportDisclosure(reportRoot, data);
   }
  // on-chain disclosure
  function _checkProof(uint256 reportRoot, string key, bytes data, bytes32 salt, bytes32[] merkleProof) internal view {
    require(reports[reportRoot] != 0);
    bytes32 currHash = keccak256(bytes.concat(bytes1(0x00), abi.encode(key), data, salt));
    for (uint256 i = 0; i < merkleProof.length; i++) {
      bytes32 proofSegment = merkleProof[i];

      if (currHash <= proofSegment) {
        currHash = keccak256(bytes.concat(bytes1(0x01), currHash, proofSegment));
      } else {
        currHash = keccak256(bytes.concat(bytes1(0x01), proofSegment, currHash));
      }
    }
    require(currHash == reportRoot, "Bug Report Notary: Merkle proof failed.");
  }

  function getBalance(bytes32 reportRoot, address paymentToken) public view returns (uint256) {
    return balances[_getBalanceID(reportRoot, paymentToken)];
  }
  
  function _getBalanceID(bytes32 reportRoot, address paymentToken) internal pure returns (bytes32) {
    return keccak256(abi.encode(reportRoot, paymentToken));
  }

  function _modifyBalance(bytes32 balanceID, uint256 newAmount) internal {
    balances[balanceID] = newAmount;
  }

  function payReporter(bytes32 reportRoot, address paymentToken, uint256 amount) public payable {
    require(amount > 0);
    bytes32 balanceID = _getBalanceID(reportRoot, paymentToken);
    uint256 currBalance = balances[balanceID];
    _modifyBalance(balanceID, currBalance + amount);
    emit Payment(reportRoot, msg.sender, paymentToken, amount);
    if (paymentToken == nativeAsset) {
      require(msg.value == amount);
    } else {
      require(msg.value == 0);
      IERC20(paymentToken).safeTransferFrom(msg.sender, address(this), amount);
    }
  }

  function withdraw(bytes32 reportRoot, address paymentToken, uint256 amount, bytes32[] calldata merkleProof) public {
    bytes32 balanceID = _getBalanceID(reportRoot, paymentToken);
    uint256 currBalance = getBalance(balanceID);
    _modifyBalance(balanceID, currBalance - amount);
    _checkProof(reportRoot, abi.encode("reporter", msg.sender), merkleProof);
    emit Withdrawal(reportRoot, msg.sender, paymentToken, amount);
    if (paymentToken == nativeAsset) {
      (bool sent, ) = payable(msg.sender).call{value: amount}("");
      require(sent, "Bug Report Notary: Failed to send native asset");
    } else {
      IERC20(paymentToken).safeTransfer(msg.sender, amount);
    }
  }
}