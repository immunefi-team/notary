pragma solidity >=0.8.4;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/utils/math/SafeCast.sol";

import "hardhat/console.sol";

contract BugReportNotary is Initializable, AccessControl {

  using SafeERC20 for IERC20;
  using Address for address payable;
  using SafeCast for uint256;

  address public constant NATIVE_ASSET = address(0x0); // mock address that represents the native asset of the chain
  bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
  uint256 private constant SEPARATOR_LEAF = 0;
  uint256 private constant SEPARATOR_ATTESTATION = 1;
  string private constant KEY_REPORTER = "reporter";
  string private constant KEY_REPORT = "report";
  uint64 private constant ATTESTATION_DELAY = 17280;

  struct TimestampPadded {
    uint8 flags;
    uint184 _reserved;
    uint64 blockHeight;
  }

  struct Attestation {
    TimestampPadded timestamp;
    bytes32 commitment;
  }

  mapping (bytes32 => TimestampPadded) public reports; // report root => block.number
  mapping (bytes32 => TimestampPadded) public reportStatuses; // keccak256(report root, triager address) => report's statuses (bit field) as reported by triager
  mapping (bytes32 => TimestampPadded) public disclosures; // keccak256(report root, key) => Disclosure
  mapping (bytes32 => Attestation) public attestations; // keccak256(report root, triager address, key) => Attestation
  mapping (bytes32 => uint256) public balances; // keccak256(report root, payment token address) => balance

  event ReportSubmitted(bytes32 indexed reportRoot, uint64 seenAtBlock);
  event ReportUpdated(address indexed triager, bytes32 indexed reportRoot, uint8 newStatusBitField);
  event ReportDisclosure(bytes32 indexed reportRoot, string indexed key, bytes data);
  event ReportAttestation(address indexed triager, bytes32 indexed reportRoot, string indexed key, uint64 seenAtBlock);

  event Payment(bytes32 indexed reportRoot, address indexed from, address paymentToken, uint256 amount);
  event Withdrawal(bytes32 indexed reportRoot, address indexed to, address paymentToken, uint256 amount);

  //ACCESS CONTROL
  function initialize(address initAdmin) external initializer {
    _setupRole(DEFAULT_ADMIN_ROLE, initAdmin);
    _setupRole(OPERATOR_ROLE, initAdmin);
  }

  // NOTARY FUNCTIONS
  function submit(bytes32 reportRoot) external onlyRole(OPERATOR_ROLE) {
    require(reports[reportRoot].blockHeight == 0);
    uint64 blockNo = block.number.toUint64();
    reports[reportRoot] = TimestampPadded(0, 0, blockNo);
    emit ReportSubmitted(reportRoot, blockNo);
  }

  function _getReportStatusID(bytes32 reportRoot, address triager) internal pure returns (bytes32) {
    return keccak256(abi.encode(reportRoot, triager));
  }

  function _getAttestationID(bytes32 reportRoot, address triager, string memory key) internal pure returns (bytes32) {
    return keccak256(abi.encode(reportRoot, triager, key));
  }

  function _getDisclosureID(bytes32 reportRoot, string memory key) internal pure returns (bytes32) {
    return keccak256(abi.encode(reportRoot, key));
  }

  function attest(bytes32 reportRoot, string calldata key, bytes32 commitment) external onlyRole(OPERATOR_ROLE) {
    require(commitment != 0x0);
    Attestation storage attestation = attestations[_getAttestationID(reportRoot, msg.sender, key)];
    require(attestation.timestamp.blockHeight == 0 && attestation.commitment == 0x0);
    uint64 blockNo = block.number.toUint64();
    attestation.commitment = commitment;
    attestation.timestamp = TimestampPadded(0, 0, blockNo);
    emit ReportAttestation(msg.sender, reportRoot, key, blockNo);
  }

  function _validateBlockHeight(bytes32 reportRoot, uint64 eventBlockHeight) internal view {
    require(eventBlockHeight + ATTESTATION_DELAY <= disclosures[_getDisclosureID(reportRoot, KEY_REPORT)].blockHeight);
  }

  function validateAttestation(bytes32 reportRoot, address triager, bytes32 salt, bytes calldata value, bytes32[] calldata merkleProof) public view {
    Attestation memory attestation = attestations[_getAttestationID(reportRoot, triager, KEY_REPORT)];
    _validateBlockHeight(reportRoot, attestation.timestamp.blockHeight);
    bytes32 attestationHash = keccak256(bytes.concat(abi.encode(SEPARATOR_ATTESTATION, triager, KEY_REPORT, salt), value));
    require(attestation.commitment == attestationHash);
    _checkProof(reportRoot, KEY_REPORT, salt, value, merkleProof);
  }

  function updateReport(bytes32 reportRoot, uint8 newStatusBitField) external onlyRole(OPERATOR_ROLE) {
    require(attestations[_getAttestationID(reportRoot, msg.sender, KEY_REPORT)].commitment != 0);
    require(newStatusBitField != 0);
    reportStatuses[_getReportStatusID(reportRoot, msg.sender)] = TimestampPadded(newStatusBitField, 0, block.number.toUint64());
    emit ReportUpdated(msg.sender, reportRoot, newStatusBitField);
  }

  function _getFlag(uint256 flags, uint8 which) internal pure returns (bool) {
    return flags >> which & 1 == 1;
  }

  function reportHasStatus(bytes32 reportRoot, address triager, uint8 statusType) public view returns (bool) {
    return _getFlag(reportStatuses[_getReportStatusID(reportRoot, triager)].flags, statusType);
  }

  function validateReportStatus(bytes32 reportRoot, address triager, uint8 statusType, bytes32 salt, bytes calldata value, bytes32[] calldata merkleProof) public view returns (bool) {
    validateAttestation(reportRoot, triager, salt, value, merkleProof);
    TimestampPadded memory reportStatus = reportStatuses[_getReportStatusID(reportRoot, triager)];
    _validateBlockHeight(reportRoot, reportStatus.blockHeight);
    return _getFlag(reportStatus.flags, statusType);
  }

  function disclose(bytes32 reportRoot, string calldata key, bytes32 salt, bytes calldata value, bytes32[] calldata merkleProof)
   external onlyRole(OPERATOR_ROLE) {
    TimestampPadded storage timestamp = disclosures[_getDisclosureID(reportRoot, key)];
    require(timestamp.blockHeight == 0);
    _checkProof(reportRoot, key, salt, value, merkleProof);
    timestamp.blockHeight = block.number.toUint64();
    emit ReportDisclosure(reportRoot, key, value);
  }

  // on-chain disclosure
  function _checkProof(bytes32 reportRoot, string memory key, bytes32 salt, bytes memory value, bytes32[] calldata merkleProof) internal view {
    require(reports[reportRoot].blockHeight != 0, "Bug Report Notary: Merkle root not submitted.");
    bytes32 leafHash = keccak256(bytes.concat(abi.encode(SEPARATOR_LEAF, key, salt), value));
    require(MerkleProof.verify(merkleProof, reportRoot, leafHash), "Bug Report Notary: Merkle proof failed.");
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

  function payReporter(bytes32 reportRoot, address paymentToken, uint256 amount) external payable {
    require(amount > 0);
    bytes32 balanceID = _getBalanceID(reportRoot, paymentToken);
    uint256 currBalance = balances[balanceID];
    _modifyBalance(balanceID, currBalance + amount);
    emit Payment(reportRoot, msg.sender, paymentToken, amount);
    if (paymentToken == NATIVE_ASSET) {
      require(msg.value == amount);
    } else {
      require(msg.value == 0);
      IERC20(paymentToken).safeTransferFrom(msg.sender, address(this), amount);
    }
  }

  // Note: future versions may only allow EOAs to call this fn
  function withdraw(bytes32 reportRoot, address paymentToken, uint256 amount, bytes32 salt, address reporter, bytes32[] calldata merkleProof)
   external {
    bytes32 balanceID = _getBalanceID(reportRoot, paymentToken);
    uint256 currBalance = balances[balanceID];
    _checkProof(reportRoot, KEY_REPORTER, salt, abi.encode(reporter), merkleProof);
    _modifyBalance(balanceID, currBalance - amount);
    emit Withdrawal(reportRoot, reporter, paymentToken, amount);
    if (paymentToken == NATIVE_ASSET) {
      payable(reporter).sendValue(amount);
    } else {
      IERC20(paymentToken).safeTransfer(reporter, amount);
    }
  }
}
