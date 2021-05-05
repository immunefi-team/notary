pragma solidity >=0.8.4;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

import "hardhat/console.sol";

contract BugReportNotary is Initializable, AccessControl {

  using SafeERC20 for IERC20;

  address public constant nativeAsset = address(0x0); // mock address that represents the native asset of the chain
  bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
  uint256 private constant leafSeperator = 0;
  uint256 private constant attestationSeperator = 1;
  string private constant reporterKey = "reporter";
  string private constant reportKey = "report";
  uint64 private constant attestationValidityDelay = 17280;

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
    uint64 blockNo = uint64(block.number);
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
    uint64 blockNo = uint64(block.number);
    attestations[_getAttestationID(reportRoot, msg.sender, key)] = Attestation(
      TimestampPadded(0, 0, blockNo),
      commitment);
    emit ReportAttestation(msg.sender, reportRoot, key, blockNo);
  }

  function validateAttestation(bytes32 reportRoot, address triager, bytes32 salt, bytes calldata value, bytes32[] calldata merkleProof) external view {
    Attestation memory attestation = attestations[_getAttestationID(reportRoot, triager, reportKey)];
    uint64 disclosureBlockHeight = disclosures[_getDisclosureID(reportRoot, reportKey)].blockHeight;
    require(attestation.timestamp.blockHeight + attestationValidityDelay <= disclosureBlockHeight);

    bytes32 attestationHash = keccak256(bytes.concat(abi.encode(attestationSeperator, triager, reportKey, salt), value));
    require(attestation.commitment == attestationHash);

    bytes32 leafHash = keccak256(bytes.concat(abi.encode(leafSeparator, reportKey, salt), value));
    _checkProof(reportRoot, leafHash, merkleProof);
  }

  function updateReport(bytes32 reportRoot, uint8 newStatusBitField) external onlyRole(OPERATOR_ROLE) {
    require(attestations[_getAttestationID(reportRoot, msg.sender, reportKey)].commitment != 0);
    require(newStatusBitField != 0);
    reportStatuses[_getReportStatusID(reportRoot, msg.sender)] = TimestampPadded(newStatusBitField, 0, uint64(block.number));
    emit ReportUpdated(msg.sender, reportRoot, newStatusBitField);
  }

  function reportHasStatus(bytes32 reportRoot, address triager, uint8 statusType) external view returns (bool) {
    return reportStatuses[_getReportStatusID(reportRoot, triager)].flags >> statusType & 1 == 1;
  }

  function disclose(bytes32 reportRoot, string calldata key, byte32 salt, bytes calldata value, bytes32[] calldata merkleProof)
   external onlyRole(OPERATOR_ROLE) {
    TimestampPadded storage timestamp = disclosures[_getDisclosureID(reportRoot, key)];
    require(timestamp.blockHeight == 0);
    bytes32 leafHash = keccak256(bytes.concat(abi.encode(leafseparator, key, salt), value));
    _checkProof(reportRoot, leafHash, merkleProof);
    uint64 blockNo = uint64(block.number);
    timestamp.blockHeight = blockNo;
    emit ReportDisclosure(reportRoot, key, data);
  }

  // on-chain disclosure
  function _checkProof(bytes32 reportRoot, bytes32 leafHash, bytes32[] memory merkleProof) internal view {
    require(reports[reportRoot].blockHeight != 0, "Bug Report Notary: Merkle root not submitted.");
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
    if (paymentToken == nativeAsset) {
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
    bytes32 leafHash = keccak256(bytes.concat(abi.encode(leafSeparator, reporterKey, salt), abi.encode(reporter)));
    _checkProof(reportRoot, leafHash, merkleProof);
    _modifyBalance(balanceID, currBalance - amount);
    emit Withdrawal(reportRoot, reporter, paymentToken, amount);
    if (paymentToken == nativeAsset) {
      (bool sent, ) = payable(reporter).call{value: amount}("");
      require(sent, "Bug Report Notary: Failed to send native asset");
    } else {
      IERC20(paymentToken).safeTransfer(reporter, amount);
    }
  }
}
