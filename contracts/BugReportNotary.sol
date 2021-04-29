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
  uint256 private constant leafSeperator = 0;
  uint256 private constant internalNodeSeperator = 1;
  uint256 private constant attestationSeperator = 2;
  string private constant reporterKey = "reporter";
  string private constant descriptionKey = "description";

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
    require(commitment != 0);
    uint64 blockNo = uint64(block.number);
    attestations[_getAttestationID(reportRoot, msg.sender, key)] = Attestation(
      TimestampPadded(0, 0, blockNo),
      commitment);
    emit ReportAttestation(msg.sender, reportRoot, key, blockNo);
  }

  function checkDescriptionAttestation(bytes32 reportRoot, bytes32 salt, bytes calldata value, address triager, bytes32[] calldata merkleProof) external view returns(bool) {
    bytes32 leaf = keccak256(abi.encode(leafSeperator, descriptionKey, salt, value));
    _checkProof(reportRoot, leaf, merkleProof);

    bytes32 validCommitment = keccak256(abi.encode(
      attestationSeperator,
      descriptionKey,
      salt,
      value,
      triager));
    Attestation memory attestation = attestations[_getAttestationID(reportRoot, triager, descriptionKey)];
    TimestampPadded memory disclosure = disclosures[_getDisclosureID(reportRoot, descriptionKey)];
    return  attestation.commitment == validCommitment
      && attestation.timestamp.blockHeight + 17280 <= disclosure.blockHeight; // ~24 hours with 5 second blocktimes
  }

  function updateReport(bytes32 reportRoot, uint8 newStatusBitField) external onlyRole(OPERATOR_ROLE) {
    require(attestations[_getAttestationID(reportRoot, msg.sender, descriptionKey)].commitment != 0);
    _updateReport(reportRoot, newStatusBitField);
  }

  function _updateReport(bytes32 reportRoot, uint8 newStatusBitField) internal {
    require(newStatusBitField != 0);
    reportStatuses[_getReportStatusID(reportRoot, msg.sender)].flags = newStatusBitField;
    emit ReportUpdated(msg.sender, reportRoot, newStatusBitField);
  }

  function reportHasStatus(bytes32 reportRoot, address triager, uint8 statusType) external view returns (bool) {
    return reportStatuses[_getReportStatusID(reportRoot, triager)].flags >> statusType & 1 == 1;
  }

  function discloseDescription(bytes32 reportRoot, bytes32 salt, bytes calldata value, bytes32[] calldata merkleProof) external onlyRole(OPERATOR_ROLE) {
    bytes memory data = abi.encode(leafSeperator, descriptionKey, salt, value);
    bytes32 leaf = keccak256(data);
    _disclose(reportRoot, descriptionKey, leaf, merkleProof);
    emit ReportDisclosure(reportRoot, descriptionKey, data);
  }

  function _disclose(bytes32 reportRoot, string memory key, bytes32 leaf, bytes32[] memory merkleProof) internal {
    TimestampPadded storage timestamp = disclosures[_getDisclosureID(reportRoot, key)];
    require(timestamp.blockHeight == 0);
    _checkProof(reportRoot, leaf, merkleProof);
    uint64 blockNo = uint64(block.number);
    timestamp.blockHeight = blockNo;
  }

  // on-chain disclosure
  function _checkProof(bytes32 reportRoot, bytes32 leaf, bytes32[] memory merkleProof) internal view {
    require(reports[reportRoot].blockHeight != 0);
    bytes32 currHash = leaf;
    for (uint256 i = 0; i < merkleProof.length; i++) {
      bytes32 proofSegment = merkleProof[i];

      if (currHash <= proofSegment) {
        currHash = keccak256(abi.encode(internalNodeSeperator, currHash, proofSegment));
      } else {
        currHash = keccak256(abi.encode(internalNodeSeperator, proofSegment, currHash));
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

  function withdraw(bytes32 reportRoot, address paymentToken, uint256 amount, bytes32 salt, bytes32[] calldata merkleProof) external {
    bytes32 balanceID = _getBalanceID(reportRoot, paymentToken);
    uint256 currBalance = balances[balanceID];
    _modifyBalance(balanceID, currBalance - amount);
    bytes32 leaf = keccak256(abi.encode(leafSeperator, reporterKey, salt, msg.sender));
    _checkProof(reportRoot, leaf, merkleProof);
    emit Withdrawal(reportRoot, msg.sender, paymentToken, amount);
    if (paymentToken == nativeAsset) {
      (bool sent, ) = payable(msg.sender).call{value: amount}("");
      require(sent, "Bug Report Notary: Failed to send native asset");
    } else {
      IERC20(paymentToken).safeTransfer(msg.sender, amount);
    }
  }
}