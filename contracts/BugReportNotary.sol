// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/utils/math/SafeCast.sol";
import "./interfaces/INotary.sol";

contract BugReportNotary is Initializable, AccessControl, INotary {

  using SafeCast for uint256;

  bytes32 public constant override OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
  uint256 private constant SEPARATOR_LEAF = 0;
  uint256 private constant SEPARATOR_ATTESTATION = 1;
  string public constant override KEY_REPORT = "report";
  uint64 public constant override ATTESTATION_DELAY = 1 days;

  mapping (bytes32 => TimestampPadded) private reports;
  mapping (bytes32 => TimestampPadded) private reportStatuses;
  mapping (bytes32 => TimestampPadded) private disclosures;
  mapping (bytes32 => Attestation) private attestations;

  // MAPPING GETTERS
  function getReport(bytes32 reportRoot) public view override returns (TimestampPadded memory) {
    return reports[reportRoot];
  }

  function getReportStatus(bytes32 reportRoot, address triager) public view override returns (TimestampPadded memory) {
    return reportStatuses[_getReportStatusID(reportRoot, triager)];
  }

  function getDisclosure(bytes32 reportRoot, string memory key) public view override returns (TimestampPadded memory) {
    return disclosures[_getDisclosureID(reportRoot, key)];
  }

  function getAttestation(bytes32 reportRoot, address triager, string memory key) public view override returns (Attestation memory) {
    return attestations[_getAttestationID(reportRoot, triager, key)];
  }

  function _getReportStatusID(bytes32 reportRoot, address triager) internal pure returns (bytes32) {
    return keccak256(abi.encode(reportRoot, triager));
  }

  function _getDisclosureID(bytes32 reportRoot, string memory key) internal pure returns (bytes32) {
    return keccak256(abi.encode(reportRoot, key));
  }

  function _getAttestationID(bytes32 reportRoot, address triager, string memory key) internal pure returns (bytes32) {
    return keccak256(abi.encode(reportRoot, triager, key));
  }

  //ACCESS CONTROL
  function initialize(address initAdmin) external initializer {
    _setupRole(DEFAULT_ADMIN_ROLE, initAdmin);
    _setupRole(OPERATOR_ROLE, initAdmin);
  }

  // NOTARY FUNCTIONS
  function submit(bytes32 reportRoot) override external onlyRole(OPERATOR_ROLE) {
    require(reportRoot != 0, "Bug Report Notary: cannot submit 0 report root");
    TimestampPadded storage timestamp_padded = reports[reportRoot];
    require(timestamp_padded.timestamp == 0, "Bug Report Notary: Report already submitted");
    uint64 timestamp = block.timestamp.toUint64();
    timestamp_padded.timestamp = timestamp;
    emit ReportSubmitted(reportRoot, timestamp);
  }

  function attest(bytes32 reportRoot, string calldata key, bytes32 commitment) override external onlyRole(OPERATOR_ROLE) {
    require(commitment != 0x0, "Bug Report Notary: Invalid commitment");
    require(reports[reportRoot].timestamp != 0, "Bug Report Notary: Report not yet submitted");
    require(getDisclosure(reportRoot, key).timestamp == 0, "Bug Report Notary: Report key already disclosed");
    Attestation storage attestation = attestations[_getAttestationID(reportRoot, msg.sender, key)];
    require(attestation.timestamp.timestamp == 0 && attestation.commitment == 0x0, "Bug Report Notary: Attestation already submitted");
    uint64 timestamp = block.timestamp.toUint64();
    attestation.commitment = commitment;
    attestation.timestamp = TimestampPadded(0, 0, timestamp);
    emit ReportAttestation(msg.sender, reportRoot, key, timestamp);
  }

  function _validateTimestamp(bytes32 reportRoot, uint64 eventTimestamp) internal view {
    require(eventTimestamp + ATTESTATION_DELAY <= getDisclosure(reportRoot, KEY_REPORT).timestamp, "Bug Report Notary: Invalid timestamp");
  }

  function validateAttestation(bytes32 reportRoot, address triager, bytes32 salt, bytes calldata value, bytes32[] calldata merkleProof) override public view {
    Attestation memory attestation = getAttestation(reportRoot, triager, KEY_REPORT);
    _validateTimestamp(reportRoot, attestation.timestamp.timestamp);
    bytes32 attestationHash = keccak256(bytes.concat(abi.encode(SEPARATOR_ATTESTATION, triager, KEY_REPORT, salt), value));
    require(attestation.commitment == attestationHash, "Bug Report Notary: Commitment does not match valid attestation");
    _checkProof(reportRoot, KEY_REPORT, salt, value, merkleProof);
  }

  function updateReport(bytes32 reportRoot, uint8 newStatusBitField) override external onlyRole(OPERATOR_ROLE) {
    require(getAttestation(reportRoot, msg.sender, KEY_REPORT).commitment != 0, "Bug Report Notary: Report is unattested");
    require(newStatusBitField != 0, "Bug Report Notary: Invalid status update");
    require(getDisclosure(reportRoot, KEY_REPORT).timestamp == 0, "Bug Report Notary: Report key already disclosed");
    uint64 timestamp = block.timestamp.toUint64();
    reportStatuses[_getReportStatusID(reportRoot, msg.sender)] = TimestampPadded(newStatusBitField, 0, timestamp);
    emit ReportUpdated(msg.sender, reportRoot, newStatusBitField, timestamp);
  }

  function _getFlag(uint256 flags, uint8 which) internal pure returns (bool) {
    return flags >> which & 1 == 1;
  }

  function reportHasStatus(bytes32 reportRoot, address triager, uint8 statusType) override public view returns (bool) {
    return _getFlag(getReportStatus(reportRoot, triager).flags, statusType);
  }

  function validateReportStatus(bytes32 reportRoot, address triager, uint8 statusType, bytes32 salt, bytes calldata value, bytes32[] calldata merkleProof) override public view returns (bool) {
    validateAttestation(reportRoot, triager, salt, value, merkleProof);
    TimestampPadded memory reportStatus = getReportStatus(reportRoot, triager);
    _validateTimestamp(reportRoot, reportStatus.timestamp);
    return _getFlag(reportStatus.flags, statusType);
  }

  function disclose(bytes32 reportRoot, string calldata key, bytes32 salt, bytes calldata value, bytes32[] calldata merkleProof) override external {
    _checkProof(reportRoot, key, salt, value, merkleProof);
    TimestampPadded storage timestamp = disclosures[_getDisclosureID(reportRoot, key)];
    if (timestamp.timestamp == 0) {
      timestamp.timestamp = block.timestamp.toUint64();
      emit ReportDisclosure(reportRoot, key, value);
    }
  }

  function _checkProof(bytes32 reportRoot, string memory key, bytes32 salt, bytes memory value, bytes32[] calldata merkleProof) internal view {
    require(reports[reportRoot].timestamp != 0, "Bug Report Notary: Merkle root not submitted.");
    bytes32 leafHash = keccak256(bytes.concat(abi.encode(SEPARATOR_LEAF, key, salt), value));
    require(MerkleProof.verify(merkleProof, reportRoot, leafHash), "Bug Report Notary: Merkle proof failed.");
  }
}
