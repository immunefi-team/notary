// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

import "@openzeppelin/contracts/access/AccessControl.sol";

interface INotary is IAccessControl {

    // public constants
    function OPERATOR_ROLE() external pure returns (bytes32);
    function KEY_REPORT() external pure returns (string);
    function ATTESTATION_DELAY() external pure returns (uint64);

    struct TimestampPadded {
	uint8 flags;
	uint184 _reserved;
	uint64 timestamp;
    }

    struct Attestation {
	TimestampPadded timestamp;
	bytes32 commitment;
    }

    // public mappings
    function reports(bytes32 reportRoot) external view returns (TimestampPadded); // report root => block.timestamp
    function reportStatuses(bytes32) external view returns (TimestampPadded); // keccak256(report root, triager address) => report's statuses (bit field) as reported by triager
    function disclosures(bytes32) external view returns (TimestampPadded); // keccak256(report root, key) => block.timestamp
    function attestations(bytes32) external view returns (Attestation); // keccak256(report root, triager address, key) => Attestation

    event ReportSubmitted(bytes32 indexed reportRoot, uint64 timestamp);
    event ReportAttestation(address indexed triager, bytes32 indexed reportRoot, string indexed key, uint64 timestamp);
    event ReportUpdated(address indexed triager, bytes32 indexed reportRoot, uint8 newStatusBitField, uint64 timestamp);
    event ReportDisclosure(bytes32 indexed reportRoot, string indexed key, bytes value);

    // public functions
    function submit(bytes32 reportRoot) external;
    function attest(bytes32 reportRoot, string calldata key, bytes32 commitment) external;
    function updateReport(bytes32 reportRoot, uint8 newStatusBitField) external;
    function disclose(bytes32 reportRoot, string calldata key, bytes32 salt, bytes calldata value, bytes32[] calldata merkleProof) external;

    // public pure functions
    function reportHasStatus(bytes32 reportRoot, address triager, uint8 statusType) external view returns (bool);
    function validateReportStatus(bytes32 reportRoot, address triager, uint8 statusType, bytes32 salt, bytes calldata value, bytes32[] calldata merkleProof) external view returns (bool);
    function validateAttestation(bytes32 reportRoot, address triager, bytes32 salt, bytes calldata value, bytes32[] calldata merkleProof) external view;
}
