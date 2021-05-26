// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

import "@openzeppelin/contracts/access/AccessControl.sol";

interface INotary is IAccessControl {

    // public constants
    function OPERATOR_ROLE() external pure returns (bytes32);
    function KEY_REPORT() external pure returns (string memory);
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
    function getReport(bytes32 reportRoot) external view returns (TimestampPadded memory);
    function getReportStatus(bytes32 reportRoot, address triager) external view returns (TimestampPadded memory);
    function getDisclosure(bytes32 reportRoot, string memory key) external view returns (TimestampPadded memory);
    function getAttestation(bytes32 reportRoot, address triager, string memory key) external view returns (Attestation memory);

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