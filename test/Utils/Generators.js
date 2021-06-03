"use strict";

const { upgrades, ethers } = require("hardhat");
const abiCoder = ethers.utils.defaultAbiCoder; //An AbiCoder created when the library is imported which is used by the Interface.
const keccak256 = require('keccak256');

const { ReportKeys, generateRandomSalt } = require('./Helpers');
const { generateLeafData,
    generateLeaf,
    generateReportRoot,
    generateReporterLeaf,
    generateReportNumberLeaf,
    generateProjectLeaf,
    generateReportLeaf,
    getLeafGenerator,
    generateReportMerkleTree,
    merkleProof,
    generateCommitment } = require("./Merkle");

// [!] SMART CONTRACT FUNCTION GENERATORS to use them in mocha test cases:
// useful to generate arguments for functions.

function makeSubmitArgs(report) {
    const reportRoot = generateReportRoot(report);
    return reportRoot;
}

function makeAttestArgs(report, triagerAddr) {
    const reportRoot = generateReportRoot(report);
    const key = ReportKeys.report;
    const commitment = generateCommitment(report, triagerAddr);

    return [reportRoot, key, commitment];
}

function makeDiscloseArgs(report, key) {
    const reportRoot = generateReportRoot(report);
    const salt = report.salts;

    const value = abiCoder.encode(["bytes"], [report.project]);


    const merkleProofval = merkleProof(report, key);

    return [reportRoot, salt, value, merkleProofval];
}

function makeWithdrawArgs(report, key) {
    const reportRoot = generateReportRoot(report);
    const reportAddress = report.paymentWalletAddress;
    const salt = report.salts;

    const merkleProofval = merkleProof(report, key);

    return [reportRoot, reportAddress, salt, merkleProofval];
}

module.exports = {
    makeSubmitArgs,
    makeAttestArgs,
    makeDiscloseArgs,
    makeWithdrawArgs
};
