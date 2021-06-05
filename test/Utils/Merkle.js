"use strict";

const { ethers } = require("hardhat");
const { MerkleTree } = require('merkletreejs');
const abiCoder = ethers.utils.defaultAbiCoder; //An AbiCoder created when the library is imported which is used by the Interface.
const keccak256 = require('keccak256');
const { ReportKeys } =  require('./Helpers');

function generateLeafData(key, salt, value) {
    return ethers.utils.hexConcat([abiCoder.encode(["uint256", "string", "bytes32"], [0, key, salt]), value]);
}

function generateLeaf(key, salt, value) {
    return keccak256(generateLeafData(key, salt, value));
}

function generateReportRoot(report) {
    const tree = generateReportMerkleTree(report);
    //console.log(tree.getHexLeaves())
    return tree.getHexRoot();
}

function generateReporterLeaf(report) {
    const key = ReportKeys.reporter;
    const salt = report.salts.find((salt) => salt.key === key)?.salt;
    const value = abiCoder.encode(["address"], [report.paymentWalletAddress]);

    return generateLeaf(key, salt, value);
}

function generateReportNumberLeaf(report) {
    const key = ReportKeys.reportNumber;
    const salt = report.salts.find((salt) => salt.key === key)?.salt;
    const value = abiCoder.encode(["uint256"], [report.id]);

    return generateLeaf(key, salt, value);
}

function generateProjectLeaf(report) {
    const key = ReportKeys.project;
    const salt = report.salts.find((salt) => salt.key === key)?.salt;
    const value = abiCoder.encode(["bytes"], [report.project]);

    return generateLeaf(key, salt, value);
}

function generateReportLeaf(report) {
    const key = ReportKeys.report;
    const salt = report.salts.find((salt) => salt.key === key)?.salt;
    const value = abiCoder.encode(["bytes"], [report.project]);

    return generateLeaf(key, salt, value);
}

function getLeafGenerator(key) {
    switch (key) {
        case ReportKeys.project:
            return generateProjectLeaf;
        case ReportKeys.report:
            return generateReportLeaf;
        case ReportKeys.reportNumber:
            return generateReportNumberLeaf;
        case ReportKeys.reporter:
            return generateReporterLeaf;
        default:
            console.log("Unexpected-Key in LeafGenerator");
    }
}

function generateReportMerkleTree(report) {
    const reportNumberLeaf = generateReportNumberLeaf(report);

    const reporterLeaf = generateReporterLeaf(report);
    const projectNameLeaf = generateProjectLeaf(report);
    const reportLeaf = generateReportLeaf(report);

    return new MerkleTree([reportNumberLeaf, reporterLeaf, projectNameLeaf, reportLeaf], keccak256, { sort: true });
}


function merkleProof(report, key) {
    const leafGenerator = getLeafGenerator(key);
    const leaf = leafGenerator(report);
    const tree = generateReportMerkleTree(report);
    return tree.getHexProof(leaf);
}


function generateCommitment(report, triagerAddr) {
    const key = ReportKeys.report;
    const salt = report.salts.find((salt) => salt.key === key)?.salt;

    const value = abiCoder.encode(["bytes"], [report.project]);

    const attestationData = ethers.utils.hexConcat([
        abiCoder.encode(["uint256", "address", "string", "bytes32"], [1, triagerAddr, key, salt]),
        value,
    ]);

    return keccak256(attestationData);
}


module.exports = {
    generateLeafData,
    generateLeaf,
    generateReportRoot,
    generateReporterLeaf,
    generateReportNumberLeaf,
    generateProjectLeaf,
    generateReportLeaf,
    getLeafGenerator,
    generateReportMerkleTree,
    merkleProof,
    generateCommitment
};