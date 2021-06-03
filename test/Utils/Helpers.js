"use strict";

const { ethers } = require("hardhat");

function generateRandomSalt() {
    const buf = ethers.utils.randomBytes(32);
    const salt = ethers.utils.hexlify(buf);
    return salt;
}

const ReportKeys = {
    report: "report",
    reporter: "reporter",
    reportNumber: "immunefi report number",
    project: "project",
}

module.exports = {
    ReportKeys,
    generateRandomSalt
}
