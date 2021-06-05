"use strict";

const { ethers } = require("hardhat");

const ReportKeys = {
    report: "report",
    reporter: "reporter",
    reportNumber: "immunefi report number",
    project: "project",
}

function generateRandomSalt() {
    const buf = ethers.utils.randomBytes(32);
    const salt = ethers.utils.hexlify(buf);
    return salt;
}

function generateSaltForKeys(){
    var rKeys = Object.values(ReportKeys);
    return rKeys.map((key) => ({ key, salt: generateRandomSalt(),}))
}

module.exports = {
    ReportKeys,
    generateRandomSalt,
    generateSaltForKeys
}
