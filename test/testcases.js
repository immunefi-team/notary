// WIP: WORK IN PROGRESS
const keccak256 = require('keccak256');
const { expect } = require("chai");
const { upgrades,ethers } = require("hardhat");
const { MerkleTree } = require('merkletreejs');
const abiCoder = ethers.utils.defaultAbiCoder; //An AbiCoder created when the library is imported which is used by the Interface.

// [!] CONSTANTS

const ReportKeys = {
    report: "report",
    reporter: "reporter",
    reportNumber: "immunefi report number",
    project: "project",
}

const operator_keccak = keccak256("OPERATOR_ROLE");
const NativeAsset = '0x0000000000000000000000000000000000000000' //  ETH on mainet, XDAI on paonetwork

// [!] Merkle Helpers

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
    const salt = report.salts;
    const value = abiCoder.encode(["address"], [report.paymentWalletAddress]);

    return generateLeaf(key, salt, value);
}

function generateReportNumberLeaf(report) {
    const key = ReportKeys.reportNumber;
    const salt = report.salts;
    const value = abiCoder.encode(["uint256"], [report.id]);

    return generateLeaf(key, salt, value);
}

function generateProjectLeaf(report) {
    const key = ReportKeys.project;
    const salt = report.salts;
    const value = abiCoder.encode(["bytes"], [report.project]);

    return generateLeaf(key, salt, value);
}

function generateReportLeaf(report) {
    const key = ReportKeys.report;
    const salt = report.salts;
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

// [!] Helpers

function generateRandomSalt() {
    const buf = ethers.utils.randomBytes(32);
    salt = ethers.utils.hexlify(buf);
    return salt;
}


function generateCommitment(report, triagerAddr) {
    const key = ReportKeys.report;
    const salt = report.salts;

    const value = abiCoder.encode(["bytes"], [report.project]);

    const attestationData = ethers.utils.hexConcat([
        abiCoder.encode(["uint256", "address", "string", "bytes32"], [1, triagerAddr, key, salt]),
        value,
    ]);

    return keccak256(attestationData);
}



// [!] SMART CONTRACT FUNCTION GENERATORS

async function F_submit(report) {
    const reportRoot = generateReportRoot(report);
    return reportRoot;
}

function F_attest(report, triagerAddr) {
    const reportRoot = generateReportRoot(report);
    const key = ReportKeys.report;
    const commitment = generateCommitment(report, triagerAddr);

    return [reportRoot, key, commitment];
}

function F_disclose(report, key) {
    const reportRoot = generateReportRoot(report);
    const salt = report.salts;

    const value = abiCoder.encode(["bytes"], [report.project]);


    const merkleProofval = merkleProof(report, key);

    return [reportRoot, salt, value, merkleProofval];
}

function F_getAttestionID(report, triageraddress, key) {
    const reportRoot = generateReportRoot(report);
    return keccak256(abiCoder.encode(["bytes32", "address", "string"], [reportRoot, triageraddress, key]));
}


function F_withdraw(report,key){
    const reportRoot = generateReportRoot(report);
    const reportAddress = report.paymentWalletAddress;
    const salt = report.salts;

    const merkleProofval = merkleProof(report,key);

    return [reportRoot,reportAddress,salt,merkleProofval];
}

// [!] TESTING SETUP

describe("Notary Test Workflows", function () {
    let Notary, instance;

    let Deployer,
        Triager,
        Reporter,
        Client;

    let salt,report,triagerAddress
    
    beforeEach(async () => {
        [Deployer, Reporter, Triager, Client] = await ethers.getSigners();

        Notary = await ethers.getContractFactory("BugReportNotary");
        instance = await upgrades.deployProxy(Notary, [Deployer.address], { unsafeAllow: ['delegatecall'] });
        
        salt = generateRandomSalt();
        report = { "id": 1, "salts": salt, "paymentWalletAddress": Deployer.address, "project": "0xbf971d4360414c84ea06783d0ea51e69035ee526" }
        triagerAddress = Deployer.address;
        
        //console.log("[-] Deployed to :", instance.address, "\n====================\n");
    });

    describe("=> Testing OpenZ initialize()",function(){
        it("Should only be able to called ONCE when deploying/upgrading",async function(){
            await expect(instance.connect(Deployer).initialize(Deployer.address))
            .to.be.reverted; // since contract is already deployed and already intialized 
        })

        // it("Should only be callable by the proxy owner",async function(){
        //     await expect(instance.connect(Deployer).initialize(Deployer.addresss))
        // })
    });

    describe("=> Testing submit()",function(){
        let getReportRoot;

        beforeEach(async () => {
            getReportRoot = F_submit(report);
        });

        it("Only Callable by the operator role only", async function () {
            await expect(instance.connect(Deployer).submit(getReportRoot));
        })

        it("If caller doesnt have operator role, Access Control check fail",async function(){
            await expect(instance.connect(Reporter).submit(getReportRoot)).to.be.reverted;
        })

        it("Only Accepts a report root of merkle tree constructed from the report",async function(){
            await expect(instance.connect(Deployer).submit(getReportRoot))
            //.to.emit(instance, "ReportSubmitted").
            //withArgs(getReportRoot,ethers.block.timestamp); // NEED HELP HERE WITH CURRENT BLOCK TIMESTAMP
        })
    });

    describe("=> Testing Attest()",function(){
        let getReportRoot,
            key,
            commitment;

        beforeEach(async () => {
            await instance.connect(Deployer).submit(F_submit(report)); //reportRoot
            [getReportRoot,key,commitment] = F_attest(report,triagerAddress); 
        });

        it("Attest the report",async function(){
            await expect(instance.connect(Deployer).attest(getReportRoot,key,commitment))
            // .to.emit(instance,"ReportAttestation")
            // .withArgs(triagerAddress,getReportRoot,key,ethers.block.timestamp);
        })

        it("Attest the report: only OPERATOR", async function () {
            await expect(instance.connect(Reporter).attest(getReportRoot, key, commitment))
            .to.be.reverted;
        })
    })

    describe("=> Testing getBalance()",function(){
        let getReportRoot;

        beforeEach(async () => {
            getReportRoot = F_submit(report);
            await instance.connect(Deployer).submit(getReportRoot);
        });

        it("should return the amount of tokens deposited to a given report",async function(){
            Before_Balance = await instance.connect(Deployer).getBalance(getReportRoot,NativeAsset);
            console.log(ethers.utils.formatEther(Before_Balance));

            // Paying in Native Asset , 9 wei , tiniest bounty ever paid in the history
            // https://github.com/immunefi-team/notary/blob/main/contracts/BugReportNotary.sol#L156
            await instance.connect(Client).payReporter(getReportRoot, NativeAsset, 9, { value: 9 })

            After_Balance = await instance.connect(Deployer).getBalance(getReportRoot, NativeAsset);
            console.log(ethers.utils.formatEther(After_Balance));

            await expect(ethers.utils.formatEther(After_Balance)).to.equal('0.000000000000000009')

        })
    })

    describe("=> Testing PayReporter()",function(){
        let getReportRoot;

        beforeEach(async () => {
            getReportRoot = F_submit(report);
            await instance.connect(Deployer).submit(getReportRoot);
        });

        it("should allow anyone to deposit a bounty payment in any er20 token or the native asset to a given report",async function(){
            // Paying in Native
            await expect(instance.connect(Client).payReporter(getReportRoot, NativeAsset, 9, { value: 9 }));
            // Paying in ERC20 : I think, in order to send ERC20 , our msg.sender first need to have that tokens in account.
            //await expect(instance.connect(Client).payReporter(getReportRoot, '0x761d38e5ddf6ccf6cf7c55759d5210750b5d60f3', 9));

            After_Balance = await instance.connect(Deployer).getBalance(getReportRoot, '0x761d38e5ddf6ccf6cf7c55759d5210750b5d60f3');
            console.log(ethers.utils.formatEther(After_Balance));

        })
    })


    describe("=> Testing Withdraw()",function(){
        let reportRoot,
            reportAddress,
            salt,
            merkleProofval

        beforeEach(async () => {
            [reportRoot, reportAddress, salt, merkleProofval] = F_withdraw(report, ReportKeys.reporter);
            await instance.connect(Deployer).submit(reportRoot);
            await instance.connect(Client).payReporter(reportRoot, NativeAsset, 100, { value: 100 })
        });

        it("should allow multiple withdrawals",async function(){
            await expect(instance.connect(Deployer).withdraw(reportRoot, NativeAsset,5,salt,reportAddress,merkleProofval))
            //Balance = await instance.connect(Reporter).getBalance(reportRoot, NativeAsset);
            await expect(instance.connect(Deployer).withdraw(reportRoot, NativeAsset, 5, salt, reportAddress, merkleProofval))
        })

        it("no underflow/overflow should exist",async function(){
            // TODO
        })
    })


    describe("=> upgradeToAndCall()",function(){
        it("Upgrading the current proxy",async function(){
            // current proxy address, Update Smart Contract Reference, New Deployer address
            await upgrades.upgradeProxy(instance.address, Notary, { args: Deployer.address, unsafeAllow: ['delegatecall'] })
            
        })

        it("Only ProxyOwner should able to upgrade the contract",async function(){
            // How to try upgrading with other User??, upgrades.upgradeProxy uses deployer.address i guess.
            
            //await upgrades.upgradeProxy(instance.address, Notary, { args: Client.address, unsafeAllow: ['delegatecall'] })
        })
    })



});
