// WIP: WORK IN PROGRESS
const keccak256 = require('keccak256');
const { expect } = require("chai");
const { upgrades, ethers } = require("hardhat");
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


function F_withdraw(report, key) {
    const reportRoot = generateReportRoot(report);
    const reportAddress = report.paymentWalletAddress;
    const salt = report.salts;

    const merkleProofval = merkleProof(report, key);

    return [reportRoot, reportAddress, salt, merkleProofval];
}

// [!] TESTING SETUP

describe("Notary Test Workflows", function () {
    let Notary, instance;

    let Deployer,
        Triager,
        Reporter,
        Client;

    let salt, report, triagerAddress

    beforeEach(async () => {
        [Deployer, Reporter, Triager, Client] = await ethers.getSigners();

        Notary = await ethers.getContractFactory("BugReportNotary");
        instance = await upgrades.deployProxy(Notary, [Deployer.address], { unsafeAllow: ['delegatecall'] });

        salt = generateRandomSalt();
        report = { "id": 1, "salts": salt, "paymentWalletAddress": Deployer.address, "project": "0xbf971d4360414c84ea06783d0ea51e69035ee526" }
        triagerAddress = Deployer.address;

        //console.log("[-] Deployed to :", instance.address, "\n====================\n");
    });

    describe("=> Testing OpenZ initialize()", function () {
        it("Should only be able to called ONCE when deploying/upgrading", async function () {
            await expect(instance.connect(Deployer).initialize(Deployer.address))
                .to.be.reverted; // since contract is already deployed and already intialized 
        })

        // it("Should only be callable by the proxy owner",async function(){
        //     await expect(instance.connect(Deployer).initialize(Deployer.addresss))
        // })
    });

    describe("=> Testing submit()", function () {
        let getReportRoot;

        beforeEach(async () => {
            getReportRoot = F_submit(report);
        });

        it("Only Callable by the operator role only", async function () {
            await expect(instance.connect(Deployer).submit(getReportRoot));
        })

        it("If caller doesnt have operator role, Access Control check fail", async function () {
            await expect(instance.connect(Reporter).submit(getReportRoot)).to.be.reverted;
        })

        it("Only Accepts a report root of merkle tree constructed from the report", async function () {
            await expect(instance.connect(Deployer).submit(getReportRoot))
            //.to.emit(instance, "ReportSubmitted").
            //withArgs(getReportRoot,ethers.block.timestamp); // NEED HELP HERE WITH CURRENT BLOCK TIMESTAMP
        })

        it("Revert on submitting same root mulitple times",async function(){
            await expect(instance.connect(Deployer).submit(getReportRoot))
            await expect(instance.connect(Deployer).submit(getReportRoot)).to.be.reverted; // .timestamp already exists in `reports` mapping.
        })

    });

    describe("=> Testing Attest()", function () {
        let getReportRoot,
            key,
            commitment;

        beforeEach(async () => {
            await instance.connect(Deployer).submit(F_submit(report)); //reportRoot
            [getReportRoot, key, commitment] = F_attest(report, triagerAddress);
        });

        it("Attest the report", async function () {
            await expect(instance.connect(Deployer).attest(getReportRoot, key, commitment))
            // .to.emit(instance,"ReportAttestation")
            // .withArgs(triagerAddress,getReportRoot,key,ethers.block.timestamp);
        })

        it("Attest the report: only OPERATOR", async function () {
            await expect(instance.connect(Reporter).attest(getReportRoot, key, commitment))
                .to.be.reverted;
        })

        it("Attest Twice should revert",async function(){
            await expect(instance.connect(Deployer).attest(getReportRoot, key, commitment))
            await expect(instance.connect(Deployer).attest(getReportRoot, key, commitment)).to.be.reverted;
        })

        //  Error: incorrect data length
        it("Attest Commitment is Empty then revert",async function(){
            //await instance.connect(Deployer).attest(getReportRoot, key, 0x0000000000000000000000000000000000000000000000000000000000000000 );
        //     await instance.connect(Deployer).attest(getReportRoot, key,keccak256(0x0));
        //     await instance.connect(Deployer).attest(getReportRoot, key, ethers.constants.AddressZero)
        })

    })

    describe("=> Testing getBalance()", function () {
        let getReportRoot;

        beforeEach(async () => {
            getReportRoot = F_submit(report);
            await instance.connect(Deployer).submit(getReportRoot);
        });

        it("should return the amount of tokens deposited to a given report", async function () {
            Before_Balance = await instance.connect(Deployer).getBalance(getReportRoot, NativeAsset);
            console.log(ethers.utils.formatEther(Before_Balance));

            // Paying in Native Asset , 9 wei , tiniest bounty ever paid in the history
            // https://github.com/immunefi-team/notary/blob/main/contracts/BugReportNotary.sol#L156
            await instance.connect(Client).payReporter(getReportRoot, NativeAsset, 9, { value: 9 })

            After_Balance = await instance.connect(Deployer).getBalance(getReportRoot, NativeAsset);
            console.log(ethers.utils.formatEther(After_Balance));

            await expect(ethers.utils.formatEther(After_Balance)).to.equal('0.000000000000000009')

        })
    })

    describe("=> Testing PayReporter()", function () {
        let getReportRoot;

        beforeEach(async () => {
            getReportRoot = F_submit(report);
            await instance.connect(Deployer).submit(getReportRoot);
        });

        it("should allow anyone to deposit a bounty payment in any er20 token or the native asset to a given report", async function () {
            // Paying in Native
            await expect(instance.connect(Client).payReporter(getReportRoot, NativeAsset, 9, { value: 9 }));
            

            // Paying in ERC20 : I think, in order to send ERC20 , our msg.sender first need to have that tokens in account.
            //await expect(instance.connect(Client).payReporter(getReportRoot, '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', 9));

            After_Balance = await instance.connect(Deployer).getBalance(getReportRoot, '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2');
            console.log(ethers.utils.formatEther(After_Balance));
            // wrapped ether erc20, .deposit function ,  //  0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2
        })

        it("Paying amount ZERO should revert by the require statement",async function(){
            await expect(instance.connect(Client).payReporter(getReportRoot, NativeAsset, 0, { value: 9 })).to.be.reverted;
        })

        // it("Paying with invalid paymentToken address should revert",async function(){
        //     await expect(instance.connect(Client).payReporter(getReportRoot, NativeAsset, 0, { value: 9 })).to.be.reverted;
        // })

         // TODOS
        // 1. invalid contract addr check
        // 2. check to not  pay 0,
        // 3. we use wrapped ether , check to make sure  we are not using native asset value.
    })


    describe("=> Testing Withdraw()", function () {
        let reportRoot,
            reportAddress,
            salt,
            merkleProofval

        beforeEach(async () => {
            [reportRoot, reportAddress, salt, merkleProofval] = F_withdraw(report, ReportKeys.reporter);
            await instance.connect(Deployer).submit(reportRoot);
            await instance.connect(Client).payReporter(reportRoot, NativeAsset, 100, { value: 100 })
        });

        it("should allow multiple withdrawals", async function () {
            await expect(instance.connect(Deployer).withdraw(reportRoot, NativeAsset, 5, salt, reportAddress, merkleProofval))
            //Balance = await instance.connect(Reporter).getBalance(reportRoot, NativeAsset);
            await expect(instance.connect(Deployer).withdraw(reportRoot, NativeAsset, 5, salt, reportAddress, merkleProofval))
        })

        it("no underflow/overflow should exist", async function () {
            // TODO
        })

         // TODOS
        // withdrawal reportRoot with different account caller check
        // check if SC amount >= user wallet account 
        // with invalid address, with native asset, ether wrapper.
        // withdrawl if report is not paid
        // withdraw if amount passwd is "0"
    })

    describe("=> updateReport()",function(){
        let getReportRoot,
            key,
            commitment,
            attest_id,
            newStatusBitField;

        beforeEach(async () => {
            await instance.connect(Deployer).submit(F_submit(report));
            [getReportRoot, key, commitment] = F_attest(report, triagerAddress);
            instance.connect(Deployer).attest(getReportRoot, key, commitment)

            newStatusBitField = 00000001;
            Rkey = ReportKeys.report;
            attest_id = F_getAttestionID(report, triagerAddress, Rkey);
        })

        it("update trying",async function(){
            // https://github.com/immunefi-team/notary/blob/main/contracts/BugReportNotary.sol#L100
            const check_exist = await instance.connect(Deployer).attestations[attest_id];
            console.log(check_exist);

            await instance.connect(Deployer).updateReport(getReportRoot,newStatusBitField);

            val = await instance.connect(Deployer).reportHasStatus(getReportRoot, triagerAddress,0)
            console.log("====>",val);
            
            // TODOS
            // flag : 1 => false
            //  update report  on non-exist root
            // if  attest not perfommed, then no update 
        })
    })

    describe("=> disclose()",function(){
        let getReportRoot,
            merkleProofval,
            commit,
            rr,
            kk,
            key,
            salt,
            value;

        this.beforeEach(async () => {
            getReportRoot = F_submit(report)
            await instance.connect(Deployer).submit(getReportRoot);
            
            [rr, kk, commit] = F_attest(report, triagerAddress)
            await instance.connect(Deployer).attest(rr,kk,commit)

            key = ReportKeys.report;
            [getReportRoot, salt, value, merkleProofval] = F_disclose(report,key);
        });

        it("Disclosure Trying",async function(){
            await expect(instance.connect(Deployer).disclose(getReportRoot, key, salt, value, merkleProofval))
            .to.emit(instance,'ReportDisclosure')
            .withArgs(getReportRoot,key,value);

            // TimeStampped validationfailed because we cann't attest the report which is  inthe  process of disclosure.
            //const validate = await instance.connect(Deployer).validateAttestation(getReportRoot, Deployer.address, salt, value, merkleProofval);
        })
    })


    describe("=> upgradeToAndCall()", function () {
        it("Upgrading the current proxy", async function () {
            // current proxy address, Update Smart Contract Reference, New Deployer address
            await upgrades.upgradeProxy(instance.address, Notary, { args: Deployer.address, unsafeAllow: ['delegatecall'] })

        })

        it("Only ProxyOwner should able to upgrade the contract", async function () {
            await upgrades.admin.transferProxyAdminOwnership(instance.address, Client.address);

            await expect(upgrades.upgradeProxy(instance.address, Notary, { unsafeAllow: ['delegatecall'] }))
                .to.be.revertedWith("caller is not the owner");
        })
    })



});
