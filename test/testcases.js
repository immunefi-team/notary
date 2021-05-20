// WIP: WORK IN PROGRESS
const keccak256 = require('keccak256');
const { expect } = require("chai");
const { upgrades, ethers } = require("hardhat");
const { MerkleTree } = require('merkletreejs');
const { isConstructSignatureDeclaration } = require('typescript');
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

// [!] Merkle Helper Functions

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

// [!] Helper Functions

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


// [!] SMART CONTRACT FUNCTION GENERATORS to use them in mocha test cases:
// useful to generate arguments for functions.

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

describe("Notary Test Workflows",async function () {
    let TestTokenERC20,
        tkk_instance;

    let Notary,
        instance;

    // addresses to

    let ERC20Payer,
        Deployer,
        Triager,
        Reporter,
        Client;

    let salt, report, triagerAddress

    beforeEach(async () => {
        // Mock TestToken Contract - Initialization
        TestTokenERC20 = await ethers.getContractFactory("TestToken");

        [ERC20Payer, Deployer, Triager, Reporter, Client] = await ethers.getSigners();

        tkk_instance = await TestTokenERC20.deploy(ERC20Payer.address);

        // Notary Contract - Initialization

        Notary = await ethers.getContractFactory("BugReportNotary");
        instance = await upgrades.deployProxy(Notary, [Deployer.address], { unsafeAllow: ['delegatecall'] });

        // Adding to `Notary contract instance` to TestToken SC `Allowance`
        await tkk_instance.allowance(ERC20Payer.address, instance.address);
        await tkk_instance.approve(instance.address, 500000000000);
        // console.log(ethers.utils.formatEther(await tkk_instance.allowance(ERC20Payer.address, instance.address))) // returns the allowance (uint256)amount

        // console.log("ERC20Payer :", await ERC20Payer.address, "Client :", await Client.address);
        // console.log("TTKN_address : ", await tkk_instance.address, "ERC20Payer BALANCE :", ethers.utils.formatEther(await tkk_instance.balanceOf(ERC20Payer.address)))


        // Report
        salt = generateRandomSalt();
        report = { "id": 1, "salts": salt, "paymentWalletAddress": Deployer.address, "project": "0xbf971d4360414c84ea06783d0ea51e69035ee526" }
        triagerAddress = Deployer.address; // Note: Report PaymentWalletAddress is also a Deployer.address 
    });


    describe("===> initialize()", function () {
        // since contract is already deployed and already intialized 
        it("initialize() : Revert on re-intialize", async function () {
            await expect(instance.connect(Deployer).initialize(Deployer.address))
                .to.be.reverted; 
        })
    });


    describe("===> submit()", function () {
        let getReportRoot;

        beforeEach(async () => {
            getReportRoot = F_submit(report);
        });

        it("submit(): Only Callable by the operator role only", async function () {
            await expect(instance.connect(Deployer).submit(getReportRoot));
        })

        it("submit(): Revert if called by other than OPERATOR ROLE", async function () {
            await expect(instance.connect(Reporter).submit(getReportRoot)).to.be.reverted;
        })

        it("submit(): Only Accepts a report root of merkle tree constructed from the report", async function () {
            await expect(await instance.connect(Deployer).submit(getReportRoot))
            // .to.emit(instance, "ReportSubmitted").
            //     withArgs(getReportRoot, ethers.provider.getBlockNumber().timestamp); // TBA, How to generate current block timestamp?
        })

        it("submit(): Revert on submitting same report root multiple times",async function(){
            await expect(instance.connect(Deployer).submit(getReportRoot))
            await expect(instance.connect(Deployer).submit(getReportRoot)).revertedWith("Bug Report Notary: Report already submitted"); // since report already exists in `reports` mapping.
        })

    });

    describe("===> Attest()", function () {
        let getReportRoot,
            key,
            commitment;

        beforeEach(async () => {
            await instance.connect(Deployer).submit(F_submit(report));
            [getReportRoot, key, commitment] = F_attest(report, triagerAddress);
        });

        it("Attest(): Attest the report", async function () {
            await expect(instance.connect(Deployer).attest(getReportRoot, key, commitment))
            // .to.emit(instance,"ReportAttestation")
            // .withArgs(triagerAddress,getReportRoot,key,ethers.block.timestamp);
        })

        it("Attest(): Revert if Caller is not an Operator", async function () {
            await expect(instance.connect(Reporter).attest(getReportRoot, key, commitment))
                .to.be.reverted;
        })

        it("Attest(): Attest multiple times on same report should revert",async function(){
            await expect(instance.connect(Deployer).attest(getReportRoot, key, commitment))
            await expect(instance.connect(Deployer).attest(getReportRoot, key, commitment)).to.be.reverted;
        })

        //  Error: incorrect data length
        it("Attest(): Revert if Attest Commitment is Empty",async function(){
            await expect(instance.connect(Deployer).attest(getReportRoot, key, 0x000000000000000000000000000000)).to.be.reverted;
        })

    })

    describe("===> getBalance()", function () {
        let getReportRoot,
            Balance;

        beforeEach(async () => {
            getReportRoot = F_submit(report);
            await instance.connect(Deployer).submit(getReportRoot);
        });

        it("getBalance(): should return the amount of tokens deposited to a given report",async function(){
            Balance = await instance.connect(Deployer).getBalance(getReportRoot, NativeAsset);
            await expect(ethers.utils.formatEther(Balance)).to.equal('0.0') // since we didn't paid the report, the initial balance of reporter address is 0
        })
    })

    describe("===> PayReporter()", function () {
        let getReportRoot;

        // For testing "Paying the report with ERC20 tokens", We are deploying `TestToken` Mock
        beforeEach(async () => {
            // generate Root of report
            getReportRoot = F_submit(report);
            await instance.connect(Deployer).submit(getReportRoot);
        });


        it("PayReporter(): Anyone can Pay the report, Paying in NATIVE ASSET",async function(){
            await expect(instance.connect(Triager).payReporter(getReportRoot, NativeAsset, 9, { value: 9 }))
        })

        it("PayReporter(): Paying the report with ERC20 tokens",async function(){
            await expect(instance.connect(ERC20Payer).payReporter(getReportRoot, tkk_instance.address, 133337))
            await expect(ethers.utils.formatEther(await instance.connect(Deployer).getBalance(getReportRoot, tkk_instance.address))).to.be.equal('0.000000000000133337');
        })

        it("PayReporter(): While Paying the report with ERC20 tokens,If native asset `value` sent then revert",async function(){ // Native Asset  `value` should be 0 when paying with ERC20 tokens
            await expect(instance.connect(ERC20Payer).payReporter(getReportRoot, tkk_instance.address, 133337, { value: 100 })).to.be.revertedWith("Bug Report Notary: Native asset sent for ERC20 payment");
        })

        it("PayReporter(): Pay the report and check the final balance of the report", async function () {
            Before_Balance = await instance.connect(Deployer).getBalance(getReportRoot, NativeAsset);
            //console.log(ethers.utils.formatEther(Before_Balance));

            // Paying in Native Asset , 9 wei
            await instance.connect(Client).payReporter(getReportRoot, NativeAsset, 9, { value: 9 })

            After_Balance = await instance.connect(Deployer).getBalance(getReportRoot, NativeAsset);
            //console.log(ethers.utils.formatEther(After_Balance));

            await expect(ethers.utils.formatEther(After_Balance)).to.equal('0.000000000000000009')
        })

        it("PayReporter(): Paying with amount '0' should revert", async function () {
            await expect(instance.connect(Client).payReporter(getReportRoot, NativeAsset, 0, { value: 9 })).revertedWith("Bug Report Notary: Amount must be larger than zero");
        })

        it("PayReporter(): Paying with invalid payment/Token address should revert", async function () {
            await expect(instance.connect(Client).payReporter(getReportRoot, 0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee, 1)).to.be.reverted;
        })

        it("PayReporter(): Reports can get paid multiple times", async function () {
            await expect(instance.connect(Client).payReporter(getReportRoot, NativeAsset, 9, { value: 9 }));
            await expect(instance.connect(Client).payReporter(getReportRoot, NativeAsset, 100, { value: 100 }));
        })

        it("PayReporter(): No Underflow/Overflow on amount", async function () {
            // TODO
        })
    })

    describe("===> Testing Withdraw()", function () {
        let reportRoot,
            reportAddress,
            salt,
            merkleProofval

        beforeEach(async () => {
            [reportRoot, reportAddress, salt, merkleProofval] = F_withdraw(report, ReportKeys.reporter);
            await instance.connect(Deployer).submit(reportRoot);
        });

        if ("Withdraw(): Anyonce can perform a withdraw on a report", async function () { // but the amount will get `withdrawed` to the address which was provided along with the report. 
            await instance.connect(Client).payReporter(reportRoot, NativeAsset, 1000000000000000, { value: 1000000000000000 })
        })

        it("Withdraw(): Check balances before/after withdraw on a report for address and 'balances' map (smart contract storage)",async function(){
            // storage -> stored on smart contract memory i.e `balances` mapping
            // address -> actual balance of the address

            // Intially: Balances would be "0.0" for report and address
            
            Initial_Balance_address = ethers.utils.formatEther(await ethers.provider.getBalance(reportAddress));
            Initial_Balance_storage = ethers.utils.formatEther(await instance.connect(Client).getBalance(reportRoot,NativeAsset));

           // IERC20(paymentToken).safeTransferFrom(msg.sender, address(this), amount); : Storing the payment amount on SC `balances`
            await instance.connect(Client).payReporter(reportRoot, NativeAsset, 1000000000000000, { value: 1000000000000000 })

            Before_Balance_address = ethers.utils.formatEther(await ethers.provider.getBalance(reportAddress));
            Before_Balance_storage = ethers.utils.formatEther(await instance.connect(Client).getBalance(reportRoot, NativeAsset));

            await expect(instance.connect(Client).withdraw(reportRoot, NativeAsset, 50000000000, salt, reportAddress, merkleProofval)) // report should have now 0.0000000000000095 wei
            
            After_Balance_address = ethers.utils.formatEther(await ethers.provider.getBalance(reportAddress));
            After_Balance_storage = ethers.utils.formatEther(await instance.connect(Client).getBalance(reportRoot, NativeAsset));

            // storage
            console.log(Initial_Balance_storage, Before_Balance_storage, After_Balance_storage);

            // address :  Why they both are same?
            console.log(Initial_Balance_address, Before_Balance_address, After_Balance_address);
        })

        it("Withdraw(): Withdraw the Custom ERC20 Balance from the report",async function(){
            console.log(ethers.utils.formatEther(await tkk_instance.balanceOf(reportAddress)));
            await expect(instance.connect(ERC20Payer).payReporter(reportRoot, tkk_instance.address, 133337))

            console.log(ethers.utils.formatEther(await tkk_instance.balanceOf(reportAddress)));
            await expect(instance.connect(Deployer).withdraw(reportRoot, tkk_instance.address, 10000, salt, reportAddress, merkleProofval))
            console.log(ethers.utils.formatEther(await tkk_instance.balanceOf(reportAddress)));
        })

        it("Withdraw(): multiple withdrawals on same report should work", async function () {
            await instance.connect(Client).payReporter(reportRoot, NativeAsset, 100, { value: 100 })

            await expect(instance.connect(Deployer).withdraw(reportRoot, NativeAsset, 5, salt, reportAddress, merkleProofval))
            await expect(instance.connect(Deployer).withdraw(reportRoot, NativeAsset, 5, salt, reportAddress, merkleProofval))
        })

        it("Withdraw(): Withdrawing unpaid Report should revert", async function () {
            await expect(instance.connect(Deployer).withdraw(reportRoot, NativeAsset, 5, salt, reportAddress, merkleProofval)).to.be.reverted;
        })

        it("Withdraw(): Should work with Withdrawal amount with '0'", async function () { // Since there's no check for amount 0, Transaction gonna utilize the gas only then
            await instance.connect(Client).payReporter(reportRoot, NativeAsset, 100, { value: 100 })
            await expect(instance.connect(Deployer).withdraw(reportRoot, NativeAsset, 0, salt, reportAddress, merkleProofval));
        })

        it("Withdraw(): revert if withdrawing with invalid Payment/Token Address",async function(){
            await instance.connect(Client).payReporter(reportRoot, NativeAsset, 100, { value: 100 })
            await expect(instance.connect(Deployer).withdraw(reportRoot, 0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee, 10, salt, reportAddress, merkleProofval)).to.be.reverted;
        })

        it("Withdraw(): revert if withdrawal amount > report amount", async function(){
            await instance.connect(Client).payReporter(reportRoot, NativeAsset, 100, { value: 100 })
            await expect(instance.connect(Deployer).withdraw(reportRoot, NativeAsset, 1000, salt, reportAddress, merkleProofval)).to.be.reverted;
        })

        it("Withdraw(): No underflow/overflow on amount", async function () {
            // TODO
        })
    })

    describe("===> updateReport()",function(){
        let getReportRoot,
            key,
            commitment,
            attest_id,
            newStatusBitField;

        beforeEach(async () => {
            await instance.connect(Deployer).submit(F_submit(report));
            [getReportRoot, key, commitment] = F_attest(report, triagerAddress);

            newStatusBitField = 00000001; // Bitnumbers
            Rkey = ReportKeys.report;
            attest_id = F_getAttestionID(report, triagerAddress, Rkey);
        })

        it("updateReport(): Update the report with newStatusBitField",async function(){
            instance.connect(Deployer).attest(getReportRoot, key, commitment)
            await expect(instance.connect(Deployer).updateReport(getReportRoot, newStatusBitField));
        })

        it("updateReport(): Update the report with newStatusBitField and check ReportStatus",async function(){
            instance.connect(Deployer).attest(getReportRoot, key, commitment)

             // 0 here is to get the `first` bit from 8 bits , i.e 1 byte = 8 bits, since boolean use only first bit
            // false: report has been not updated
            await expect(await instance.connect(Deployer).reportHasStatus(getReportRoot, triagerAddress, 0)).to.be.false;

            // updated with newStatusBitField: replace '0' with '1'
            await expect(await instance.connect(Deployer).updateReport(getReportRoot,newStatusBitField));

            // true: report has been updated
            await expect(await instance.connect(Deployer).reportHasStatus(getReportRoot, triagerAddress, 0)).to.be.true;
        
        })

        it("updateReport(): Revert if updating the report with invalid StatusBitField", async function () {
            instance.connect(Deployer).attest(getReportRoot, key, commitment)
            await expect(instance.connect(Deployer).updateReport(getReportRoot, 0000000)).to.be.revertedWith("Bug Report Notary: Invalid status update");
        })

        it("updateReport(): Updating the non-attested report should revert", async function () {
            await expect(instance.connect(Deployer).updateReport(F_submit(report), newStatusBitField)).to.be.revertedWith("Bug Report Notary: Report is unattested");
        })

    })

    describe("===> disclose()",function(){
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
            
            key = ReportKeys.report;
            [getReportRoot, salt, value, merkleProofval] = F_disclose(report,key);
        });

        it("disclose(): Only operator can disclose the report", async function () {
            await instance.connect(Deployer).attest(rr, kk, commit)

            await expect(instance.connect(Client).disclose(getReportRoot, key, salt, value, merkleProofval))
                .to.be.reverted;
        })

        it("disclose(): Disclosing the report",async function(){
            await instance.connect(Deployer).attest(rr, kk, commit)

            await expect(instance.connect(Deployer).disclose(getReportRoot, key, salt, value, merkleProofval))
            .to.emit(instance,'ReportDisclosure')
            .withArgs(getReportRoot,key,value);
        })

        // should fail?
        it("disclose(): Doing Attest on Disclosed Report should revert",async function(){
            await expect(instance.connect(Deployer).disclose(getReportRoot, key, salt, value, merkleProofval))
                .to.emit(instance, 'ReportDisclosure')
                .withArgs(getReportRoot, key, value);

            await instance.connect(Deployer).attest(getReportRoot, key, commit)
        })

        // should fail?
        it("disclose(): Doing Update on Disclosed Report should revert", async function () {
            await instance.connect(Deployer).attest(getReportRoot, key, commit)
            
            await expect(instance.connect(Deployer).disclose(getReportRoot, key, salt, value, merkleProofval))
                .to.emit(instance, 'ReportDisclosure')
                .withArgs(getReportRoot, key, value);

            console.log("STATUS : ", await instance.connect(Deployer).reportHasStatus(getReportRoot, triagerAddress, 0))

            await expect(instance.connect(Deployer).updateReport(getReportRoot, 00000001));

            console.log("STATUS : ", await instance.connect(Deployer).reportHasStatus(getReportRoot, triagerAddress, 0))
        })

        it("disclose(): Disclosing the already disclosed report should revert", async function () {
            await instance.connect(Deployer).attest(rr, kk, commit)

            await expect(instance.connect(Deployer).disclose(getReportRoot, key, salt, value, merkleProofval))
                .to.emit(instance, 'ReportDisclosure')
                .withArgs(getReportRoot, key, value);

            await expect(instance.connect(Deployer).disclose(getReportRoot, key, salt, value, merkleProofval))
                .to.be.revertedWith("Bug Report Notary: Key already disclosed for report");
        })
    })


    describe("===> upgradeProxy()", function () {
        it("upgradeProxy(): Upgrading the current proxy", async function () {
                                      //[current proxy address, Updated Smart Contract Reference, New Deployer address]
            await upgrades.upgradeProxy(instance.address, Notary, { args: Deployer.address, unsafeAllow: ['delegatecall'] })

        })

        it("upgradeProxy(): Only ProxyOwner should able to upgrade the contract", async function () {
            await upgrades.admin.transferProxyAdminOwnership(instance.address, Client.address);

            await expect(upgrades.upgradeProxy(instance.address, Notary, { unsafeAllow: ['delegatecall'] }))
                .to.be.revertedWith("caller is not the owner");
        })
    })


});
