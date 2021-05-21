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

const address_ZERO = ethers.constants.AddressZero;
const random_bytes_RAND = ethers.utils.formatBytes32String("hax");
const random_bytes_ZERO = ethers.utils.formatBytes32String(0);

const ONE_ETHER_FORMAT = ethers.utils.parseUnits("1", "ether");
const HALF_ETHER_FORMAT = ethers.utils.parseUnits("0.5", "ether");

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

async function F_SUBMIT(report) {
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

function F_getAttestionID(report, Triager, key) {
    const reportRoot = generateReportRoot(report);
    return keccak256(abiCoder.encode(["bytes32", "address", "string"], [reportRoot, Triager, key]));
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
    // contract instance 1

    let TestTokenERC20,
        tkk_instance;

    // contract instance 2

    let Notary,
        instance;

    // addresses

    let ERC20Payer,
        Deployer,
        Triager,
        Reporter1,
        Reporter2,
        Client;

    let salt, report1,report2

    before(async function () {
        // https://forum.openzeppelin.com/t/logging-verbose-during-local-tests-with-upgradeable-contracts/4633/10
        await upgrades.silenceWarnings();
    });

    beforeEach(async () => {

        // Mock TestToken Contract - Initialization
        TestTokenERC20 = await ethers.getContractFactory("TestToken");

        [ERC20Payer, Deployer, Triager, Reporter1,Reporter2, Client] = await ethers.getSigners();

        tkk_instance = await TestTokenERC20.deploy(ERC20Payer.address);

        // Notary Contract - Initialization

        Notary = await ethers.getContractFactory("BugReportNotary");
        instance = await upgrades.deployProxy(Notary, [Deployer.address], { unsafeAllow: ['delegatecall'] });

        // Adding to `ERC20Payer` address to TestToken SC `Allowance`
        await tkk_instance.allowance(ERC20Payer.address, instance.address);
        await tkk_instance.approve(instance.address, ethers.utils.parseUnits("100000", "ether")); // ether format for 100000 tokens
        
        // console.log(ethers.utils.formatEther(await tkk_instance.allowance(ERC20Payer.address, instance.address))) // returns the allowance (uint256)amount
        // console.log("ERC20Payer :", await ERC20Payer.address, "Client :", await Client.address);
        // console.log("TTKN_address : ", await tkk_instance.address, "ERC20Payer BALANCE :", ethers.utils.formatEther(await tkk_instance.balanceOf(ERC20Payer.address)))

        // Constant Reports
        salt = generateRandomSalt();
        report1 = { "id": 1, "salts": salt, "paymentWalletAddress": Reporter1.address, "project": "0xbf971d4360414c84ea06783d0ea51e69035ee526" }
        report2 = { "id": 2, "salts": salt, "paymentWalletAddress": Reporter2.address, "project": "0xfbb1b73c4f0bda4f67dca266ce6ef42f520fbb98" }

        // `Deployer` is the only operator on deployProxy,To keep Deployer seperate for proxy upgrades tasks \ 
        // Assigning `OPERATOR` role to `Triager` who will be responsible for all `OPERATOR` operations on contract functions.
        await instance.connect(Deployer).grantRole(operator_keccak, Triager.address);
    });

    describe("===> submit()", function () {
        let getReportRoot;

        beforeEach(async () => {
            getReportRoot = F_SUBMIT(report1);
        });

        it("submit(): Only Callable by the operator role only", async function () {
            await expect(instance.connect(Triager).submit(getReportRoot));
            // .to.emit(instance, "ReportSubmitted").
            // withArgs(getReportRoot, await ethers.provider.getBlock(await ethers.provider.getBlockNumber()).timestamp); // AssertionError - How to  get current block timestamp?
        })

        it("submit(): Revert if called by other than OPERATOR ROLE", async function () {
            await expect(instance.connect(Reporter1).submit(getReportRoot)).to.be.reverted;
        })

        it("submit(): Only Accepts a report root format of merkle tree constructed from the report", async function () {
            //  accept
            await expect(instance.connect(Triager).submit(random_bytes_RAND));
            //  reject
            await expect(instance.connect(Triager).submit(address_ZERO)).to.be.reverted;
        })

        it("submit(): Revert on submitting same report root multiple times",async function(){
            await expect(instance.connect(Triager).submit(getReportRoot))
            await expect(instance.connect(Triager).submit(getReportRoot)).revertedWith("Bug Report Notary: Report already submitted"); // since report already exists in `reports` mapping.
        })

    });

    describe("===> Attest()", function () {
        let getReportRoot,
            key,
            commitment;

        beforeEach(async () => {
            await instance.connect(Triager).submit(F_SUBMIT(report1));
            [getReportRoot, key, commitment] = F_attest(report1, Triager.address);
        });

        it("Attest(): Attest the report", async function () {
            await expect(instance.connect(Triager).attest(getReportRoot, key, commitment))
            // .to.emit(instance,"ReportAttestation")
            // .withArgs(Triager.address,getReportRoot,key,ethers.block.timestamp);
        })

        it("Attest(): Revert if Caller is not an Operator", async function () {
            await expect(instance.connect(Reporter1).attest(getReportRoot, key, commitment))
                .to.be.reverted;
        })

        it("Attest(): Attest multiple times on same report should revert",async function(){
            await expect(instance.connect(Triager).attest(getReportRoot, key, commitment))
            await expect(instance.connect(Triager).attest(getReportRoot, key, commitment)).to.be.reverted;
        })

        it("Attest(): Revert if Attest Commitment is Empty",async function(){
            await expect(instance.connect(Triager).attest(getReportRoot, key, random_bytes_ZERO)).revertedWith("Bug Report Notary: Invalid commitment");
        })

        // [BUG] should fail
        it("Attest(): Attest on non-exisiting report should revert",async function(){
            [getReportRoot, key, commitment] = F_attest(report2,Reporter2.address);
            await expect(instance.connect(Triager).attest(getReportRoot,key,commitment));
        })

    })

    describe("===> getBalance()", function () {
        let getReportRoot,
            Balance;

        beforeEach(async () => {
            getReportRoot = F_SUBMIT(report1);
            await instance.connect(Triager).submit(getReportRoot);
        });

        it("getBalance(): should return the amount of tokens deposited to a given report",async function(){
            Balance = await instance.connect(Triager).getBalance(getReportRoot, NativeAsset);
            await expect(ethers.utils.formatEther(Balance)).to.equal('0.0') // since we didn't paid the report, the initial balance of reporter address is 0
        })
    })

    describe("===> PayReporter()", function () {
        let getReportRoot;
        
        beforeEach(async () => {
            // generate Root of report
            getReportRoot = F_SUBMIT(report1);
            await instance.connect(Triager).submit(getReportRoot);
        });


        it("PayReporter(): Anyone can Pay the report, Paying in NATIVE ASSET",async function(){
            await expect(instance.connect(Triager).payReporter(getReportRoot, NativeAsset, ONE_ETHER_FORMAT, { value: ONE_ETHER_FORMAT }))
        })

        it("PayReporter(): Paying the report with ERC20 tokens",async function(){
            await expect(instance.connect(ERC20Payer).payReporter(getReportRoot, tkk_instance.address, ONE_ETHER_FORMAT)) //  sending 1 TOKEN only
            await expect(ethers.utils.formatEther(await instance.connect(Triager).getBalance(getReportRoot, tkk_instance.address))).to.be.equal('1.0');
        })

        it("PayReporter(): While Paying the report with ERC20 tokens,If native asset `value` sent then revert",async function(){ // Native Asset  `value` should be 0 when paying with ERC20 tokens
            await expect(instance.connect(ERC20Payer).payReporter(getReportRoot, tkk_instance.address, ONE_ETHER_FORMAT, { value: 100 })).to.be.revertedWith("Bug Report Notary: Native asset sent for ERC20 payment");
        })

        it("PayReporter(): Pay the report and check the final balance of the report", async function () {
            Before_Balance = await instance.connect(Triager).getBalance(getReportRoot, NativeAsset);
            //console.log(ethers.utils.formatEther(Before_Balance));

            // Paying in Native Asset , 1 ETHER
            await instance.connect(Client).payReporter(getReportRoot, NativeAsset, ONE_ETHER_FORMAT, { value: ONE_ETHER_FORMAT })

            After_Balance = await instance.connect(Triager).getBalance(getReportRoot, NativeAsset);

            await expect(ethers.utils.formatEther(After_Balance)).to.equal('1.0')
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
            [reportRoot, reportAddress, salt, merkleProofval] = F_withdraw(report1, ReportKeys.reporter);
            await instance.connect(Triager).submit(reportRoot);
        });

        it("Withdraw(): Workflow: Client pays the report,Other user withdraws the report,Compare the final balances on both smart contract `balances` map and main address", async function () { // but the amount will get `withdrawed` to the address which was provided along with the report. 
            // storage -> stored on smart contract memory i.e `balances` mapping
            // address -> actual balance of the address

            // Intially: Balances would be "0.0" for report and balance for address is "10000" ether from hardhat node

            /*
            1. client paid the `Reporter1` report with 1 ETHER which is only stored on smart contract `balances`
            2. Checking balance of `Reporter1` report to == 1 ETHER
            3. `Reporter2` withdraws the 0.5 ETHER for the `Reporter1` report.
            4. `Reporter1` now should now have 10000.5 ETHER in main address and 0.5 ETHER on smart contract report balance.
            */
            
            var main_bal_before = await ethers.provider.getBalance(Reporter1.address)

            //1
            // IERC20(paymentToken).safeTransferFrom(msg.sender, address(this), amount); : Storing the payment amount on SC `balances`
            // msg.sender is the caller user -> address(this) is the smart contract address
             await instance.connect(Client).payReporter(reportRoot, NativeAsset, ONE_ETHER_FORMAT, { value: ONE_ETHER_FORMAT })
            //2
            await expect(ethers.utils.formatEther(await instance.connect(Reporter1).getBalance(reportRoot, NativeAsset))).to.equal("1.0"); // 1 ETHER
            //3
            await expect(instance.connect(Reporter2).withdraw(reportRoot, NativeAsset, HALF_ETHER_FORMAT , salt, reportAddress, merkleProofval)) // report should have now 0.5 ETHER
            //4
            await expect(ethers.utils.formatEther(await instance.connect(Reporter1).getBalance(reportRoot, NativeAsset))).to.equal("0.5"); // balance on smart contract `balances` mapping
            var main_bal_after = await ethers.provider.getBalance(Reporter1.address) 
            
            // console.log(ethers.utils.formatEther(bal_before), ethers.utils.formatEther(bal_after));

            final_bal = await main_bal_after.sub(main_bal_before)  // 10000.4988922 - 9999.9988922
            await expect(ethers.utils.formatEther(final_bal)).to.equal("0.5");
        })
        
        it("Withdraw(): Withdraw the Custom ERC20 Balance from the report",async function(){
            await expect(instance.connect(ERC20Payer).payReporter(reportRoot, tkk_instance.address, ONE_ETHER_FORMAT))
            Before_Balance = await instance.connect(Triager).getBalance(reportRoot, tkk_instance.address);
            
            await expect(instance.connect(Reporter2).withdraw(reportRoot, tkk_instance.address, HALF_ETHER_FORMAT, salt, reportAddress, merkleProofval))
            After_Balance = await instance.connect(Triager).getBalance(reportRoot, tkk_instance.address);
            await expect(ethers.utils.formatEther(After_Balance)).to.equal("0.5");
        })

        it("Withdraw(): multiple withdrawals on same report should work", async function () {
            await instance.connect(Client).payReporter(reportRoot, NativeAsset, 100, { value: 100 })

            await expect(instance.connect(Triager).withdraw(reportRoot, NativeAsset, 5, salt, reportAddress, merkleProofval))
            await expect(instance.connect(Triager).withdraw(reportRoot, NativeAsset, 5, salt, reportAddress, merkleProofval))
        })

        it("Withdraw(): Withdrawing unpaid Report should revert", async function () {
            await expect(instance.connect(Triager).withdraw(reportRoot, NativeAsset, 5, salt, reportAddress, merkleProofval)).to.be.reverted;
        })

        it("Withdraw(): Should work with Withdrawal amount with '0'", async function () { // Since there's no check for amount 0, Transaction gonna utilize the gas only then
            await instance.connect(Client).payReporter(reportRoot, NativeAsset, 100, { value: 100 })
            await expect(instance.connect(Triager).withdraw(reportRoot, NativeAsset, 0, salt, reportAddress, merkleProofval));
        })

        it("Withdraw(): revert if withdrawing with invalid Payment/Token Address",async function(){
            await instance.connect(Client).payReporter(reportRoot, NativeAsset, 100, { value: 100 })
            await expect(instance.connect(Triager).withdraw(reportRoot, 0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee, 10, salt, reportAddress, merkleProofval)).to.be.reverted;
        })

        it("Withdraw(): revert if withdrawal amount > report amount", async function(){
            await instance.connect(Client).payReporter(reportRoot, NativeAsset, 100, { value: 100 })
            await expect(instance.connect(Triager).withdraw(reportRoot, NativeAsset, 1000, salt, reportAddress, merkleProofval)).to.be.reverted;
        })

        it("Withdraw(): Anyone can perform withdraw() on the report", async function () {  // but the payments goes to original report owner who provided walletaddress
            await instance.connect(Client).payReporter(reportRoot, NativeAsset, ONE_ETHER_FORMAT, { value: ONE_ETHER_FORMAT })
            await expect(instance.connect(Triager).withdraw(reportRoot, NativeAsset, HALF_ETHER_FORMAT, salt, reportAddress, merkleProofval))
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
            await instance.connect(Triager).submit(F_SUBMIT(report1));
            [getReportRoot, key, commitment] = F_attest(report1, Triager.address);

            newStatusBitField = 00000001; // Bitnumbers
            Rkey = ReportKeys.report;
            attest_id = F_getAttestionID(report1, Triager.address, Rkey);
        })

        it("updateReport(): Update the report with newStatusBitField",async function(){
            instance.connect(Triager).attest(getReportRoot, key, commitment)
            await expect(instance.connect(Triager).updateReport(getReportRoot, newStatusBitField));
        })

        it("updateReport(): Update the report with newStatusBitField and check ReportStatus",async function(){
            instance.connect(Triager).attest(getReportRoot, key, commitment)

             // Bit Fields binary: 0 here is to get the `first` bit from 8 bits , i.e 1 byte = 8 bits, since boolean use only first bit

            // false: report has not been updated
            await expect(await instance.connect(Triager).reportHasStatus(getReportRoot, Triager.address, 0)).to.be.false;

            // updated the report with newStatusBitField by OPERATOR: replace '0' with '1'
            await expect(await instance.connect(Triager).updateReport(getReportRoot,newStatusBitField));

            // true: report has been updated
            await expect(await instance.connect(Triager).reportHasStatus(getReportRoot, Triager.address, 0)).to.be.true;
        
        })

        it("updateReport(): Only Operator can update the report with new statusfield",async function(){
            instance.connect(Triager).attest(getReportRoot, key, commitment)
            await expect(instance.connect(Client).updateReport(getReportRoot, newStatusBitField)).to.be.reverted;
        })

        it("updateReport(): Revert if updating the report with invalid StatusBitField", async function () {
            instance.connect(Triager).attest(getReportRoot, key, commitment)
            await expect(instance.connect(Triager).updateReport(getReportRoot, 0000000)).to.be.revertedWith("Bug Report Notary: Invalid status update");
        })

        it("updateReport(): Updating the non-attested report should revert", async function () {
            await expect(instance.connect(Triager).updateReport(F_SUBMIT(report1), newStatusBitField)).to.be.revertedWith("Bug Report Notary: Report is unattested");
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
            getReportRoot = F_SUBMIT(report1)
            await instance.connect(Triager).submit(getReportRoot);
            
            [rr, kk, commit] = F_attest(report1, Triager.address)
            
            key = ReportKeys.report;
            [getReportRoot, salt, value, merkleProofval] = F_disclose(report1,key);
        });

        it("disclose(): Only operator can disclose the report", async function () {
            await instance.connect(Triager).attest(rr, kk, commit)

            await expect(instance.connect(Client).disclose(getReportRoot, key, salt, value, merkleProofval))
                .to.be.reverted;
        })

        it("disclose(): Disclosing the report",async function(){
            await instance.connect(Triager).attest(rr, kk, commit)

            await expect(instance.connect(Triager).disclose(getReportRoot, key, salt, value, merkleProofval))
            .to.emit(instance,'ReportDisclosure')
            .withArgs(getReportRoot,key,value);
        })

        // [BUG] should fail
        it("disclose(): Doing Attest on Disclosed Report should revert",async function(){
            await expect(instance.connect(Triager).disclose(getReportRoot, key, salt, value, merkleProofval))
                .to.emit(instance, 'ReportDisclosure')
                .withArgs(getReportRoot, key, value);

            await instance.connect(Triager).attest(getReportRoot, key, commit)
        })

        // [BUG] should fail
        it("disclose(): Doing Update on Disclosed Report should revert", async function () {
            await instance.connect(Triager).attest(getReportRoot, key, commit)
            
            await expect(instance.connect(Triager).disclose(getReportRoot, key, salt, value, merkleProofval))
                .to.emit(instance, 'ReportDisclosure')
                .withArgs(getReportRoot, key, value);

            // false
            //console.log("STATUS : ", await instance.connect(Triager).reportHasStatus(getReportRoot, Triager.address, 0))

            await expect(instance.connect(Triager).updateReport(getReportRoot, 00000001));

            // true
            //console.log("STATUS : ", await instance.connect(Triager).reportHasStatus(getReportRoot, Triager.address, 0))
        })

        //[BUG] should fail
        it("disclose(): Disclosing the already disclosed report should revert", async function () {
            await instance.connect(Triager).attest(rr, kk, commit)

            await expect(instance.connect(Triager).disclose(getReportRoot, key, salt, value, merkleProofval))
                .to.emit(instance, 'ReportDisclosure')
                .withArgs(getReportRoot, key, value);

            await expect(instance.connect(Triager).disclose(getReportRoot, key, salt, value, merkleProofval))
                .to.be.revertedWith("Bug Report Notary: Key already disclosed for report");
        })
    })


    describe("===> ValidateAttestation()", function () {
        let getReportRoot,
            merkleProofval,
            commit,
            rr,
            kk,
            key,
            salt,
            value;

        this.beforeEach(async () => {
            getReportRoot = F_SUBMIT(report1)
            await instance.connect(Triager).submit(getReportRoot);

            [rr, kk, commit] = F_attest(report1, Triager.address)

            key = ReportKeys.report;
            [getReportRoot, salt, value, merkleProofval] = F_disclose(report1, key);
        });

        // Bug Report Notary: Invalid timestamp
        // TimeStampped validation failed because we cann't attest the report which is in the process of disclosure of `ATTESTATION_DELAY` i.e 24 hours
        it("validateAttestation(): Validate attestation after disclosing the report", async function () {
            await instance.connect(Triager).attest(getReportRoot, kk, commit)
            await expect(instance.connect(Triager).disclose(getReportRoot, key, salt, value, merkleProofval))
            await expect(instance.connect(Triager).validateAttestation(getReportRoot, Triager.address, salt, value, merkleProofval)).to.be.revertedWith("Bug Report Notary: Invalid timestamp");
        })
    });

    describe("===> initialize()", function () {
        // since contract is already deployed and already intialized 
        it("initialize() : Revert on re-intialize", async function () {
            await expect(instance.connect(Deployer).initialize(Client.address))
                .to.be.reverted;
        })

        it("intialize() : Triager(OPERATOR) shouldn't able to call intialize", async function () {
            // Since contract is already deployed, User wouldn't  able to re-intialize
            await expect(instance.connect(Triager).initialize(Client.address))
                .to.be.reverted;
        })
    });



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
