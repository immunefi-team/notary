const keccak256 = require('keccak256');
const { expect } = require("chai");
const { upgrades, ethers } = require("hardhat");
const { MerkleTree } = require('merkletreejs');
const abiCoder = ethers.utils.defaultAbiCoder; //An AbiCoder created when the library is imported which is used by the Interface.
const { ReportKeys, generateRandomSalt } = require('./Utils/Helpers');

// Merkle Helpers
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
    generateCommitment } = require("./Utils/Merkle");

// Function Argument Generators
const { makeSubmitArgs,
    makeAttestArgs,
    makeDiscloseArgs,
    makeWithdrawArgs } = require("./Utils/Generators");


// [!] CONSTANTS KEYWORDS
const OperatorKeccak = keccak256("OPERATOR_ROLE");
const NativeAsset = '0x0000000000000000000000000000000000000000' // ethers.utils.getAddress('0x0') //  ETH on mainet, XDAI on paonetwork
const AttestationDelay = 24 // 24 hours

const Address_Zero = ethers.constants.AddressZero;
const Bytes32_String = ethers.utils.formatBytes32String("hax");
const Bytes32_Zero = ethers.utils.formatBytes32String(0);

const ONE_ETHER_FORMAT = ethers.utils.parseUnits("1", "ether");
const HALF_ETHER_FORMAT = ethers.utils.parseUnits("0.5", "ether");


// [!] TESTING SETUP
describe("Notary Test Cases",async function () {
    let TestERC20Factory,
        TestERC20;

    let EscrowImpl,
        Escrow;
    
    let NotaryImpl,
        Notary;

    // addresses
    let ERC20Payer,
        Deployer,
        Triager,
        Reporter1,
        Reporter2,
        Client;

    let report1,report2

    before(async function () {
        await upgrades.silenceWarnings(); // https://forum.openzeppelin.com/t/logging-verbose-during-local-tests-with-upgradeable-contracts/4633/10
    });

    beforeEach(async () => {
        // Mock ERC20 `TestToken` Contract - Initialization
        TestERC20Factory = await ethers.getContractFactory("TestToken");
        [ERC20Payer, Deployer, Triager, Reporter1,Reporter2, Client] = await ethers.getSigners();
        TestERC20 = await TestERC20Factory.deploy(ERC20Payer.address);

        // Notary Contract - Initialization
        NotaryImpl = await ethers.getContractFactory("BugReportNotary");
        Notary = await upgrades.deployProxy(NotaryImpl, [Deployer.address], { unsafeAllow: ['delegatecall'] });

        // Escrow Contract - Initialization : Escrow contract initialize the `notary` interface with `Notary.address`
        EscrowImpl = await ethers.getContractFactory("Escrow");
        Escrow = await upgrades.deployProxy(EscrowImpl, [Notary.address], { unsafeAllow: ['delegatecall'] });

        await TestERC20.approve(Escrow.address, ethers.utils.parseUnits("100000", "ether")); // ether format for 100000 tokens

        report1 = { "id": 1, "salts": generateRandomSalt(), "paymentWalletAddress": Reporter1.address, "project": "0xbf971d4360414c84ea06783d0ea51e69035ee526" }
        report2 = { "id": 2, "salts": generateRandomSalt(), "paymentWalletAddress": Reporter2.address, "project": "0xfbb1b73c4f0bda4f67dca266ce6ef42f520fbb98" }

        // `Deployer` is the only operator on deployProxy,To keep Deployer independent for proxy upgrades tasks \ 
        // Assigning `OPERATOR` role to `Triager` who will be responsible for all `OPERATOR` operations on `Notary`contract functions.
        await Notary.connect(Deployer).grantRole(OperatorKeccak, Triager.address);
    });

    it("precheck: if `Escrow` and `Notary` is on same proxy interface.",async function(){
        let escrow_notary_proxy_addr = await Escrow.connect(Deployer).notary(); // get the address of notary interface from Escrow.
        await expect(escrow_notary_proxy_addr).to.be.equal(Notary.address);
    })

    describe("===> submit()", function () {
        let reportRoot;

        beforeEach(async () => {
            reportRoot = makeSubmitArgs(report1);
        });

        it("Only Callable by the `OPERATOR` role", async function () {
            let resp = await Notary.connect(Triager).submit(reportRoot);
            let block = await ethers.provider.getBlock(resp.blockNumber);
            expect(resp).to.emit(Notary, "ReportSubmitted").withArgs(reportRoot, block.timestamp);
        })

        it("Revert, If called by other than `OPERATOR` role", async function () {
            await expect(Notary.connect(Reporter1).submit(reportRoot)).to.be.reverted;
        })

        it("Only Accepts a root of merkle tree format constructed from the report", async function () {
            await expect(Notary.connect(Triager).submit(Bytes32_String)); 
            await expect(Notary.connect(Triager).submit(Bytes32_Zero)).to.be.reverted;
        })

        it("Revert, If the same report root submitted more than once",async function(){
            await expect(Notary.connect(Triager).submit(reportRoot))
            await expect(Notary.connect(Triager).submit(reportRoot)).revertedWith("Bug Report Notary: Report already submitted"); // since report already exists in `reports` mapping.
        })

    });

    describe("===> Attest()", function () {
        let reportRoot,
            key,
            commitment;

        beforeEach(async () => {
            await Notary.connect(Triager).submit(makeSubmitArgs(report1));
            [reportRoot, key, commitment] = makeAttestArgs(report1, Triager.address);
        });

        it("Attest the report", async function () {
            let resp = await Notary.connect(Triager).attest(reportRoot, key, commitment);
            let block = await ethers.provider.getBlock(resp.blockNumber);
            expect(resp).to.emit(Notary, "ReportAttestation").withArgs(Triager.address,reportRoot,key,block.timestamp);
        })

        it("Revert, if the caller is not an `OPERATOR`", async function () {
            await expect(Notary.connect(Reporter1).attest(reportRoot, key, commitment))
                .to.be.reverted;
        })

        it("Revert, if attest more than once on the same report",async function(){
            await expect(Notary.connect(Triager).attest(reportRoot, key, commitment))
            await expect(Notary.connect(Triager).attest(reportRoot, key, commitment)).to.be.reverted;
        })

        it("Revert, if attest `commitment` is empty",async function(){
            await expect(Notary.connect(Triager).attest(reportRoot, key, Bytes32_Zero)).revertedWith("Bug Report Notary: Invalid commitment");
        })

        it("Revert, if attest on non-exisiting report",async function(){
            [reportRoot, key, commitment] = makeAttestArgs(report2,Reporter2.address);
            await expect(Notary.connect(Triager).attest(reportRoot, key, commitment)).revertedWith("Bug Report Notary: Report not yet submitted");
        })

    })

    describe("===> getBalance()", function () {
        let reportRoot,
            Balance;

        beforeEach(async () => {
            reportRoot = makeSubmitArgs(report1);
            await Notary.connect(Triager).submit(reportRoot);
        });

        it("Should return the amount of tokens deposited to a given report",async function(){
            Balance = await Escrow.connect(Triager).getBalance(reportRoot, NativeAsset)
            await expect(ethers.utils.formatEther(Balance)).to.equal('0.0') // since we didn't paid the report, the initial balance of reporter address is 0
        })

        it("Anyone can call the function with or without `OPERATOR` role", async function () {
            await expect(Escrow.connect(Reporter2).getBalance(reportRoot, NativeAsset))
        })
        
    })

    describe("===> deposit()", function () {
        let reportRoot;
        
        beforeEach(async () => {
            reportRoot = makeSubmitArgs(report1);
            await Notary.connect(Triager).submit(reportRoot);
        });


        it("Anyone can Pay the report, Paying in NATIVE ASSET",async function(){
            await expect(Escrow.connect(Client).deposit(reportRoot, NativeAsset, ONE_ETHER_FORMAT, { value: ONE_ETHER_FORMAT }))
        })

        it("Paying the report with ERC20 tokens",async function(){
            await expect(Escrow.connect(ERC20Payer).deposit(reportRoot, TestERC20.address, ONE_ETHER_FORMAT)) //  sending 1 TOKEN only
            await expect(ethers.utils.formatEther(await Escrow.connect(Triager).getBalance(reportRoot, TestERC20.address))).to.be.equal('1.0');
        })

        it("Revert, If report is paid with ERC20 tokens along with NATIVE asset",async function(){ // Native Asset  `value` should be 0 when paying with ERC20 tokens
            await expect(Escrow.connect(ERC20Payer).deposit(reportRoot, TestERC20.address, ONE_ETHER_FORMAT, { value: 100 })).to.be.revertedWith("Bug Report Escrow: Native asset sent for ERC20 payment");
        })

        it("Pay the report and check the final balance of the report", async function () {
            await Escrow.connect(Client).deposit(reportRoot, NativeAsset, ONE_ETHER_FORMAT, { value: ONE_ETHER_FORMAT })
            After_Balance = await Escrow.connect(Triager).getBalance(reportRoot, NativeAsset);
            await expect(ethers.utils.formatEther(After_Balance)).to.equal('1.0')
        })

        it("Revert, If the report paying amount is '0'", async function () {
            await expect(Escrow.connect(Client).deposit(reportRoot, NativeAsset, 0, { value: 0 })).revertedWith("Bug Report Escrow: Amount must be larger than zero");
        })

        it("Revert, If paying the report with invalid/non-exist asset address", async function () {
            await expect(Escrow.connect(Client).deposit(reportRoot, 0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee, 1)).to.be.reverted;
        })

        it("Reports can get paid multiple times and check the final balance of the report", async function () {
            await Escrow.connect(Client).deposit(reportRoot, NativeAsset, ONE_ETHER_FORMAT, { value: ONE_ETHER_FORMAT });
            await Escrow.connect(Client).deposit(reportRoot, NativeAsset, ONE_ETHER_FORMAT, { value: ONE_ETHER_FORMAT });
            After_Balance = await Escrow.connect(Triager).getBalance(reportRoot, NativeAsset);
            await expect(ethers.utils.formatEther(After_Balance)).to.equal('2.0')
        })

        it("[TODO] deposit(): No Underflow/Overflow on amount", async function () {
            // TODO
        })
    })


    describe("===> withdraw()", function () {
        let reportRoot,
            reportAddress,
            salt,
            merkleProofval

        beforeEach(async () => {
            [reportRoot, reportAddress, salt, merkleProofval] = makeWithdrawArgs(report1, ReportKeys.reporter);
            await Notary.connect(Triager).submit(reportRoot);
        });

        it("Workflow: Client pays the report,Other user withdraws the report,Compare the final balances on both `smart contract report` and `main address on blockchain`", async function () { // Anyone can withdraw the report,  but the amount will get `withdrawed` to the address which was provided along with the report.
            // Intially: Balances would be "0.0" for report and balance for address is "10000" ether from hardhat node
            /*
            1. client paid the `Reporter1` report with 1 ETHER which is only stored on smart contract `balances`
            2. Checking balance of `Reporter1` report to == 1 ETHER
            3. `Reporter2` withdraws the 0.5 ETHER for the `Reporter1` report.
            4. `Reporter1` now should now have 10000.5 ETHER in main address and 0.5 ETHER on smart contract report balance.
            */
            
            var reporter_bal_before = await ethers.provider.getBalance(Reporter1.address)

            //1
            await expect(ethers.utils.formatEther(await Escrow.connect(Reporter1).getBalance(reportRoot, NativeAsset))).to.equal("0.0"); // since no one paid yet
            await Escrow.connect(Client).deposit(reportRoot, NativeAsset, ONE_ETHER_FORMAT, { value: ONE_ETHER_FORMAT })
            //2
            await expect(ethers.utils.formatEther(await Escrow.connect(Reporter1).getBalance(reportRoot, NativeAsset))).to.equal("1.0"); // 1 ETHER
            //3
            await expect(Escrow.connect(Reporter2).withdraw(reportRoot, NativeAsset, HALF_ETHER_FORMAT , salt, reportAddress, merkleProofval)) // report should have now 0.5 ETHER
            //4
            await expect(ethers.utils.formatEther(await Escrow.connect(Reporter1).getBalance(reportRoot, NativeAsset))).to.equal("0.5"); // balance on smart contract `balances` mapping

            var reporter_bal_after = await ethers.provider.getBalance(Reporter1.address)
            
            reporter_final_bal = await reporter_bal_after.sub(reporter_bal_before)  // 10000.5 - 10000
            await expect(ethers.utils.formatEther(reporter_final_bal)).to.equal("0.5");
        })

        
        it("Withdraw the Custom ERC20 Balance from the report and check final balance of the report",async function(){
            await expect(Escrow.connect(ERC20Payer).deposit(reportRoot, TestERC20.address, ONE_ETHER_FORMAT))
            Before_Balance = await Escrow.connect(Triager).getBalance(reportRoot, TestERC20.address);
            
            await expect(Escrow.connect(Reporter2).withdraw(reportRoot, TestERC20.address, HALF_ETHER_FORMAT, salt, reportAddress, merkleProofval))
            After_Balance = await Escrow.connect(Triager).getBalance(reportRoot, TestERC20.address);
            await expect(ethers.utils.formatEther(After_Balance)).to.equal("0.5");
        })

        it("Multiple withdrawals on the report should work, Check the final balance of report", async function () {
            await Escrow.connect(Client).deposit(reportRoot, NativeAsset, ONE_ETHER_FORMAT, { value: ONE_ETHER_FORMAT })

            await expect(Escrow.connect(Triager).withdraw(reportRoot, NativeAsset, HALF_ETHER_FORMAT, salt, reportAddress, merkleProofval))
            await expect(Escrow.connect(Triager).withdraw(reportRoot, NativeAsset, HALF_ETHER_FORMAT, salt, reportAddress, merkleProofval))
            
            After_Balance = await Escrow.connect(Triager).getBalance(reportRoot, NativeAsset);
            await expect(ethers.utils.formatEther(After_Balance)).to.equal("0.0");
        })

        it("Revert, If calling `withdraw` amount on the report which doesn't have any balance", async function () {
            await expect(Escrow.connect(Triager).withdraw(reportRoot, NativeAsset, 5, salt, reportAddress, merkleProofval)).to.be.reverted;
        })

        it("Withdraw should work with amount '0'", async function () { // Since there's no check for amount 0, Transaction gonna utilize the gas only then
            await Escrow.connect(Client).deposit(reportRoot, NativeAsset, 100, { value: 100 })
            await expect(Escrow.connect(Triager).withdraw(reportRoot, NativeAsset, 0, salt, reportAddress, merkleProofval));
        })

        it("Revert, if withdrawing the report with invalid asset address",async function(){
            await Escrow.connect(Client).deposit(reportRoot, NativeAsset, 100, { value: 100 })
            await expect(Escrow.connect(Triager).withdraw(reportRoot, 0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee, 10, salt, reportAddress, merkleProofval)).to.be.reverted;
        })

        it("revert, if withdrawal amount > report amount", async function(){
            await Escrow.connect(Client).deposit(reportRoot, NativeAsset, 100, { value: 100 })
            await expect(Escrow.connect(Triager).withdraw(reportRoot, NativeAsset, 1000, salt, reportAddress, merkleProofval)).to.be.reverted;
        })

        it("revert, if argument `address` passed is different from actual report address", async function () { // merkle verify will fail
            await Escrow.connect(Client).deposit(reportRoot, NativeAsset, ONE_ETHER_FORMAT, { value: ONE_ETHER_FORMAT })
            await expect(Escrow.connect(Triager).withdraw(reportRoot, NativeAsset, ONE_ETHER_FORMAT, salt, Reporter2.address, merkleProofval)).revertedWith('Bug Report Notary: Merkle proof failed.');
        })

        it("Anyone can perform withdraw() on the report, Check if the report address recieves the funds", async function () {  // but the payments goes to original report owner who provided walletaddress
            await Escrow.connect(ERC20Payer).deposit(reportRoot, TestERC20.address, ONE_ETHER_FORMAT)
            await Escrow.connect(Reporter1).withdraw(reportRoot, TestERC20.address, HALF_ETHER_FORMAT, salt, reportAddress, merkleProofval)

            var report_bal_after = await Escrow.connect(Reporter1).getBalance(reportRoot, TestERC20.address);
            await expect(ethers.utils.formatEther(report_bal_after)).to.equal("0.5");

            var reporter_bal_after = await TestERC20.balanceOf(reportAddress);
            await expect(ethers.utils.formatEther(reporter_bal_after)).to.equal("0.5");
        })

        it("[TODO] withdraw(): No underflow/overflow on amount", async function () {
            // TODO
        })
    })

    describe("===> updateReport()",function(){
        let reportRoot,
            key,
            commitment,
            newStatusBitField;

        beforeEach(async () => {
            await Notary.connect(Triager).submit(makeSubmitArgs(report1));
            [reportRoot, key, commitment] = makeAttestArgs(report1, Triager.address);

            newStatusBitField = 00000001; // Bitnumbers
            Rkey = ReportKeys.report;
        })

        it("updateReport(): Update the report with newStatusBitField",async function(){
           Notary.connect(Triager).attest(reportRoot, key, commitment)
            await expect(Notary.connect(Triager).updateReport(reportRoot, newStatusBitField));
        })

        it("updateReport(): Update the report with newStatusBitField and check ReportStatus",async function(){
           Notary.connect(Triager).attest(reportRoot, key, commitment)

            await expect(await Notary.connect(Triager).reportHasStatus(reportRoot, Triager.address, 0)).to.be.false;
            await expect(await Notary.connect(Triager).updateReport(reportRoot,newStatusBitField));
            await expect(await Notary.connect(Triager).reportHasStatus(reportRoot, Triager.address, 0)).to.be.true;
        
        })

        it("updateReport(): Only Operator can update the report with new statusfield",async function(){
           Notary.connect(Triager).attest(reportRoot, key, commitment)
            await expect(Notary.connect(Client).updateReport(reportRoot, newStatusBitField)).to.be.reverted;
        })

        it("updateReport(): Revert if updating the report with invalid StatusBitField", async function () {
           Notary.connect(Triager).attest(reportRoot, key, commitment)
            await expect(Notary.connect(Triager).updateReport(reportRoot, 0000000)).to.be.revertedWith("Bug Report Notary: Invalid status update");
        })

        it("updateReport(): Updating the non-attested report should revert", async function () {
            await expect(Notary.connect(Triager).updateReport(makeSubmitArgs(report1), newStatusBitField)).to.be.revertedWith("Bug Report Notary: Report is unattested");
        })

    })

    describe("===> disclose()",function(){
        let reportRoot,
            merkleProofval,
            commit,
            rr,
            kk,
            key,
            salt,
            value;

        this.beforeEach(async () => {
            reportRoot = makeSubmitArgs(report1)
            await Notary.connect(Triager).submit(reportRoot);
            
            [rr, kk, commit] = makeAttestArgs(report1, Triager.address)
            
            key = ReportKeys.report;
            [reportRoot, salt, value, merkleProofval] = makeDiscloseArgs(report1,key);
        });

        it("Anyone can disclose the report",async function(){
            await Notary.connect(Triager).attest(rr, kk, commit)

            await expect(Notary.connect(Triager).disclose(reportRoot, key, salt, value, merkleProofval))
            .to.emit(Notary,'ReportDisclosure')
            .withArgs(reportRoot,key,value);
        })

        // [BUG] should fail : https://github.com/immunefi-team/notary/issues/16
        it("[BUG] Doing Attest on Disclosed Report should revert",async function(){
            await Notary.connect(Triager).disclose(reportRoot, key, salt, value, merkleProofval)
            await expect(Notary.connect(Triager).attest(reportRoot, key, commit)).to.be.reverted;
        })

        // [BUG] should fail : https://github.com/immunefi-team/notary/issues/16
        it("[BUG] Doing Update on Disclosed Report should revert", async function () {
            await Notary.connect(Triager).attest(reportRoot, key, commit)
            
            await Notary.connect(Triager).disclose(reportRoot, key, salt, value, merkleProofval)
            await expect(Notary.connect(Triager).updateReport(reportRoot, 00000001)).to.be.reverted;;
        })

    })


    describe("===> ValidateAttestation()", function () {
        let reportRoot,
            merkleProofval,
            commit,
            rr,
            kk,
            key,
            salt,
            value;

        this.beforeEach(async () => {
            reportRoot = makeSubmitArgs(report1)
            await Notary.connect(Triager).submit(reportRoot);

            [rr, kk, commit] = makeAttestArgs(report1, Triager.address)

            key = ReportKeys.report;
            [reportRoot, salt, value, merkleProofval] = makeDiscloseArgs(report1, key);
        });

        it("Revert, if validating the attestation on disclosed report `BEFORE` AttestationDelay timestamp", async function () {
            await Notary.connect(Triager).attest(reportRoot, kk, commit)
            await expect(Notary.connect(Triager).disclose(reportRoot, key, salt, value, merkleProofval))
            await expect(Notary.connect(Triager).validateAttestation(reportRoot, Triager.address, salt, value, merkleProofval)).to.be.revertedWith("Bug Report Notary: Invalid timestamp");
        })

        it("Validating the attestation on disclosed report `AFTER` AttestationDelay", async function () {
            await Notary.connect(Triager).attest(reportRoot, kk, commit)
            await expect(Notary.connect(Triager).disclose(reportRoot, key, salt, value, merkleProofval))

            const increaseTime = AttestationDelay * 60 * 60 // ATTESTION in `hour` format x 60 min x 60 sec
            await ethers.provider.send("evm_increaseTime", [increaseTime]) //  1. increase block time 
            await ethers.provider.send("evm_mine") // 2. then mine the block
            await expect(Notary.connect(Triager).validateAttestation(reportRoot, Triager.address, salt, value, merkleProofval));
        })

        it("should return true, if a given attestation is valid and has a given status set to true", async function () {
            await Notary.connect(Triager).attest(reportRoot, kk, commit)
            await Notary.connect(Triager).updateReport(reportRoot, 00000001)
            await expect(Notary.connect(Triager).disclose(reportRoot, key, salt, value, merkleProofval))

            const increaseTime = AttestationDelay * 60 * 60 
            await ethers.provider.send("evm_increaseTime", [increaseTime]) 
            await ethers.provider.send("evm_mine")          
        
            let status = await Notary.connect(Triager).validateReportStatus(reportRoot, Triager.address,0, salt, value, merkleProofval);
            await expect(status).to.be.true;
        })

    });

    describe("===> initialize()", function () {
        // since contract is already deployed and already intialized 
        it("initialize() : Revert on re-intialize", async function () {
            await expect(Notary.connect(Deployer).initialize(Client.address))
                .to.be.reverted;
        })

        it("intialize() : (OPERATOR) shouldn't able to call intialize", async function () {
            // Since contract is already deployed, User wouldn't  able to re-intialize
            await expect(Notary.connect(Triager).initialize(Client.address))
                .to.be.reverted;
        })
    });



    describe("===> upgradeProxy()", function () {
        it("upgradeProxy(): Upgrading the current proxy", async function () {
                                      //[current proxy address, Updated Smart Contract Reference, New Deployer address]
            await upgrades.upgradeProxy(Notary.address, NotaryImpl, { args: Deployer.address, unsafeAllow: ['delegatecall'] })

        })

        it("upgradeProxy(): Only ProxyOwner should able to upgrade the contract", async function () {
            await upgrades.admin.transferProxyAdminOwnership(Notary.address, Client.address);
            await expect(upgrades.upgradeProxy(Notary.address, NotaryImpl, { unsafeAllow: ['delegatecall'] }))
                .to.be.revertedWith("caller is not the owner");
        })
    })


});
