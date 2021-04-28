const { Contract } = require("@ethersproject/contracts");
const { expect } = require("chai");
const { upgrades } = require("hardhat");


describe("Bug Report Notary", function () {
  let proxyOwner1,
    proxyOwner2,
    operator1,
    operator2,
    reporter1,
    reporter2,
    bountySponsor1,
    bounySponsor2;

  let Notary, instance;
  const exampleBytes = '0x627567'; // "bug";
  const exampleHash = ethers.utils.keccak256(ethers.utils.concat([0x00, exampleBytes]));
  const concatHashes = ethers.utils.hexlify(ethers.utils.concat([0x01,exampleHash,exampleHash]));
  const interHashes = ethers.utils.hexlify(ethers.utils.concat([exampleHash,exampleHash]))
  const exampleRoot = ethers.utils.keccak256(concatHashes);
  const OPERATOR_ROLE = ethers.utils.id("OPERATOR_ROLE");
  

  beforeEach(async () => {
    [ proxyOwner1,
      proxyOwner2,
      operator1,
      operator2,
      reporter1,
      reporter2,
      bountySponsor1,
      bounySponsor2 ] = await ethers.getSigners();
    
    Notary = await ethers.getContractFactory("BugReportNotary");
    instance = await upgrades.deployProxy(Notary, [operator1.address]);
  });

  it("should allow operator to disclose report", async function () {
    await instance.connect(operator1).submit(exampleRoot, reporter1.address);
    await expect(instance.connect(operator1).disclose(1, exampleBytes, [exampleHash])).to.emit(instance, "ReportDisclosure").withArgs(1, exampleBytes);
  });

  it("should not allow operator to disclose non leaf node", async function () {
    await instance.connect(operator1).submit(exampleRoot, reporter1.address);
    await expect(instance.connect(operator1).disclose(1, interHashes, [])).to.be.reverted;
  });

  it("should be deployed as a proxy with an initial operator", async function () {
    const isOperator = await instance.hasRole(OPERATOR_ROLE, operator1.address);
    expect(isOperator).to.equal(true);
  });

  it("should not be able to call initialize after deploy", async function () {
    await expect(instance.initialize(operator2.address))
      .to.be.revertedWith("Initializable: contract is already initialized");
  });

  it("should allow operator to submit bug", async function () {
    await expect(instance.connect(operator1).submit(exampleHash, reporter1.address)) 
      .to.emit(instance, "ReportSubmitted").withArgs(reporter1.address, 1);
  });

  it("should allow operator to set a status on a bug", async function () {
    await instance.connect(operator1).submit(exampleHash, reporter1.address);
    const tx = await instance.connect(operator1).setReportStatus(1, 1, true);
    expect(tx).to.emit(instance, "ReportUpdated").withArgs(1, 1, 3);
  })

  it("should not allow non-operator to submit bug", async function () {
    await expect(instance.connect(operator2).submit(exampleHash, reporter1.address))
      .to.be.reverted;
  });

  it("should only allow the proxy admin to upgrade the contract", async function () {
    await upgrades.admin.changeProxyAdmin(instance.address, proxyOwner2.address);
    let upgraded = await expect(
      upgrades.upgradeProxy(instance.address, Notary, {args: [operator2.address]})
      ).to.be.reverted;
  })
});

