const { Contract } = require("@ethersproject/contracts");
const { expect } = require("chai");
const { upgrades } = require("hardhat");


describe("Notary", function () {
  let proxyOwner1,
    proxyOwner2,
    operator1,
    operator2,
    reporter1,
    reporter2,
    bountySponsor1,
    bounySponsor2;

  let Notary, instance;
  const exampleHash = "0x706618637b8ca922f6290ce1ecd4c31247e9ab75cf0530a0ac95c0332173d7c5"
  

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

  it("should be deployed as a proxy with an initial operator", async function () {
    const isOperator = await instance.operators(operator1.address);
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

  it("should not allow non-operator to submit bug", async function () {
    await expect(instance.connect(operator2).submit(exampleHash, reporter1.address))
      .to.be.revertedWith("Bug Report Notary: Not Authorized");
  });
});

