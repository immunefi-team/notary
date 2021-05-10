const { upgrades } = require("hardhat");

async function main() {
  Notary = await ethers.getContractFactory("BugReportNotary");
  // using unsafe allow b/c this module isn't smart enough to detect that the delegate call in the OZ Address library can't be reached
  instance = await upgrades.deployProxy(Notary, ["0xfaCe3EC7B1d2d5482D12e4773b014c12Af9Dc681"], { unsafeAllow: ['delegatecall'] });

  console.log("Notary deployed to:", instance.address);
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main()
  .then(() => process.exit(0))
  .catch(error => {
    console.error(error);
    process.exit(1);
  });
