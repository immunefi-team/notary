
const keccak256 = require('keccak256');
const { expect } = require("chai");
const { upgrades } = require("hardhat");
const { MerkleTree } = require('merkletreejs');
const abiCoder = ethers.utils.defaultAbiCoder;

function getValueTypes(key) {
  return {
    "reporter": ["address"],
    "report": ["bytes"],
  }[key];
}
  
// value should be passed in encoded, e.g. generateLeafData("reporter", example_salt, abiCoder.encode(["address"], [example_address]) )
function generateLeafData(key, salt, value) {
  return ethers.utils.hexConcat([abiCoder.encode(["uint256", "string", "bytes32"], [0, key, salt]), value]);
}

function generateLeaf(key, salt, value) {
  return keccak256(generateLeafData(key, salt, value));
}

// same deal with value here as above (must be encoded first)
function generateAttestationData(triager, key, salt, value) {
  return ethers.utils.hexConcat([abiCoder.encode(["uint256", "address", "string", "bytes32"], [1, triager, key, salt]), value]);
}

function generateCommitment(key, salt, value, triager) {
  return keccak256(generateAttestationData(key, salt, value, triager));
}

describe("Merkle Tree", function () {
    let proxyOwner1,
      proxyOwner2,
      operator1,
      operator2,
      reporter1,
      reporter2,
      bountySponsor1,
      bounySponsor2;
  
    let Notary, instance;
    
  
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
      // using unsafe allow b/c this module isn't smart enough to detect that the delegate call in the OZ Address library can't be reached
      instance = await upgrades.deployProxy(Notary, [operator1.address], { unsafeAllow: ['delegatecall'] });
    });

    it("should allow disclosure on a submitted report hash", async function () {
        const exampleAddress = abiCoder.encode(["address"], [ethers.constants.AddressZero]);
        const exampleReport = abiCoder.encode(["bytes"], [ethers.constants.HashZero]);
        const a = ["reporter", ethers.constants.HashZero, exampleAddress];
        const b = ["report", ethers.constants.HashZero, exampleReport];
        const leaves = [a,b].map(v => generateLeaf(...v));
        const tree = new MerkleTree(leaves, keccak256, { sort: true });

        const root = tree.getHexRoot();
        await instance.connect(operator1).submit(root);

        const leafData = generateLeafData(...a);
        const leaf = generateLeaf(...a);
        const proof = tree.getHexProof(leaf);
        await expect(instance.connect(operator1).disclose(root, "reporter", ethers.constants.HashZero, exampleAddress, proof))
          .to.emit(instance, "ReportDisclosure").withArgs(root, "reporter", exampleAddress);
        console.log(exampleAddress);
    });
});


