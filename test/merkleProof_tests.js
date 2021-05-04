
const keccak256 = require('keccak256');
const { expect } = require("chai");
const { upgrades } = require("hardhat");
const { MerkleTree } = require('merkletreejs');
const abiCoder = ethers.utils.defaultAbiCoder;

function getValueTypes(key) {
    let types;
    switch (key) {
      case "reporter":
        types = ["address"];
        break;
      case "description":
        types = ["bytes"];
        break;
      case "title":
        types = ["bytes"];
        break;
      case "severity":
        types = ["bytes"];
        break;
    }
    return types;
  }

function generateLeafData(key, salt, values) {
  return abiCoder.encode(["uint256", "string", "bytes32", ...getValueTypes(key)], [0, key, salt, ...values]);
}

function generateLeaf(key, salt, values) {
  return keccak256(generateLeafData(key, salt, values));
}

function generateAttestationData(key, salt, values, triager) {
  return abiCoder.encode(["uint256", "string", "bytes32", ...getValueTypes(key), "address"], [2, key, salt, ...values, triager]);
}

function generateCommitment(key, salt, values, triager) {
  return keccak256(generateAttestationData(key, salt, values, triager));
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
      instance = await upgrades.deployProxy(Notary, [operator1.address]);
    });

    it("should allow disclosure on a submitted report hash", async function () {
        const a = ["reporter", ethers.constants.HashZero, [ethers.constants.AddressZero]];
        const b = ["description", ethers.constants.HashZero, [ethers.constants.HashZero]];
        const leaves = [a,b].map(v => generateLeaf(...v));
        const tree = new MerkleTree(leaves, keccak256, { sort: true });

        const root = tree.getHexRoot();
        await instance.connect(operator1).submit(root);

        const leafData = generateLeafData(...a);
        const leaf = generateLeaf(...a);
        const proof = tree.getHexProof(leaf);
        await expect(instance.connect(operator1).disclose(root, "reporter", leafData, proof)).to.emit(instance, "ReportDisclosure").withArgs(root, "reporter", leafData);
    });
});


