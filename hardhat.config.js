require("@nomiclabs/hardhat-waffle");
require('@openzeppelin/hardhat-upgrades');
require('hardhat-deploy');
const { config } = require("dotenv");
const { resolve } = require("path");
config({ path: resolve(__dirname, "./.env") });

// This is a sample Hardhat task. To learn how to create your own go to
// https://hardhat.org/guides/create-task.html
task("accounts", "Prints the list of accounts", async () => {
  const accounts = await ethers.getSigners();

  for (const account of accounts) {
    console.log(account.address);
  }
});

// You need to export an object to set up your config
// Go to https://hardhat.org/config/ to learn more

/**
 * @type import('hardhat/config').HardhatUserConfig
 */
module.exports = {
  networks: {
    poa: {
      accounts: {
        mnemonic: process.env.MNEMONIC,
        count: 10,
        initialIndex: 6
      },
      chainId: 77,
      url: "https://sokol.poa.network"
    },
    xdai: {
      accounts: {
        mnemonic: process.env.MNEMONIC,
        count: 10,
        initialIndex: 6
      },
      chainId: 100,
      url: "https://rpc.xdaichain.com/"
    }
  },
  solidity: {
    version: "0.8.4",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200
      }
    }
  }
};

