const { ethers } = require("hardhat");

async function main() {
    let user1,user2;

    Contract = await ethers.getContractFactory("TestToken");

    [user1, user2] = await ethers.getSigners();

    instance = await Contract.deploy(user1.address); // minting in user1.address

    console.log("USER1 :",await user1.address,"USER2 :",await user2.address);
    console.log("TTKN_address : ", await instance.address, "USER1 BALANCE :", ethers.utils.formatEther(await instance.balanceOf(user1.address)), ",     USER2 BALANCE :", ethers.utils.formatEther(await instance.balanceOf(user2.address)));

    await instance.allowance(user1.address, user2.address);
    await instance.approve(user2.address, 500000000000);

    console.log("ALLOWANCE LIMIT IS :", ethers.utils.formatEther(await instance.allowance(user1.address, user2.address)));

    await instance.transfer(user2.address,5000000);

    console.log("TTKN_address : ", await instance.address, "USER1 BALANCE :", ethers.utils.formatEther(await instance.balanceOf(user1.address)), ",     USER2 BALANCE :", ethers.utils.formatEther(await instance.balanceOf(user2.address)));
}


main();
