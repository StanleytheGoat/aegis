const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("MockHoneypot", function () {
  let honeypot;
  let deployer;
  let buyer;
  let router; // simulates a DEX router contract

  beforeEach(async function () {
    [deployer, buyer] = await ethers.getSigners();

    const MockHoneypot = await ethers.getContractFactory("MockHoneypot");
    honeypot = await MockHoneypot.deploy();
    await honeypot.waitForDeployment();

    // Deploy a simple contract to act as "DEX router" (has code, so isLikelyDex = true)
    const DummyRouter = await ethers.getContractFactory("AegisGateway");
    router = await DummyRouter.deploy(deployer.address, deployer.address);
    await router.waitForDeployment();
  });

  describe("Honeypot Mechanics", function () {
    it("should report owner as address(0) (fake renounce)", async function () {
      expect(await honeypot.owner()).to.equal(ethers.ZeroAddress);
    });

    it("should have 99% sell tax", async function () {
      expect(await honeypot.sellTaxBps()).to.equal(9900);
    });

    it("should allow buys (transfers from EOA) without tax", async function () {
      // Transfer tokens to buyer (simulates a buy - from EOA, no tax)
      const amount = ethers.parseEther("1000");
      await honeypot.transfer(buyer.address, amount);
      expect(await honeypot.balanceOf(buyer.address)).to.equal(amount);
    });

    it("should apply 99% tax on sells (transfers to contract)", async function () {
      // Give buyer some tokens
      const amount = ethers.parseEther("1000");
      await honeypot.transfer(buyer.address, amount);

      // Buyer tries to "sell" (transfer to a contract address = DEX)
      const routerAddr = await router.getAddress();
      await honeypot.connect(buyer).transfer(routerAddr, amount);

      // Router should only receive 1% (99% tax)
      const routerBalance = await honeypot.balanceOf(routerAddr);
      const expectedAfterTax = amount / 100n; // 1%
      expect(routerBalance).to.equal(expectedAfterTax);
    });

    it("should allow deployer to pause selling", async function () {
      await honeypot.pauseSelling();
      expect(await honeypot.sellPaused()).to.equal(true);
    });

    it("should block sells when paused", async function () {
      const amount = ethers.parseEther("100");
      await honeypot.transfer(buyer.address, amount);
      await honeypot.pauseSelling();

      const routerAddr = await router.getAddress();
      await expect(
        honeypot.connect(buyer).transfer(routerAddr, amount)
      ).to.be.revertedWith("Trading paused");
    });

    it("should enforce max sell amount", async function () {
      // Max sell is 1% of total supply = 10M tokens
      const totalSupply = await honeypot.totalSupply();
      const maxSell = totalSupply / 100n;

      const amount = maxSell + 1n;
      await honeypot.transfer(buyer.address, amount);

      const routerAddr = await router.getAddress();
      await expect(
        honeypot.connect(buyer).transfer(routerAddr, amount)
      ).to.be.revertedWith("Exceeds max sell");
    });

    it("should whitelist deployer from sell restrictions", async function () {
      const amount = ethers.parseEther("1000");
      const routerAddr = await router.getAddress();

      // Deployer is whitelisted - should transfer full amount
      await honeypot.transfer(routerAddr, amount);
      // Deployer sends to contract but is whitelisted, so no tax
      // However, _isLikelyDex checks extcodesize of `to`, and deployer address is EOA
      // The transfer goes through without tax since deployer is whitelisted
      const routerBalance = await honeypot.balanceOf(routerAddr);
      expect(routerBalance).to.equal(amount);
    });
  });

  describe("Hidden Admin Functions", function () {
    it("should allow real owner to change sell tax", async function () {
      await honeypot.setSellTax(5000); // 50%
      expect(await honeypot.sellTaxBps()).to.equal(5000);
    });

    it("should block non-owner from changing sell tax", async function () {
      await expect(
        honeypot.connect(buyer).setSellTax(0)
      ).to.be.revertedWith("Not owner");
    });

    it("should allow real owner to change max sell", async function () {
      await honeypot.setMaxSell(1);
      expect(await honeypot.maxSellAmount()).to.equal(1);
    });
  });
});
