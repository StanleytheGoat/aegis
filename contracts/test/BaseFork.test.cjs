/**
 * Fork tests against real Base mainnet state.
 *
 * Run with: FORK_BASE=1 npx hardhat test contracts/test/BaseFork.test.cjs
 *
 * These tests deploy AegisGateway with the real Safe multisig as fee recipient,
 * verify all integrations work against live Base state, and test the full
 * attestation -> execute -> fee flow.
 */
const { expect } = require("chai");
const { ethers } = require("hardhat");

// Real Base mainnet addresses (verified via ethskills)
const POOL_MANAGER = "0x498581ff718922c3f8e6a244956af099b2652b2b";
const SAFE_FEE_RECIPIENT = "0x3cfFEcfdBC7cE87067990b2863dfBBfD1cfD5952";
const WETH = "0x4200000000000000000000000000000000000006";
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

describe("Base Mainnet Fork Tests", function () {
  // Skip if not forking
  before(function () {
    if (!process.env.FORK_BASE) {
      this.skip();
    }
  });

  let gateway;
  let deployer;
  let agent;

  beforeEach(async function () {
    [deployer, agent] = await ethers.getSigners();

    // Deploy AegisGateway with real Safe as fee recipient
    const Gateway = await ethers.getContractFactory("AegisGateway");
    gateway = await Gateway.deploy(deployer.address, SAFE_FEE_RECIPIENT);
    await gateway.waitForDeployment();
  });

  describe("Deployment on Base fork", function () {
    it("should deploy with correct fee recipient (Safe multisig)", async function () {
      expect(await gateway.feeRecipient()).to.equal(SAFE_FEE_RECIPIENT);
    });

    it("should verify Safe has code at fee recipient address", async function () {
      const code = await ethers.provider.getCode(SAFE_FEE_RECIPIENT);
      expect(code).to.not.equal("0x");
      expect(code.length).to.be.greaterThan(2);
    });

    it("should verify PoolManager exists on Base", async function () {
      const code = await ethers.provider.getCode(POOL_MANAGER);
      expect(code).to.not.equal("0x");
    });

    it("should verify WETH exists on Base", async function () {
      const code = await ethers.provider.getCode(WETH);
      expect(code).to.not.equal("0x");
    });

    it("should verify USDC exists on Base", async function () {
      const code = await ethers.provider.getCode(USDC);
      expect(code).to.not.equal("0x");
    });

    it("should set correct default parameters", async function () {
      expect(await gateway.riskThreshold()).to.equal(70);
      expect(await gateway.feeBps()).to.equal(5);
      expect(await gateway.attester()).to.equal(deployer.address);
      expect(await gateway.owner()).to.equal(deployer.address);
    });
  });

  describe("Attestation and execution on fork", function () {
    it("should record attestation and execute protected transaction", async function () {
      // Create a simple ETH receiver contract
      const Receiver = await ethers.getContractFactory("EthReceiver");
      const receiver = await Receiver.deploy();
      await receiver.waitForDeployment();

      const receiverAddr = await receiver.getAddress();

      // Create attestation
      const attestationId = ethers.keccak256(ethers.toUtf8Bytes("fork-test-1"));
      const selector = "0x00000000"; // fallback
      const riskScore = 10;

      // Sign attestation
      const gatewayAddr = await gateway.getAddress();
      const network = await ethers.provider.getNetwork();
      const messageHash = ethers.solidityPackedKeccak256(
        ["bytes32", "address", "address", "bytes4", "uint8", "uint256", "address"],
        [attestationId, agent.address, receiverAddr, selector, riskScore, network.chainId, gatewayAddr]
      );
      const signature = await deployer.signMessage(ethers.getBytes(messageHash));

      // Record attestation
      await gateway.recordAttestation(
        attestationId,
        agent.address,
        receiverAddr,
        selector,
        riskScore,
        signature
      );

      // Execute protected transaction with 0.001 ETH
      const txValue = ethers.parseEther("0.001");
      const expectedFee = (txValue * 5n) / 10000n; // 5 bps
      const minFee = ethers.parseEther("0.0001");
      const actualFee = expectedFee < minFee ? minFee : expectedFee;

      await gateway.connect(agent).executeProtected(
        attestationId,
        receiverAddr,
        "0x00000000",
        { value: txValue }
      );

      // Verify fee was collected
      const fees = await gateway.accumulatedFees();
      expect(fees).to.equal(actualFee);

      // Verify agent tx count
      expect(await gateway.agentTxCount(agent.address)).to.equal(1);
    });

    it("should allow fee withdrawal to Safe multisig", async function () {
      // Fund gateway with some ETH to simulate accumulated fees
      const Receiver = await ethers.getContractFactory("EthReceiver");
      const receiver = await Receiver.deploy();
      await receiver.waitForDeployment();

      const receiverAddr = await receiver.getAddress();

      // Record + execute to generate fees
      const attestationId = ethers.keccak256(ethers.toUtf8Bytes("fork-fee-test"));
      const selector = "0x00000000";
      const riskScore = 5;

      const gatewayAddr = await gateway.getAddress();
      const network = await ethers.provider.getNetwork();
      const messageHash = ethers.solidityPackedKeccak256(
        ["bytes32", "address", "address", "bytes4", "uint8", "uint256", "address"],
        [attestationId, agent.address, receiverAddr, selector, riskScore, network.chainId, gatewayAddr]
      );
      const signature = await deployer.signMessage(ethers.getBytes(messageHash));

      await gateway.recordAttestation(
        attestationId, agent.address, receiverAddr, selector, riskScore, signature
      );

      await gateway.connect(agent).executeProtected(
        attestationId, receiverAddr, "0x00000000",
        { value: ethers.parseEther("0.01") }
      );

      const fees = await gateway.accumulatedFees();
      expect(fees).to.be.greaterThan(0);

      // Get Safe balance before
      const safeBefore = await ethers.provider.getBalance(SAFE_FEE_RECIPIENT);

      // Withdraw fees - anyone can call, goes to Safe
      await gateway.withdrawFees();

      // Verify fees arrived at Safe
      const safeAfter = await ethers.provider.getBalance(SAFE_FEE_RECIPIENT);
      expect(safeAfter - safeBefore).to.equal(fees);

      // Verify accumulated fees reset
      expect(await gateway.accumulatedFees()).to.equal(0);
    });
  });

  describe("Ownership transfer", function () {
    it("should transfer ownership to Safe multisig", async function () {
      await gateway.transferOwnership(SAFE_FEE_RECIPIENT);
      expect(await gateway.owner()).to.equal(SAFE_FEE_RECIPIENT);
    });

    it("should prevent deployer from admin actions after transfer", async function () {
      await gateway.transferOwnership(SAFE_FEE_RECIPIENT);

      await expect(
        gateway.setRiskThreshold(50)
      ).to.be.reverted;
    });
  });

  describe("Fee math edge cases", function () {
    it("should handle zero-value transactions (no fee)", async function () {
      const Receiver = await ethers.getContractFactory("EthReceiver");
      const receiver = await Receiver.deploy();
      const receiverAddr = await receiver.getAddress();

      const attestationId = ethers.keccak256(ethers.toUtf8Bytes("zero-value-test"));
      const selector = "0x00000000";
      const gatewayAddr = await gateway.getAddress();
      const network = await ethers.provider.getNetwork();
      const messageHash = ethers.solidityPackedKeccak256(
        ["bytes32", "address", "address", "bytes4", "uint8", "uint256", "address"],
        [attestationId, agent.address, receiverAddr, selector, 0, network.chainId, gatewayAddr]
      );
      const signature = await deployer.signMessage(ethers.getBytes(messageHash));

      await gateway.recordAttestation(
        attestationId, agent.address, receiverAddr, selector, 0, signature
      );

      // Zero value tx should work with no fee
      await gateway.connect(agent).executeProtected(
        attestationId, receiverAddr, "0x00000000",
        { value: 0 }
      );

      expect(await gateway.accumulatedFees()).to.equal(0);
    });

    it("should enforce minFee for medium-value transactions", async function () {
      const Receiver = await ethers.getContractFactory("EthReceiver");
      const receiver = await Receiver.deploy();
      const receiverAddr = await receiver.getAddress();

      const attestationId = ethers.keccak256(ethers.toUtf8Bytes("minfee-test"));
      const selector = "0x00000000";
      const gatewayAddr = await gateway.getAddress();
      const network = await ethers.provider.getNetwork();
      const messageHash = ethers.solidityPackedKeccak256(
        ["bytes32", "address", "address", "bytes4", "uint8", "uint256", "address"],
        [attestationId, agent.address, receiverAddr, selector, 0, network.chainId, gatewayAddr]
      );
      const signature = await deployer.signMessage(ethers.getBytes(messageHash));

      await gateway.recordAttestation(
        attestationId, agent.address, receiverAddr, selector, 0, signature
      );

      // 0.001 ETH: 5 bps = 0.00000005 ETH (50000000000 wei), which is less than
      // minFee (0.0001 ETH = 100000000000000 wei), so minFee should apply
      const txValue = ethers.parseEther("0.001");
      await gateway.connect(agent).executeProtected(
        attestationId, receiverAddr, "0x00000000",
        { value: txValue }
      );

      const minFee = ethers.parseEther("0.0001");
      expect(await gateway.accumulatedFees()).to.equal(minFee);
    });
  });
});
