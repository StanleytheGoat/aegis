const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("AegisGateway", function () {
  let gateway;
  let gatewayAddress;
  let owner;
  let attester;
  let agent;
  let target;
  let feeRecipient;
  let chainId;

  // Helper to create signature hash matching the contract's format
  // Includes chainId and contract address to prevent cross-chain replay
  async function signAttestation(signer, attestationId, agentAddr, targetAddr, selector, riskScore) {
    const messageHash = ethers.solidityPackedKeccak256(
      ["bytes32", "address", "address", "bytes4", "uint8", "uint256", "address"],
      [attestationId, agentAddr, targetAddr, selector, riskScore, chainId, gatewayAddress]
    );
    return signer.signMessage(ethers.getBytes(messageHash));
  }

  beforeEach(async function () {
    [owner, attester, agent, target, feeRecipient] = await ethers.getSigners();

    const AegisGateway = await ethers.getContractFactory("AegisGateway");
    gateway = await AegisGateway.deploy(attester.address, feeRecipient.address);
    await gateway.waitForDeployment();
    gatewayAddress = await gateway.getAddress();

    const network = await ethers.provider.getNetwork();
    chainId = network.chainId;
  });

  describe("Deployment", function () {
    it("should set the correct attester", async function () {
      expect(await gateway.attester()).to.equal(attester.address);
    });

    it("should set the correct owner", async function () {
      expect(await gateway.owner()).to.equal(owner.address);
    });

    it("should have default risk threshold of 70", async function () {
      expect(await gateway.riskThreshold()).to.equal(70);
    });

    it("should have default fee of 5 bps", async function () {
      expect(await gateway.feeBps()).to.equal(5);
    });

    it("should reject zero address attester", async function () {
      const AegisGateway = await ethers.getContractFactory("AegisGateway");
      await expect(
        AegisGateway.deploy(ethers.ZeroAddress, feeRecipient.address)
      ).to.be.revertedWith("Invalid attester");
    });
  });

  describe("Attestation Recording", function () {
    it("should record a valid attestation", async function () {
      const attestationId = ethers.id("test-attestation-1");
      const riskScore = 25;
      const selector = "0xa9059cbb"; // transfer(address,uint256)

      const signature = await signAttestation(
        attester, attestationId, agent.address, target.address, selector, riskScore
      );

      await gateway.recordAttestation(
        attestationId, agent.address, target.address, selector, riskScore, signature
      );

      const att = await gateway.attestations(attestationId);
      expect(att.agent).to.equal(agent.address);
      expect(att.riskScore).to.equal(riskScore);
      expect(att.used).to.equal(false);
    });

    it("should reject attestation with wrong attester", async function () {
      const attestationId = ethers.id("test-attestation-2");
      const riskScore = 25;
      const selector = "0xa9059cbb";

      // Sign as the wrong signer (agent instead of attester)
      const signature = await signAttestation(
        agent, attestationId, agent.address, target.address, selector, riskScore
      );

      await expect(
        gateway.recordAttestation(
          attestationId, agent.address, target.address, selector, riskScore, signature
        )
      ).to.be.revertedWith("Invalid attester");
    });

    it("should reject duplicate attestation IDs", async function () {
      const attestationId = ethers.id("test-attestation-3");
      const riskScore = 25;
      const selector = "0xa9059cbb";

      const signature = await signAttestation(
        attester, attestationId, agent.address, target.address, selector, riskScore
      );

      await gateway.recordAttestation(
        attestationId, agent.address, target.address, selector, riskScore, signature
      );

      await expect(
        gateway.recordAttestation(
          attestationId, agent.address, target.address, selector, riskScore, signature
        )
      ).to.be.revertedWith("Attestation exists");
    });

    it("should reject zero address agent", async function () {
      const attestationId = ethers.id("test-zero-agent");
      const selector = "0xa9059cbb";

      const signature = await signAttestation(
        attester, attestationId, ethers.ZeroAddress, target.address, selector, 10
      );

      await expect(
        gateway.recordAttestation(
          attestationId, ethers.ZeroAddress, target.address, selector, 10, signature
        )
      ).to.be.revertedWith("Invalid agent");
    });
  });

  describe("wouldAllow", function () {
    it("should return false for non-existent attestation", async function () {
      const [allowed, , reason] = await gateway.wouldAllow(ethers.id("nonexistent"));
      expect(allowed).to.equal(false);
      expect(reason).to.equal("No attestation found");
    });
  });

  describe("Admin Functions", function () {
    it("should allow owner to update risk threshold", async function () {
      await gateway.setRiskThreshold(50);
      expect(await gateway.riskThreshold()).to.equal(50);
    });

    it("should reject non-owner setting threshold", async function () {
      await expect(
        gateway.connect(agent).setRiskThreshold(50)
      ).to.be.reverted;
    });

    it("should allow owner to update fee", async function () {
      await gateway.setFeeBps(10);
      expect(await gateway.feeBps()).to.equal(10);
    });

    it("should reject fee above 1%", async function () {
      await expect(
        gateway.setFeeBps(101)
      ).to.be.revertedWith("Fee too high");
    });

    it("should allow owner to update attester", async function () {
      await gateway.setAttester(agent.address);
      expect(await gateway.attester()).to.equal(agent.address);
    });

    it("should reject zero address attester update", async function () {
      await expect(
        gateway.setAttester(ethers.ZeroAddress)
      ).to.be.revertedWith("Invalid attester");
    });
  });

  describe("Fee Recipient", function () {
    it("should set immutable feeRecipient on deploy", async function () {
      expect(await gateway.feeRecipient()).to.equal(feeRecipient.address);
    });

    it("should reject zero address feeRecipient", async function () {
      const AegisGateway = await ethers.getContractFactory("AegisGateway");
      await expect(
        AegisGateway.deploy(attester.address, ethers.ZeroAddress)
      ).to.be.revertedWith("Invalid fee recipient");
    });

    it("should allow anyone to call withdrawFees", async function () {
      await expect(
        gateway.connect(agent).withdrawFees()
      ).to.be.revertedWith("No fees to withdraw");
    });
  });
});
