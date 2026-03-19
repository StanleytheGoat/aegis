const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("AegisGateway", function () {
  let gateway;
  let owner;
  let attester;
  let agent;
  let target;

  beforeEach(async function () {
    [owner, attester, agent, target] = await ethers.getSigners();

    const AegisGateway = await ethers.getContractFactory("AegisGateway");
    gateway = await AegisGateway.deploy(attester.address);
    await gateway.waitForDeployment();
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
  });

  describe("Attestation Recording", function () {
    it("should record a valid attestation", async function () {
      const attestationId = ethers.id("test-attestation-1");
      const riskScore = 25;
      const selector = "0xa9059cbb"; // transfer(address,uint256)

      // Create the message hash that the attester would sign
      const messageHash = ethers.solidityPackedKeccak256(
        ["bytes32", "address", "address", "bytes4", "uint8"],
        [attestationId, agent.address, target.address, selector, riskScore]
      );

      // Sign as the attester
      const signature = await attester.signMessage(ethers.getBytes(messageHash));

      await gateway.recordAttestation(
        attestationId,
        agent.address,
        target.address,
        selector,
        riskScore,
        signature
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

      const messageHash = ethers.solidityPackedKeccak256(
        ["bytes32", "address", "address", "bytes4", "uint8"],
        [attestationId, agent.address, target.address, selector, riskScore]
      );

      // Sign as the wrong signer (agent instead of attester)
      const signature = await agent.signMessage(ethers.getBytes(messageHash));

      await expect(
        gateway.recordAttestation(
          attestationId,
          agent.address,
          target.address,
          selector,
          riskScore,
          signature
        )
      ).to.be.revertedWith("Invalid attester");
    });

    it("should reject duplicate attestation IDs", async function () {
      const attestationId = ethers.id("test-attestation-3");
      const riskScore = 25;
      const selector = "0xa9059cbb";

      const messageHash = ethers.solidityPackedKeccak256(
        ["bytes32", "address", "address", "bytes4", "uint8"],
        [attestationId, agent.address, target.address, selector, riskScore]
      );

      const signature = await attester.signMessage(ethers.getBytes(messageHash));

      await gateway.recordAttestation(
        attestationId, agent.address, target.address, selector, riskScore, signature
      );

      await expect(
        gateway.recordAttestation(
          attestationId, agent.address, target.address, selector, riskScore, signature
        )
      ).to.be.revertedWith("Attestation exists");
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
  });
});
