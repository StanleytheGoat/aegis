import { describe, it, expect } from "vitest";
import { scanContractSource, scanBytecode } from "./scanner.js";
import { EXPLOIT_PATTERNS } from "./patterns.js";
import * as fs from "node:fs";
import * as path from "node:path";

describe("Risk Engine - Scanner", () => {
  describe("scanContractSource", () => {
    it("should detect all honeypot patterns in MockHoneypot", () => {
      const source = fs.readFileSync(
        path.join(import.meta.dirname, "../../contracts/src/MockHoneypot.sol"),
        "utf-8",
      );
      const result = scanContractSource(source);

      expect(result.riskScore).toBeGreaterThanOrEqual(80);
      expect(result.riskLevel).toBe("critical");
      expect(result.recommendation).toBe("avoid");
      expect(result.findings.length).toBeGreaterThanOrEqual(4);

      const patternIds = result.findings.map((f) => f.patternId);
      expect(patternIds).toContain("honeypot-sell-tax");
      expect(patternIds).toContain("honeypot-sell-pause");
      expect(patternIds).toContain("honeypot-fake-renounce");
      expect(patternIds).toContain("honeypot-max-sell");
      expect(patternIds).toContain("hidden-admin-functions");
    });

    it("should return safe for a clean ERC20", () => {
      const cleanSource = `
        // SPDX-License-Identifier: MIT
        pragma solidity 0.8.19;

        import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

        contract CleanToken is ERC20 {
            constructor() ERC20("Clean", "CLN") {
                _mint(msg.sender, 1000000 * 1e18);
            }
        }
      `;
      const result = scanContractSource(cleanSource);

      expect(result.riskScore).toBeLessThan(40);
      expect(result.recommendation).toBe("proceed");
      expect(result.findings.length).toBe(0);
    });

    it("should detect reentrancy vulnerability", () => {
      const source = `
        function withdraw() external {
            uint256 amount = balances[msg.sender];
            (bool success,) = msg.sender.call{value: amount}("");
            require(success);
            balances[msg.sender] = 0; // state update after external call
        }
      `;
      const result = scanContractSource(source);

      const patternIds = result.findings.map((f) => f.patternId);
      expect(patternIds).toContain("reentrancy-external-call-before-state");
    });

    it("should detect blacklist mechanism", () => {
      const source = `
        mapping(address => bool) public isBlacklisted;

        function transfer(address to, uint256 amount) external {
            require(!isBlacklisted[msg.sender], "Blacklisted");
            // ...
        }
      `;
      const result = scanContractSource(source);

      const patternIds = result.findings.map((f) => f.patternId);
      expect(patternIds).toContain("blacklist-mechanism");
    });

    it("should detect proxy pattern in bytecode", () => {
      const source = `
        function _delegate(address implementation) internal {
            assembly {
                calldatacopy(0, 0, calldatasize())
                let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)
            }
        }
      `;
      const result = scanContractSource(source);

      const patternIds = result.findings.map((f) => f.patternId);
      expect(patternIds).toContain("proxy-pattern");
    });

    it("should handle empty source", () => {
      const result = scanContractSource("");
      expect(result.riskScore).toBe(0);
      expect(result.riskLevel).toBe("safe");
      expect(result.recommendation).toBe("proceed");
      expect(result.findings).toEqual([]);
    });

    it("should produce valid scan result structure", () => {
      const result = scanContractSource("some contract code");

      expect(result).toHaveProperty("riskScore");
      expect(result).toHaveProperty("riskLevel");
      expect(result).toHaveProperty("findings");
      expect(result).toHaveProperty("summary");
      expect(result).toHaveProperty("recommendation");
      expect(result).toHaveProperty("scannedAt");

      expect(typeof result.riskScore).toBe("number");
      expect(result.riskScore).toBeGreaterThanOrEqual(0);
      expect(result.riskScore).toBeLessThanOrEqual(100);
    });

    it("should not produce duplicate findings for the same pattern", () => {
      const source = `
        uint256 public sellTaxBps = 9900;
        uint256 public sellTax = 99;
        uint256 public _sellFee = 99;
      `;
      const result = scanContractSource(source);

      const sellTaxFindings = result.findings.filter(
        (f) => f.patternId === "honeypot-sell-tax",
      );
      expect(sellTaxFindings.length).toBe(1);
    });

    it("should cap risk score at 100", () => {
      // Source that matches many critical patterns
      const source = fs.readFileSync(
        path.join(import.meta.dirname, "../../contracts/src/MockHoneypot.sol"),
        "utf-8",
      );
      const result = scanContractSource(source);
      expect(result.riskScore).toBeLessThanOrEqual(100);
    });
  });

  describe("flash loan patterns", () => {
    it("should detect flash loan oracle manipulation", () => {
      const source = `
        function executeOperation(uint256 amount) external {
          IFlashLoan(lender).flashLoan(amount);
          uint256 price = pair.getReserves();
          // manipulate and profit
        }
      `;
      const result = scanContractSource(source);
      const patternIds = result.findings.map((f) => f.patternId);
      expect(patternIds).toContain("flash-loan-oracle-manipulation");
    });

    it("should detect flash loan governance attack", () => {
      const source = `
        function attack() external {
          IFlashLoan(lender).flashLoan(1000000e18);
          governor.castVote(proposalId, 1);
        }
      `;
      const result = scanContractSource(source);
      const patternIds = result.findings.map((f) => f.patternId);
      expect(patternIds).toContain("flash-loan-governance");
    });
  });

  describe("governance patterns", () => {
    it("should detect emergency execute without timelock", () => {
      const source = `
        function emergencyWithdraw(address target) external onlyOwner {
          target.call{value: address(this).balance}("");
        }
      `;
      const result = scanContractSource(source);
      const patternIds = result.findings.map((f) => f.patternId);
      expect(patternIds).toContain("governance-emergency-bypass");
    });

    it("should detect timelock admin takeover", () => {
      const source = `
        function setAdmin(address newAdmin) external {
          setPendingAdmin(newAdmin);
        }
      `;
      const result = scanContractSource(source);
      const patternIds = result.findings.map((f) => f.patternId);
      expect(patternIds).toContain("governance-timelock-takeover");
    });
  });

  describe("cross-chain & bridge patterns", () => {
    it("should detect bridge validator compromise risk", () => {
      const source = `
        uint256 public threshold = 2;
        function processWithdrawal(bytes[] calldata signatures) external {
          require(signatures.length >= 2, "insufficient signatures");
        }
      `;
      const result = scanContractSource(source);
      const patternIds = result.findings.map((f) => f.patternId);
      expect(patternIds).toContain("bridge-validator-compromise");
    });
  });

  describe("NFT patterns", () => {
    it("should detect NFT metadata tampering", () => {
      const source = `
        function setBaseURI(string memory newURI) external onlyOwner {
          _baseURI = newURI;
        }
      `;
      const result = scanContractSource(source);
      const patternIds = result.findings.map((f) => f.patternId);
      expect(patternIds).toContain("nft-metadata-tamper");
    });
  });

  describe("solidity/EVM patterns", () => {
    it("should detect floating pragma", () => {
      const source = `
        pragma solidity ^0.8.20;
        contract Foo {}
      `;
      const result = scanContractSource(source);
      const patternIds = result.findings.map((f) => f.patternId);
      expect(patternIds).toContain("evm-floating-pragma");
    });

    it("should detect deprecated functions", () => {
      const source = `
        function destroy() external {
          suicide(msg.sender);
        }
      `;
      const result = scanContractSource(source);
      const patternIds = result.findings.map((f) => f.patternId);
      expect(patternIds).toContain("evm-deprecated-functions");
    });

    it("should detect typographical operator error", () => {
      const source = `
        function update(uint256 amount) external {
          total =+ amount;
        }
      `;
      const result = scanContractSource(source);
      const patternIds = result.findings.map((f) => f.patternId);
      expect(patternIds).toContain("evm-typo-operator");
    });
  });

  describe("external interaction patterns", () => {
    it("should detect arbitrary external call", () => {
      const source = `
        function execute(address target, bytes memory data) external onlyOwner {
          target.call{value: msg.value}(data);
        }
      `;
      const result = scanContractSource(source);
      const patternIds = result.findings.map((f) => f.patternId);
      expect(patternIds).toContain("ext-arbitrary-call");
    });
  });

  describe("staking patterns", () => {
    it("should detect staking withdrawal delay", () => {
      const source = `
        uint256 public cooldownPeriod = 7 days;
        function unstake() external {
          require(block.timestamp >= unlockTime[msg.sender], "cooldown");
        }
      `;
      const result = scanContractSource(source);
      const patternIds = result.findings.map((f) => f.patternId);
      expect(patternIds).toContain("staking-withdrawal-delay");
    });
  });

  describe("novel attack patterns", () => {
    it("should detect transient storage usage", () => {
      const source = `
        function lock() internal {
          assembly {
            tstore(0x00, 1)
          }
        }
      `;
      const result = scanContractSource(source);
      const patternIds = result.findings.map((f) => f.patternId);
      expect(patternIds).toContain("novel-transient-storage-reentrancy");
    });
  });

  describe("economic patterns", () => {
    it("should detect bonding curve manipulation risk", () => {
      const source = `
        BondingCurve public curve;
        function buy(uint256 amount) external payable {
          uint256 price = curvePrice * supply;
        }
      `;
      const result = scanContractSource(source);
      const patternIds = result.findings.map((f) => f.patternId);
      expect(patternIds).toContain("economic-bonding-curve");
    });

    it("should detect griefing attack surface", () => {
      const source = `
        address public highestBidder;
        function bid() external payable {
          require(msg.value > currentBid);
          highestBidder = msg.sender;
        }
      `;
      const result = scanContractSource(source);
      const patternIds = result.findings.map((f) => f.patternId);
      expect(patternIds).toContain("economic-griefing");
    });
  });

  describe("permit & approval patterns", () => {
    it("should detect Permit2 over-permissioning", () => {
      const source = `
        IAllowanceTransfer public permit2;
        function depositWithPermit(uint256 amount) external {
          permit2.transferFrom(msg.sender, address(this), amount, token);
        }
      `;
      const result = scanContractSource(source);
      const patternIds = result.findings.map((f) => f.patternId);
      expect(patternIds).toContain("permit2-over-permission");
    });
  });

  describe("lending patterns", () => {
    it("should detect bad debt accumulation risk", () => {
      const source = `
        uint256 public badDebt;
        function liquidate(address user) external {
          if (collateral < debt) {
            badDebt += debt - collateral;
          }
        }
      `;
      const result = scanContractSource(source);
      const patternIds = result.findings.map((f) => f.patternId);
      expect(patternIds).toContain("lending-bad-debt");
    });
  });

  describe("pattern count", () => {
    it("should have at least 150 patterns defined", () => {
      expect(EXPLOIT_PATTERNS.length).toBeGreaterThanOrEqual(150);
    });

    it("should have unique pattern IDs", () => {
      const ids = EXPLOIT_PATTERNS.map((p) => p.id);
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(ids.length);
    });
  });

  describe("scanBytecode", () => {
    it("should detect EIP-1167 minimal proxy", () => {
      const bytecode = "0x363d3d373d3d3d363d73bebebebebebebebebebebebebebebebebebebebe5af43d82803e903d91602b57fd5bf3";
      const result = scanBytecode(bytecode);

      const patternIds = result.findings.map((f) => f.patternId);
      expect(patternIds).toContain("proxy-pattern");
    });

    it("should return safe for clean bytecode", () => {
      const bytecode = "0x6080604052600436106100";
      const result = scanBytecode(bytecode);
      expect(result.riskScore).toBe(0);
      expect(result.recommendation).toBe("proceed");
    });

    it("should handle 0x prefix and case insensitivity", () => {
      const lower = "0x363d3d373d3d3d363d73aaaa";
      const upper = "363D3D373D3D3D363D73AAAA";
      const r1 = scanBytecode(lower);
      const r2 = scanBytecode(upper);
      expect(r1.riskScore).toBe(r2.riskScore);
    });
  });
});
