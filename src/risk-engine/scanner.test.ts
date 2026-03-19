import { describe, it, expect } from "vitest";
import { scanContractSource, scanBytecode } from "./scanner.js";
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
        pragma solidity ^0.8.24;

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
