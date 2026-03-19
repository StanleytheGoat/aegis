/**
 * Aegis MCP Server
 *
 * Model Context Protocol server that provides DeFi safety tools to AI agents.
 * Any MCP-compatible agent (Claude, GPT, etc.) can connect and use these tools
 * to verify the safety of on-chain transactions before execution.
 *
 * Tools provided:
 * - scan_contract: Analyze contract source code for known exploit patterns
 * - simulate_transaction: Simulate a transaction on a forked chain
 * - check_token: Check if a token is safe to trade (anti-honeypot)
 * - assess_risk: Get a comprehensive risk assessment combining all checks
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { scanContractSource, scanBytecode } from "../risk-engine/scanner.js";
import { simulateTransaction, checkTokenSellability } from "../risk-engine/simulator.js";
import { signAttestation, generateAttestationId } from "../risk-engine/attester.js";
import type { Address, Hex } from "viem";

export function createAegisServer(): McpServer {
  const server = new McpServer({
    name: "aegis",
    version: "0.1.0",
  });

  // --- Tool: scan_contract ---
  server.tool(
    "scan_contract",
    "Analyze a smart contract's source code or bytecode for known exploit patterns, honeypot mechanics, rug-pull signals, and security vulnerabilities. Returns a risk score (0-100) and detailed findings. Use this BEFORE interacting with any unfamiliar contract.",
    {
      source: z.string().optional().describe("Solidity source code of the contract to analyze"),
      bytecode: z.string().optional().describe("Contract bytecode (hex) to analyze if source is unavailable"),
      contractAddress: z.string().optional().describe("Contract address - if provided, will attempt to fetch source from block explorer"),
      chainId: z.number().default(1).describe("Chain ID (1=Ethereum, 8453=Base, 84532=Base Sepolia)"),
    },
    async ({ source, bytecode, contractAddress, chainId }) => {
      if (!source && !bytecode && !contractAddress) {
        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              error: "Provide at least one of: source, bytecode, or contractAddress",
            }),
          }],
        };
      }

      // If we have a contract address but no source/bytecode, try to fetch it
      if (contractAddress && !source && !bytecode) {
        const fetched = await fetchContractSource(contractAddress, chainId);
        if (fetched.source) source = fetched.source;
        if (fetched.bytecode) bytecode = fetched.bytecode;
      }

      let result;
      if (source) {
        result = scanContractSource(source);
      } else if (bytecode) {
        result = scanBytecode(bytecode);
      } else {
        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              error: "Could not fetch contract source or bytecode. Provide them directly.",
            }),
          }],
        };
      }

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify(result, null, 2),
        }],
      };
    },
  );

  // --- Tool: simulate_transaction ---
  server.tool(
    "simulate_transaction",
    "Simulate a transaction on a forked chain WITHOUT actually executing it. Detects reverts, abnormal gas usage, and other red flags. Use this to preview what will happen before sending a real transaction.",
    {
      chainId: z.number().default(1).describe("Chain ID to simulate on"),
      from: z.string().describe("Sender address"),
      to: z.string().describe("Target contract address"),
      data: z.string().describe("Transaction calldata (hex)"),
      value: z.string().default("0").describe("ETH value to send (in wei)"),
    },
    async ({ chainId, from, to, data, value }) => {
      const result = await simulateTransaction({
        chainId,
        from: from as Address,
        to: to as Address,
        data: data as Hex,
        value: BigInt(value),
      });

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            ...result,
            gasUsed: result.gasUsed.toString(),
          }, null, 2),
        }],
      };
    },
  );

  // --- Tool: check_token ---
  server.tool(
    "check_token",
    "Check if a token is safe to trade. Detects honeypot mechanics (can't sell), concentrated holdings, fake ownership renouncement, and other scam indicators. Use this before swapping into any unfamiliar token.",
    {
      tokenAddress: z.string().describe("The token contract address to check"),
      chainId: z.number().default(1).describe("Chain ID (1=Ethereum, 8453=Base)"),
      holderAddress: z.string().optional().describe("Optional: address to check balance for"),
    },
    async ({ tokenAddress, chainId, holderAddress }) => {
      const holder = (holderAddress || "0x0000000000000000000000000000000000000001") as Address;

      const sellCheck = await checkTokenSellability(
        chainId,
        tokenAddress as Address,
        holder,
      );

      // Also scan the contract if we can fetch source
      const fetched = await fetchContractSource(tokenAddress, chainId);
      let scanResult = null;
      if (fetched.source) {
        scanResult = scanContractSource(fetched.source);
      } else if (fetched.bytecode) {
        scanResult = scanBytecode(fetched.bytecode);
      }

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            tokenAddress,
            chainId,
            sellability: sellCheck,
            contractScan: scanResult,
            overallAssessment: sellCheck.canSell && (!scanResult || scanResult.riskScore < 70)
              ? "LIKELY_SAFE"
              : "POTENTIALLY_DANGEROUS",
          }, null, 2),
        }],
      };
    },
  );

  // --- Tool: assess_risk ---
  server.tool(
    "assess_risk",
    "Comprehensive risk assessment combining contract scanning, transaction simulation, and token checks. This is the recommended all-in-one safety check before any DeFi interaction. Returns a go/no-go recommendation.",
    {
      action: z.enum(["swap", "approve", "transfer", "interact"]).describe("Type of action being assessed"),
      targetContract: z.string().describe("The contract being interacted with"),
      chainId: z.number().default(1).describe("Chain ID"),
      from: z.string().describe("The agent's wallet address"),
      transactionData: z.string().optional().describe("Calldata for the transaction (hex)"),
      value: z.string().default("0").describe("ETH value (in wei)"),
      tokenAddress: z.string().optional().describe("Token address if this involves a token swap"),
    },
    async ({ action, targetContract, chainId, from, transactionData, value, tokenAddress }) => {
      const checks: Record<string, any> = {};

      // 1. Scan the contract
      const fetched = await fetchContractSource(targetContract, chainId);
      if (fetched.source) {
        checks.contractScan = scanContractSource(fetched.source);
      } else if (fetched.bytecode) {
        checks.contractScan = scanBytecode(fetched.bytecode);
      }

      // 2. Simulate the transaction if we have calldata
      if (transactionData) {
        checks.simulation = await simulateTransaction({
          chainId,
          from: from as Address,
          to: targetContract as Address,
          data: transactionData as Hex,
          value: BigInt(value),
        });
        // Convert bigint for JSON serialization
        if (checks.simulation) {
          checks.simulation.gasUsed = checks.simulation.gasUsed.toString();
        }
      }

      // 3. Check token safety if relevant
      if (tokenAddress) {
        checks.tokenSafety = await checkTokenSellability(
          chainId,
          tokenAddress as Address,
          from as Address,
        );
      }

      // 4. Compute overall risk
      let overallRisk = 0;
      const risks: string[] = [];

      if (checks.contractScan) {
        overallRisk = Math.max(overallRisk, checks.contractScan.riskScore);
        if (checks.contractScan.riskScore >= 70) risks.push("contract_high_risk");
      }

      if (checks.simulation && !checks.simulation.success) {
        overallRisk = Math.max(overallRisk, 80);
        risks.push("transaction_reverts");
      }

      if (checks.simulation?.gasAnomaly) {
        overallRisk = Math.max(overallRisk, 60);
        risks.push("gas_anomaly");
      }

      if (checks.tokenSafety && !checks.tokenSafety.canSell) {
        overallRisk = Math.max(overallRisk, 90);
        risks.push("cannot_sell_token");
      }

      const decision = overallRisk >= 70 ? "BLOCK" : overallRisk >= 40 ? "WARN" : "ALLOW";

      // If not blocked, sign an attestation for on-chain verification
      let attestation: Record<string, string> | undefined;
      if (decision !== "BLOCK") {
        try {
          const selector = transactionData ? transactionData.slice(0, 10) as Hex : "0x00000000" as Hex;
          const att = await signAttestation({
            agent: from as Address,
            target: targetContract as Address,
            selector,
            riskScore: overallRisk,
          });
          attestation = {
            attestationId: att.attestationId,
            agent: att.agent,
            target: att.target,
            selector: att.selector,
            riskScore: att.riskScore.toString(),
            expiresAt: att.expiresAt.toString(),
            signature: att.signature,
          };
        } catch {
          // Attester key not configured - attestation unavailable
          // MCP-only mode still works (agent gets the risk assessment)
        }
      }

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            decision,
            overallRiskScore: overallRisk,
            riskFactors: risks,
            action,
            checks,
            attestation,
            recommendation: decision === "BLOCK"
              ? "DO NOT proceed with this transaction. High risk of fund loss."
              : decision === "WARN"
              ? "Proceed with caution. Some risk indicators detected."
              : "Transaction appears safe. Proceed normally.",
          }, null, 2),
        }],
      };
    },
  );

  // --- Resource: safety report ---
  server.resource(
    "aegis-info",
    "aegis://info",
    async () => ({
      contents: [{
        uri: "aegis://info",
        mimeType: "text/plain",
        text: [
          "Aegis - A Safety Layer for Autonomous DeFi Agents",
          "",
          "Available tools:",
          "- scan_contract: Analyze contract source/bytecode for exploit patterns",
          "- simulate_transaction: Simulate a tx on a forked chain",
          "- check_token: Anti-honeypot and token safety checks",
          "- assess_risk: Comprehensive all-in-one risk assessment",
          "",
          "Supported chains: Ethereum (1), Base (8453), Base Sepolia (84532)",
          "",
          "Usage: Call assess_risk before any DeFi interaction for maximum protection.",
        ].join("\n"),
      }],
    }),
  );

  return server;
}

/**
 * Fetch contract source code from Etherscan/Basescan.
 * Uses free API endpoints.
 */
async function fetchContractSource(
  address: string,
  chainId: number,
): Promise<{ source?: string; bytecode?: string }> {
  const explorerApis: Record<number, string> = {
    1: "https://api.etherscan.io/api",
    8453: "https://api.basescan.org/api",
    84532: "https://api-sepolia.basescan.org/api",
  };

  const apiBase = explorerApis[chainId];
  if (!apiBase) return {};

  const apiKey = process.env.ETHERSCAN_API_KEY || "";

  try {
    // Try to get verified source
    const sourceUrl = `${apiBase}?module=contract&action=getsourcecode&address=${address}&apikey=${apiKey}`;
    const sourceRes = await fetch(sourceUrl);
    const sourceData = await sourceRes.json();

    if (sourceData.result?.[0]?.SourceCode) {
      const src = sourceData.result[0].SourceCode;
      if (src && src !== "") {
        return { source: src };
      }
    }

    // Fallback: get bytecode
    const codeUrl = `${apiBase}?module=proxy&action=eth_getCode&address=${address}&tag=latest&apikey=${apiKey}`;
    const codeRes = await fetch(codeUrl);
    const codeData = await codeRes.json();

    if (codeData.result && codeData.result !== "0x") {
      return { bytecode: codeData.result };
    }
  } catch {
    // Silently fail - caller will handle missing data
  }

  return {};
}
