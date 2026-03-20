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
 * - trace_transaction: Trace all internal calls and scan every contract touched
 * - search_solodit: Search 50K+ real-world audit findings from top security firms
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { scanContractSource, scanBytecode } from "../risk-engine/scanner.js";
import {
  simulateTransaction,
  simulateWithTrace,
  checkTokenSellability,
  fetchContractSource,
} from "../risk-engine/simulator.js";
import { traceTransaction, filterScanTargets, isWellKnown } from "../risk-engine/tracer.js";
import { signAttestation, signHookAttestation, generateAttestationId } from "../risk-engine/attester.js";
import { enrichWithSolodit, querySolodit } from "../risk-engine/solodit.js";
import type { Address, Hex } from "viem";

const evmAddress = z.string().regex(/^0x[a-fA-F0-9]{40}$/, "Must be a valid EVM address (0x + 40 hex chars)");

export function createAegisServer(): McpServer {
  const server = new McpServer({
    name: "aegis",
    version: "0.5.0",
  });

  // --- Tool: scan_contract ---
  server.tool(
    "scan_contract",
    "Analyze a smart contract's source code or bytecode for known exploit patterns, honeypot mechanics, rug-pull signals, and security vulnerabilities. Returns a risk score (0-100) and detailed findings. Use this BEFORE interacting with any unfamiliar contract.",
    {
      source: z.string().optional().describe("Solidity source code of the contract to analyze"),
      bytecode: z.string().optional().describe("Contract bytecode (hex) to analyze if source is unavailable"),
      contractAddress: evmAddress.optional().describe("Contract address - if provided, will attempt to fetch source from block explorer"),
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
      from: evmAddress.describe("Sender address"),
      to: evmAddress.describe("Target contract address"),
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
      tokenAddress: evmAddress.describe("The token contract address to check"),
      chainId: z.number().default(1).describe("Chain ID (1=Ethereum, 8453=Base)"),
      holderAddress: evmAddress.optional().describe("Optional: address to check balance for"),
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
      targetContract: evmAddress.describe("The contract being interacted with"),
      chainId: z.number().default(1).describe("Chain ID"),
      from: evmAddress.describe("The agent's wallet address"),
      transactionData: z.string().optional().describe("Calldata for the transaction (hex)"),
      value: z.string().default("0").describe("ETH value (in wei)"),
      tokenAddress: evmAddress.optional().describe("Token address if this involves a token swap"),
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

      // 2. Simulate the transaction with trace analysis if we have calldata
      if (transactionData) {
        checks.simulation = await simulateWithTrace({
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

      // Include trace-level risk if trace analysis ran
      if (checks.simulation?.trace) {
        const traceRisk = checks.simulation.trace.maxRiskScore;
        overallRisk = Math.max(overallRisk, traceRisk);
        if (traceRisk >= 70) risks.push("traced_contract_high_risk");
        if (checks.simulation.riskIndicators?.includes("delegatecall_in_trace")) {
          risks.push("delegatecall_in_trace");
        }
      }

      const decision = overallRisk >= 70 ? "BLOCK" : overallRisk >= 40 ? "WARN" : "ALLOW";

      // If not blocked, sign attestations for on-chain verification
      let attestation: Record<string, string> | undefined;
      let hookAttestation: Record<string, string> | undefined;
      if (decision !== "BLOCK") {
        try {
          const selector = transactionData ? transactionData.slice(0, 10) as Hex : "0x00000000" as Hex;
          // Gateway attestation
          const gatewayAddress = process.env.AEGIS_GATEWAY_ADDRESS || "0x62c64c063ddbcd438f924184c03d8dad45230fa3";
          const att = await signAttestation({
            agent: from as Address,
            target: targetContract as Address,
            selector,
            riskScore: overallRisk,
            chainId,
            contractAddress: gatewayAddress as Address,
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
          // Hook attestation (for Uniswap v4 hook-protected pools)
          const hookContractAddress = process.env.AEGIS_HOOK_ADDRESS || "0xaEE532d9707b056f4d0939b91D4031298F7340C0";
          const hookAtt = await signHookAttestation({
            agent: from as Address,
            target: targetContract as Address,
            selector,
            riskScore: overallRisk,
            chainId,
            contractAddress: hookContractAddress as Address,
          });
          hookAttestation = {
            attestationId: hookAtt.attestationId,
            agent: hookAtt.agent,
            riskScore: hookAtt.riskScore.toString(),
            expiresAt: hookAtt.expiresAt.toString(),
            signature: hookAtt.signature,
          };
        } catch {
          // Attester key not configured - attestations unavailable
          // MCP-only mode still works (agent gets the risk assessment)
        }
      }

      // Build trace summary for the output
      let traceSummary: Record<string, any> | undefined;
      if (checks.simulation?.trace) {
        const t = checks.simulation.trace;
        traceSummary = {
          fullTrace: t.fullTrace,
          totalCalls: t.totalCalls,
          uniqueContracts: t.uniqueContracts,
          scannedContracts: t.scannedContracts,
          maxRiskScore: t.maxRiskScore,
          maxRiskLevel: t.maxRiskLevel,
          contracts: t.contracts.map((c: any) => ({
            address: c.address,
            wellKnown: c.wellKnown,
            riskScore: c.scanResult?.riskScore ?? null,
            riskLevel: c.scanResult?.riskLevel ?? (c.wellKnown ? "safe" : "unknown"),
            callTypes: c.callTypes,
            maxDepth: c.maxDepth,
            findingCount: c.scanResult?.findings?.length ?? 0,
          })),
          fallbackReason: t.fallbackReason,
        };
      }

      // 5. Enrich with Solodit cross-references if we have findings
      let soloditCrossRef: any = undefined;
      const allFindings = checks.contractScan?.findings || [];
      if (allFindings.length > 0) {
        try {
          const enriched = await enrichWithSolodit(allFindings);
          if (enriched.crossReferenceCount > 0) {
            soloditCrossRef = {
              matchCount: enriched.crossReferenceCount,
              queries: enriched.soloditMatches.map((m) => ({
                query: m.query,
                resultCount: m.totalResults,
                topFindings: m.findings.map((f) => ({
                  title: f.title,
                  severity: f.severity,
                  url: f.url,
                })),
              })),
            };
          }
        } catch {
          // Solodit enrichment is best-effort
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
            traceSummary,
            soloditCrossRef,
            attestation,
            hookAttestation,
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

  // --- Tool: trace_transaction ---
  server.tool(
    "trace_transaction",
    "Trace a transaction to discover every contract it touches internally. Uses debug_traceCall to extract the full call tree, then scans each unique contract for exploit patterns. Use this for deep inspection of multi-contract interactions (e.g., swaps routing through many pools).",
    {
      chainId: z.number().default(1).describe("Chain ID to trace on"),
      from: evmAddress.describe("Sender address"),
      to: evmAddress.describe("Target contract address"),
      data: z.string().describe("Transaction calldata (hex)"),
      value: z.string().default("0").describe("ETH value to send (in wei)"),
    },
    async ({ chainId, from, to, data, value }) => {
      // Run the trace
      const traceResult = await traceTransaction({
        chainId,
        from: from as Address,
        to: to as Address,
        data: data as Hex,
        value: BigInt(value),
      });

      // Scan each non-well-known contract
      const scanTargets = filterScanTargets(traceResult.uniqueAddresses);
      const contractResults: Array<{
        address: string;
        wellKnown: boolean;
        riskScore: number | null;
        riskLevel: string;
        findings: number;
        callTypes: string[];
      }> = [];

      // Build call metadata
      const callMeta = new Map<string, { callTypes: Set<string>; maxDepth: number }>();
      for (const call of traceResult.calls) {
        const lower = call.address.toLowerCase();
        const existing = callMeta.get(lower);
        if (existing) {
          existing.callTypes.add(call.type);
          existing.maxDepth = Math.max(existing.maxDepth, call.depth);
        } else {
          callMeta.set(lower, { callTypes: new Set([call.type]), maxDepth: call.depth });
        }
      }

      // Add well-known contracts
      for (const addr of traceResult.uniqueAddresses) {
        if (isWellKnown(addr)) {
          const meta = callMeta.get(addr.toLowerCase());
          contractResults.push({
            address: addr,
            wellKnown: true,
            riskScore: 0,
            riskLevel: "safe",
            findings: 0,
            callTypes: meta ? Array.from(meta.callTypes) : ["CALL"],
          });
        }
      }

      // Scan non-well-known contracts with rate limiting
      let maxRisk = 0;
      for (let i = 0; i < scanTargets.length; i++) {
        const addr = scanTargets[i];
        const meta = callMeta.get(addr.toLowerCase());
        let riskScore: number | null = null;
        let riskLevel = "unknown";
        let findings = 0;

        try {
          const fetched = await fetchContractSource(addr, chainId);
          if (fetched.source) {
            const scan = scanContractSource(fetched.source);
            riskScore = scan.riskScore;
            riskLevel = scan.riskLevel;
            findings = scan.findings.length;
          } else if (fetched.bytecode) {
            const scan = scanBytecode(fetched.bytecode);
            riskScore = scan.riskScore;
            riskLevel = scan.riskLevel;
            findings = scan.findings.length;
          }
        } catch {
          // fetch failed
        }

        if (riskScore !== null && riskScore > maxRisk) {
          maxRisk = riskScore;
        }

        contractResults.push({
          address: addr,
          wellKnown: false,
          riskScore,
          riskLevel,
          findings,
          callTypes: meta ? Array.from(meta.callTypes) : ["CALL"],
        });

        // Rate limit
        if (i < scanTargets.length - 1) {
          await new Promise((r) => setTimeout(r, 150));
        }
      }

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            fullTrace: traceResult.fullTrace,
            fallbackReason: traceResult.fallbackReason,
            totalCalls: traceResult.calls.length,
            uniqueContracts: traceResult.uniqueAddresses.length,
            scannedContracts: contractResults.filter((c) => c.riskScore !== null).length,
            maxRiskScore: maxRisk,
            contracts: contractResults,
            rawCalls: traceResult.calls.slice(0, 50), // cap to avoid huge payloads
          }, null, 2),
        }],
      };
    },
  );

  // --- Tool: search_solodit ---
  server.tool(
    "search_solodit",
    "Search Solodit's database of 50,000+ real-world smart contract audit findings from top firms (Cyfrin, Sherlock, Code4rena, Trail of Bits, OpenZeppelin). Cross-reference vulnerability types, protocols, or attack patterns against known audit results.",
    {
      keywords: z.string().describe("Search keywords (e.g., 'reentrancy', 'flash loan oracle', 'Uniswap')"),
      impact: z.array(z.string()).default(["HIGH", "MEDIUM"]).describe("Severity filter: HIGH, MEDIUM, LOW, GAS"),
      pageSize: z.number().default(10).describe("Number of results to return (max 20)"),
    },
    async ({ keywords, impact, pageSize }) => {
      try {
        const result = await querySolodit(keywords, { impact, pageSize: Math.min(pageSize, 20) });
        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify(result, null, 2),
          }],
        };
      } catch (err: any) {
        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              error: `Solodit search failed: ${err.message}`,
              hint: "Ensure SOLODIT_API_KEY is set in environment",
            }),
          }],
        };
      }
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
          "- assess_risk: Comprehensive all-in-one risk assessment (now with trace analysis)",
          "- trace_transaction: Trace all internal calls and scan every contract touched",
          "- search_solodit: Search 50K+ real-world audit findings from top security firms",
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

// fetchContractSource is imported from ../risk-engine/simulator.js
