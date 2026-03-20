#!/usr/bin/env tsx

/**
 * Aegis Demo -- Live Swap Protection on Base Mainnet
 *
 * Demonstrates a real end-to-end flow of Aegis protecting a Uniswap v4 swap
 * on Base mainnet. The script:
 *
 * 1. Scans a legitimate token contract (USDC on Base) and shows ALLOW
 * 2. Scans a known sketchy/unverified contract and shows BLOCK
 * 3. Demonstrates attestation generation for approved transactions
 *
 * Run: npx tsx demo/live-swap-demo.ts
 */

import { scanContractSource, scanBytecode, type ScanResult } from "../src/risk-engine/scanner.js";
import { checkTokenSellability } from "../src/risk-engine/simulator.js";
import { signAttestation, generateAttestationId } from "../src/risk-engine/attester.js";
import type { Address, Hex } from "viem";
import * as fs from "node:fs";
import * as path from "node:path";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const BASE_CHAIN_ID = 8453;
const BASE_RPC = "https://mainnet.base.org";
const ETHERSCAN_API_KEY = process.env.ETHERSCAN_API_KEY || "";

// Real tokens on Base mainnet
const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const WETH_BASE = "0x4200000000000000000000000000000000000006";

// Simulated malicious contract address (for display purposes).
// In the demo we feed the MockHoneypot source directly, as if this
// contract's source was fetched from a block explorer.
const HONEYPOT_CONTRACT = "0xDeadBeefCafe00000000000000000000BadF00d1";

// Simulated agent wallet
const AGENT_WALLET = "0x1234567890abcdef1234567890abcdef12345678" as Address;

// Swap function selector: exactInputSingle on Uniswap
const SWAP_SELECTOR = "0x04e45aaf" as Hex;

// ---------------------------------------------------------------------------
// ANSI Colors
// ---------------------------------------------------------------------------

const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const CYAN = "\x1b[36m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const RESET = "\x1b[0m";

// ---------------------------------------------------------------------------
// Display Helpers
// ---------------------------------------------------------------------------

function printHeader() {
  console.log(`
${CYAN}${BOLD}+-----------------------------------------------------------+
|                                                           |
|   AEGIS -- DeFi Safety Layer for AI Agents                |
|                                                           |
|   Live Demo: Uniswap v4 Swap Protection on Base           |
|                                                           |
+-----------------------------------------------------------+${RESET}
`);
}

function printDivider(label?: string) {
  if (label) {
    const pad = 56 - label.length;
    const left = Math.floor(pad / 2);
    const right = pad - left;
    console.log(`\n${DIM}${"-".repeat(left)} ${label} ${"-".repeat(right)}${RESET}\n`);
  } else {
    console.log(`\n${DIM}${"-".repeat(60)}${RESET}\n`);
  }
}

function printRiskMeter(score: number): string {
  const filled = Math.round(score / 5);
  const empty = 20 - filled;
  const color = score >= 70 ? RED : score >= 40 ? YELLOW : GREEN;
  return `${color}[${"#".repeat(filled)}${".".repeat(empty)}] ${score}/100${RESET}`;
}

function printSeverityBadge(severity: string): string {
  switch (severity) {
    case "critical": return `${RED}${BOLD}[CRITICAL]${RESET}`;
    case "high":     return `${RED}[HIGH]${RESET}`;
    case "medium":   return `${YELLOW}[MEDIUM]${RESET}`;
    case "low":      return `${DIM}[LOW]${RESET}`;
    default:         return `${DIM}[INFO]${RESET}`;
  }
}

function printDecision(decision: string) {
  switch (decision) {
    case "ALLOW":
      console.log(`  ${GREEN}${BOLD}[ALLOW]${RESET} Transaction appears safe. Proceed normally.`);
      break;
    case "WARN":
      console.log(`  ${YELLOW}${BOLD}[WARN]${RESET} Proceed with caution. Some risk indicators detected.`);
      break;
    case "BLOCK":
      console.log(`  ${RED}${BOLD}[BLOCK]${RESET} DO NOT proceed. High risk of fund loss.`);
      break;
  }
}

// ---------------------------------------------------------------------------
// Contract Source Fetching (duplicated from server.ts for standalone use)
// ---------------------------------------------------------------------------

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

  const apiKey = ETHERSCAN_API_KEY;

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
    // Silently fail
  }

  return {};
}

// ---------------------------------------------------------------------------
// Full Risk Assessment (mirrors assess_risk tool logic)
// ---------------------------------------------------------------------------

interface RiskAssessment {
  decision: "ALLOW" | "WARN" | "BLOCK";
  overallRiskScore: number;
  riskFactors: string[];
  contractScan: ScanResult | null;
  tokenSafety: { canSell: boolean; indicators: string[] } | null;
  attestation: Record<string, string> | null;
}

async function assessRisk(
  targetContract: string,
  tokenAddress: string | null,
): Promise<RiskAssessment> {
  const checks: {
    contractScan: ScanResult | null;
    tokenSafety: { canSell: boolean; indicators: string[] } | null;
  } = {
    contractScan: null,
    tokenSafety: null,
  };

  // 1. Scan the contract
  const fetched = await fetchContractSource(targetContract, BASE_CHAIN_ID);
  if (fetched.source) {
    checks.contractScan = scanContractSource(fetched.source);
  } else if (fetched.bytecode) {
    checks.contractScan = scanBytecode(fetched.bytecode);
  }

  // 2. Check token safety if relevant
  if (tokenAddress) {
    checks.tokenSafety = await checkTokenSellability(
      BASE_CHAIN_ID,
      tokenAddress as Address,
      AGENT_WALLET,
    );
  }

  // 3. Compute overall risk
  let overallRisk = 0;
  const risks: string[] = [];

  if (checks.contractScan) {
    overallRisk = Math.max(overallRisk, checks.contractScan.riskScore);
    if (checks.contractScan.riskScore >= 70) risks.push("contract_high_risk");
    if (checks.contractScan.findings.length > 0) {
      for (const f of checks.contractScan.findings) {
        risks.push(f.patternId);
      }
    }
  } else {
    // No source or bytecode available -- that is itself a risk signal
    overallRisk = Math.max(overallRisk, 75);
    risks.push("no_verified_source");
    risks.push("unverifiable_contract");
  }

  if (checks.tokenSafety && !checks.tokenSafety.canSell) {
    overallRisk = Math.max(overallRisk, 90);
    risks.push("cannot_sell_token");
  }

  const decision: RiskAssessment["decision"] =
    overallRisk >= 70 ? "BLOCK" : overallRisk >= 40 ? "WARN" : "ALLOW";

  // 4. Generate attestation if allowed
  let attestation: Record<string, string> | null = null;
  if (decision !== "BLOCK") {
    try {
      const att = await signAttestation({
        agent: AGENT_WALLET,
        target: targetContract as Address,
        selector: SWAP_SELECTOR,
        riskScore: overallRisk,
        chainId: BASE_CHAIN_ID,
      });
      attestation = {
        attestationId: att.attestationId,
        agent: att.agent,
        target: att.target,
        selector: att.selector,
        riskScore: att.riskScore.toString(),
        expiresAt: new Date(att.expiresAt * 1000).toISOString(),
        signature: att.signature,
      };
    } catch {
      // No attester key configured -- expected in demo mode
    }
  }

  return {
    decision,
    overallRiskScore: overallRisk,
    riskFactors: risks,
    contractScan: checks.contractScan,
    tokenSafety: checks.tokenSafety,
    attestation,
  };
}

// ---------------------------------------------------------------------------
// Display a full assessment
// ---------------------------------------------------------------------------

function displayAssessment(label: string, address: string, result: RiskAssessment) {
  console.log(`  ${BOLD}Contract:${RESET}    ${address}`);
  console.log(`  ${BOLD}Chain:${RESET}       Base (8453)`);
  console.log(`  ${BOLD}Risk Score:${RESET}  ${printRiskMeter(result.overallRiskScore)}`);
  console.log();

  // Scan findings
  if (result.contractScan && result.contractScan.findings.length > 0) {
    console.log(`  ${BOLD}Findings (${result.contractScan.findings.length}):${RESET}`);
    for (const finding of result.contractScan.findings) {
      console.log(`    ${printSeverityBadge(finding.severity)} ${BOLD}${finding.patternName}${RESET}`);
      console.log(`    ${DIM}${finding.description}${RESET}`);
      if (finding.matchedSnippet) {
        const snippet = finding.matchedSnippet.length > 80
          ? finding.matchedSnippet.slice(0, 80) + "..."
          : finding.matchedSnippet;
        console.log(`    ${DIM}Matched: "${snippet}"${RESET}`);
      }
      console.log();
    }
  } else if (result.contractScan) {
    console.log(`  ${GREEN}No exploit patterns detected in contract source.${RESET}`);
    console.log();
  } else {
    console.log(`  ${YELLOW}No verified source code available for analysis.${RESET}`);
    console.log(`  ${DIM}Unverified contracts are treated as high risk by default.${RESET}`);
    console.log();
  }

  // Token safety
  if (result.tokenSafety) {
    console.log(`  ${BOLD}Token Safety:${RESET}`);
    console.log(`    Can sell:    ${result.tokenSafety.canSell ? GREEN + "Yes" : RED + "No"}${RESET}`);
    if (result.tokenSafety.indicators.length > 0) {
      console.log(`    Indicators:  ${result.tokenSafety.indicators.join(", ")}`);
    } else {
      console.log(`    Indicators:  ${GREEN}none${RESET}`);
    }
    console.log();
  }

  // Risk factors
  if (result.riskFactors.length > 0) {
    console.log(`  ${BOLD}Risk Factors:${RESET}`);
    for (const factor of result.riskFactors) {
      const color = factor.includes("high_risk") || factor.includes("cannot_sell") || factor.includes("unverifiable")
        ? RED : YELLOW;
      console.log(`    ${color}- ${factor}${RESET}`);
    }
    console.log();
  }

  // Decision
  console.log(`  ${BOLD}Decision:${RESET}`);
  printDecision(result.decision);
  console.log();

  // Attestation
  if (result.attestation) {
    console.log(`  ${BOLD}On-Chain Attestation:${RESET}`);
    console.log(`    ${DIM}ID:        ${result.attestation.attestationId.slice(0, 18)}...${RESET}`);
    console.log(`    ${DIM}Agent:     ${result.attestation.agent}${RESET}`);
    console.log(`    ${DIM}Target:    ${result.attestation.target}${RESET}`);
    console.log(`    ${DIM}Selector:  ${result.attestation.selector}${RESET}`);
    console.log(`    ${DIM}Risk:      ${result.attestation.riskScore}/100${RESET}`);
    console.log(`    ${DIM}Expires:   ${result.attestation.expiresAt}${RESET}`);
    console.log(`    ${DIM}Signature: ${result.attestation.signature.slice(0, 18)}...${RESET}`);
    console.log();
    console.log(`    ${GREEN}This attestation can be submitted on-chain to the AegisSafetyHook${RESET}`);
    console.log(`    ${GREEN}to authorize the swap through the Uniswap v4 pool.${RESET}`);
    console.log();
  } else if (result.decision !== "BLOCK") {
    console.log(`  ${DIM}Attestation: Not available (no ATTESTER_PRIVATE_KEY configured).${RESET}`);
    console.log(`  ${DIM}In production, Aegis signs an EIP-712 attestation for on-chain verification.${RESET}`);
    console.log();
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  printHeader();

  const startTime = Date.now();

  // ---- Scenario 1: Legitimate token (USDC on Base) ----

  printDivider("SCENARIO 1: Legitimate Token Swap");

  console.log(`${BOLD}  An AI agent wants to swap ETH for USDC on Base via Uniswap v4.${RESET}`);
  console.log(`${DIM}  Before executing, the agent calls Aegis assess_risk to verify safety.${RESET}`);
  console.log();

  console.log(`${DIM}  Fetching contract source from Basescan...${RESET}`);
  const usdcResult = await assessRisk(USDC_BASE, USDC_BASE);
  console.log(`${DIM}  Analysis complete.${RESET}\n`);

  displayAssessment("USDC (Base)", USDC_BASE, usdcResult);

  // ---- Scenario 2: WETH on Base (another legitimate token) ----

  printDivider("SCENARIO 2: WETH Contract Check");

  console.log(`${BOLD}  Agent verifies the WETH contract it will interact with.${RESET}`);
  console.log(`${DIM}  Wrapped ETH is a core DeFi primitive -- it should pass cleanly.${RESET}`);
  console.log();

  console.log(`${DIM}  Fetching contract source from Basescan...${RESET}`);
  const wethResult = await assessRisk(WETH_BASE, WETH_BASE);
  console.log(`${DIM}  Analysis complete.${RESET}\n`);

  displayAssessment("WETH (Base)", WETH_BASE, wethResult);

  // ---- Scenario 3: Honeypot token (BLOCKED) ----

  printDivider("SCENARIO 3: Honeypot Token (Blocked)");

  console.log(`${BOLD}  The agent discovers a new meme token -- "Totally Safe Token" (SAFE).${RESET}`);
  console.log(`${DIM}  The token claims 0% buy tax and renounced ownership.${RESET}`);
  console.log(`${DIM}  Aegis fetches the source and scans it before allowing the swap.${RESET}`);
  console.log();

  // Load the MockHoneypot source as if we fetched it from a block explorer
  const honeypotPath = path.join(import.meta.dirname, "../contracts/src/MockHoneypot.sol");
  const honeypotSource = fs.readFileSync(honeypotPath, "utf-8");
  console.log(`${DIM}  Analyzing contract source (${honeypotSource.length} chars)...${RESET}`);

  const honeypotScan = scanContractSource(honeypotSource);
  const honeypotResult: RiskAssessment = {
    decision: honeypotScan.riskScore >= 70 ? "BLOCK" : honeypotScan.riskScore >= 40 ? "WARN" : "ALLOW",
    overallRiskScore: honeypotScan.riskScore,
    riskFactors: honeypotScan.findings.map((f) => f.patternId),
    contractScan: honeypotScan,
    tokenSafety: null,
    attestation: null,
  };
  if (honeypotResult.overallRiskScore >= 70) {
    honeypotResult.riskFactors.unshift("contract_high_risk");
  }

  console.log(`${DIM}  Analysis complete.${RESET}\n`);

  displayAssessment("SAFE (Honeypot)", HONEYPOT_CONTRACT, honeypotResult);

  if (honeypotResult.decision === "BLOCK") {
    console.log(`  ${CYAN}Without Aegis:${RESET}  Agent buys SAFE token. 99% sell tax. Funds gone.`);
    console.log(`  ${GREEN}With Aegis:${RESET}     Aegis detects sell tax, sell pause, fake renounce.`);
    console.log(`                  Swap blocked before execution. Zero loss.`);
    console.log();
  }

  // ---- Summary ----

  printDivider("SUMMARY");

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

  console.log(`  ${BOLD}Results:${RESET}`);
  console.log(`    USDC (${USDC_BASE.slice(0, 10)}...):       ${usdcResult.decision === "ALLOW" ? GREEN : usdcResult.decision === "WARN" ? YELLOW : RED}${usdcResult.decision}${RESET} (risk: ${usdcResult.overallRiskScore}/100)`);
  console.log(`    WETH (${WETH_BASE.slice(0, 10)}...):       ${wethResult.decision === "ALLOW" ? GREEN : wethResult.decision === "WARN" ? YELLOW : RED}${wethResult.decision}${RESET} (risk: ${wethResult.overallRiskScore}/100)`);
  console.log(`    Honeypot (${HONEYPOT_CONTRACT.slice(0, 10)}...):  ${honeypotResult.decision === "ALLOW" ? GREEN : honeypotResult.decision === "WARN" ? YELLOW : RED}${honeypotResult.decision}${RESET} (risk: ${honeypotResult.overallRiskScore}/100)`);
  console.log();
  console.log(`  ${BOLD}Elapsed:${RESET} ${elapsed}s`);
  console.log();
  console.log(`  ${CYAN}Without Aegis:${RESET}  Agent blindly swaps into any contract. No verification.`);
  console.log(`  ${GREEN}With Aegis:${RESET}     Agent checks every contract before execution.`);
  console.log(`                  Legitimate tokens pass. Malicious contracts are blocked.`);
  console.log(`                  Zero fund loss from preventable scams.`);

  printDivider();

  console.log(`${DIM}This demo used the Aegis risk engine against live Base mainnet contracts.`);
  console.log(`In production, Aegis runs as an MCP server that any AI agent can call`);
  console.log(`before executing on-chain transactions.${RESET}\n`);

  // Output raw JSON for programmatic use
  if (process.argv.includes("--json")) {
    console.log(JSON.stringify({
      usdc: usdcResult,
      weth: wethResult,
      honeypot: honeypotResult,
    }, null, 2));
  }
}

main().catch((err) => {
  console.error(`${RED}${BOLD}Error:${RESET} ${err.message}`);
  process.exit(1);
});
