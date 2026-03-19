#!/usr/bin/env tsx

/**
 * Aegis Demo — Catching a Honeypot Token
 *
 * This demo shows how Aegis protects an AI agent from swapping into
 * a malicious honeypot token. It:
 *
 * 1. Loads the MockHoneypot contract source
 * 2. Runs it through the Aegis risk engine
 * 3. Shows the detailed findings
 * 4. Demonstrates that Aegis would BLOCK the swap
 *
 * Run: npx tsx demo/catch-honeypot.ts
 */

import { scanContractSource, type ScanResult } from "../src/risk-engine/scanner.js";
import * as fs from "node:fs";
import * as path from "node:path";

// ANSI color codes
const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const CYAN = "\x1b[36m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const RESET = "\x1b[0m";

function printHeader() {
  console.log(`
${CYAN}${BOLD}╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ⛨  AEGIS — DeFi Safety Layer for AI Agents              ║
║                                                           ║
║   Demo: Catching a Honeypot Token                         ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝${RESET}
`);
}

function printSeverityBadge(severity: string): string {
  switch (severity) {
    case "critical": return `${RED}${BOLD}[CRITICAL]${RESET}`;
    case "high": return `${RED}[HIGH]${RESET}`;
    case "medium": return `${YELLOW}[MEDIUM]${RESET}`;
    case "low": return `${DIM}[LOW]${RESET}`;
    default: return `${DIM}[INFO]${RESET}`;
  }
}

function printRiskMeter(score: number): string {
  const filled = Math.round(score / 5);
  const empty = 20 - filled;
  const color = score >= 70 ? RED : score >= 40 ? YELLOW : GREEN;
  return `${color}[${"█".repeat(filled)}${"░".repeat(empty)}] ${score}/100${RESET}`;
}

async function main() {
  printHeader();

  // Step 1: Load the honeypot contract
  console.log(`${BOLD}Step 1: Agent discovers a new token — "Totally Safe Token" (SAFE)${RESET}`);
  console.log(`${DIM}The token claims to be a meme coin with 0% buy tax and renounced ownership.${RESET}`);
  console.log(`${DIM}Sounds great... but is it?${RESET}\n`);

  const contractPath = path.join(import.meta.dirname, "../contracts/src/MockHoneypot.sol");
  const source = fs.readFileSync(contractPath, "utf-8");

  console.log(`${DIM}Loading contract source (${source.length} chars)...${RESET}\n`);

  // Step 2: Scan with Aegis
  console.log(`${BOLD}Step 2: Agent calls Aegis MCP server → scan_contract${RESET}`);
  console.log(`${DIM}Analyzing contract for known exploit patterns...${RESET}\n`);

  const result: ScanResult = scanContractSource(source);

  // Step 3: Display results
  console.log(`${BOLD}Step 3: Aegis Risk Assessment${RESET}\n`);

  console.log(`  Risk Score:   ${printRiskMeter(result.riskScore)}`);
  console.log(`  Risk Level:   ${result.riskLevel.toUpperCase()}`);
  console.log(`  Recommend:    ${result.recommendation === "avoid" ? RED + "AVOID" : result.recommendation === "caution" ? YELLOW + "CAUTION" : GREEN + "PROCEED"}${RESET}`);
  console.log();

  if (result.findings.length > 0) {
    console.log(`  ${BOLD}Findings (${result.findings.length}):${RESET}\n`);

    for (const finding of result.findings) {
      console.log(`    ${printSeverityBadge(finding.severity)} ${BOLD}${finding.patternName}${RESET}`);
      console.log(`    ${DIM}${finding.description}${RESET}`);
      if (finding.matchedSnippet) {
        console.log(`    ${DIM}Matched: "${finding.matchedSnippet}"${RESET}`);
      }
      console.log();
    }
  }

  // Step 4: Decision
  console.log(`${BOLD}Step 4: Agent Decision${RESET}\n`);

  if (result.recommendation === "avoid") {
    console.log(`  ${RED}${BOLD}⛨ BLOCKED${RESET} — Aegis prevented the swap.`);
    console.log(`  ${DIM}The agent's funds are safe. The honeypot was detected before execution.${RESET}`);
    console.log();
    console.log(`  ${CYAN}Without Aegis:${RESET}  Agent buys SAFE token, can never sell. Funds lost.`);
    console.log(`  ${GREEN}With Aegis:${RESET}     Agent detects 99% sell tax, fake renounce, sell pause.`);
    console.log(`                  Swap blocked. Zero loss.`);
  } else {
    console.log(`  ${GREEN}ALLOWED${RESET} — Transaction appears safe.`);
  }

  console.log(`\n${DIM}${"─".repeat(60)}${RESET}`);
  console.log(`${DIM}This demo used the Aegis static analysis engine.`);
  console.log(`In production, Aegis also simulates transactions on a forked chain`);
  console.log(`and checks token sellability before any swap executes.${RESET}\n`);

  // Output raw JSON for programmatic use
  if (process.argv.includes("--json")) {
    console.log(JSON.stringify(result, null, 2));
  }
}

main().catch(console.error);
