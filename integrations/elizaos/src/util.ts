/**
 * Shared utilities for parsing user messages.
 */

/** Extract the first Ethereum-style address from text. */
export function extractAddress(text: string): string | null {
  const match = text.match(/\b(0x[0-9a-fA-F]{6,40})\b/);
  return match ? match[1] : null;
}

/** Well-known chain name to chain ID mapping. */
const CHAIN_ALIASES: Record<string, number> = {
  ethereum: 1,
  eth: 1,
  mainnet: 1,
  goerli: 5,
  sepolia: 11155111,
  polygon: 137,
  matic: 137,
  arbitrum: 42161,
  arb: 42161,
  optimism: 10,
  op: 10,
  base: 8453,
  bsc: 56,
  bnb: 56,
  "binance smart chain": 56,
  avalanche: 43114,
  avax: 43114,
  fantom: 250,
  ftm: 250,
  zksync: 324,
  linea: 59144,
  scroll: 534352,
  blast: 81457,
};

/**
 * Try to extract a chain ID from the message text.
 * Looks for explicit "chain <number>" or "chainId <number>" patterns first,
 * then falls back to matching known chain names.
 */
export function extractChainId(text: string): number | null {
  // Explicit numeric chain ID
  const explicitMatch = text.match(/\bchain\s*(?:id)?\s*[:=]?\s*(\d+)\b/i);
  if (explicitMatch) return parseInt(explicitMatch[1], 10);

  // Named chain
  const lower = text.toLowerCase();
  for (const [name, id] of Object.entries(CHAIN_ALIASES)) {
    if (lower.includes(name)) return id;
  }

  return null;
}

interface VerdictInput {
  scanResult: { riskScore: number; findings: Array<{ name: string; severity: string; description: string }>; summary: string } | null;
  simResult: Record<string, unknown> | null;
  sellCheck: Record<string, unknown> | null;
  address: string;
  chainId: number;
}

/**
 * Combine multiple check results into a single human-readable verdict.
 */
export function formatRiskVerdict(input: VerdictInput): string {
  const { scanResult, simResult, sellCheck, address, chainId } = input;
  const lines: string[] = [];

  lines.push(`## Aegis Risk Assessment`);
  lines.push(`**Contract:** \`${address}\` (chain ${chainId})`);
  lines.push("");

  let maxRisk = 0;

  // Source scan results
  if (scanResult) {
    maxRisk = Math.max(maxRisk, scanResult.riskScore);
    lines.push(`### Source Scan`);
    lines.push(`Risk score: ${scanResult.riskScore}/100`);
    if (scanResult.findings.length > 0) {
      for (const f of scanResult.findings) {
        lines.push(`- [${f.severity.toUpperCase()}] ${f.name}: ${f.description}`);
      }
    } else {
      lines.push("No issues found in source code.");
    }
    lines.push("");
  }

  // Simulation results
  if (simResult) {
    lines.push(`### Transaction Simulation`);
    if ("success" in simResult) {
      lines.push(`Simulation ${simResult.success ? "succeeded" : "failed"}`);
    }
    if ("gasUsed" in simResult) {
      lines.push(`Gas used: ${simResult.gasUsed}`);
    }
    if ("error" in simResult && simResult.error) {
      lines.push(`Error: ${simResult.error}`);
      maxRisk = Math.max(maxRisk, 50);
    }
    lines.push("");
  }

  // Honeypot results
  if (sellCheck) {
    lines.push(`### Honeypot Check`);
    if ("sellable" in sellCheck) {
      if (!sellCheck.sellable) {
        lines.push("**Warning: token may not be sellable (potential honeypot)**");
        maxRisk = Math.max(maxRisk, 90);
      } else {
        lines.push("Token appears sellable.");
      }
    }
    if ("buyTax" in sellCheck) lines.push(`Buy tax: ${sellCheck.buyTax}%`);
    if ("sellTax" in sellCheck) lines.push(`Sell tax: ${sellCheck.sellTax}%`);
    lines.push("");
  }

  // Overall verdict
  let decision: string;
  if (maxRisk >= 70) {
    decision = "BLOCK - High risk detected. Interacting with this contract is not recommended.";
  } else if (maxRisk >= 30) {
    decision = "WARN - Moderate risk detected. Proceed with caution and review the findings above.";
  } else {
    decision = "ALLOW - No major risks detected. Standard caution still applies.";
  }

  lines.push(`### Verdict: ${decision}`);
  lines.push(`Overall risk score: ${maxRisk}/100`);

  return lines.join("\n");
}
