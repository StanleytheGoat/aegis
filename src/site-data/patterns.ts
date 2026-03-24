/**
 * Pattern data for the website pattern library pages.
 * Imports from the risk engine and strips non-serializable fields (RegExp).
 */

import { EXPLOIT_PATTERNS } from "../risk-engine/patterns.js";

export interface PatternInfo {
  id: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  riskWeight: number;
  category: string;
  hasSourcePatterns: boolean;
  hasBytecodePatterns: boolean;
}

// Category mapping based on pattern position in the array
const CATEGORY_RANGES: Array<[number, number, string]> = [
  [0, 19, "Token Scam & Honeypot"],
  [20, 26, "Reentrancy Variants"],
  [27, 34, "Access Control & Authorization"],
  [35, 39, "Oracle Manipulation"],
  [40, 46, "Proxy & Upgradeability"],
  [47, 52, "Signature & Cryptographic"],
  [53, 59, "Weird ERC20 Behaviors"],
  [60, 66, "DeFi-Specific"],
  [67, 73, "DoS Patterns"],
  [74, 84, "Input Validation & Misc"],
  [85, 89, "Flash Loan Attacks"],
  [90, 94, "MEV & Front-Running"],
  [95, 99, "Governance Attacks"],
  [100, 104, "Cross-Chain & Bridge"],
  [105, 109, "NFT-Specific"],
  [110, 117, "Solidity/EVM Specific"],
  [118, 121, "Unchecked External Interactions"],
  [122, 126, "Staking, Vaults & Yield"],
  [127, 131, "Economic & Game Theory"],
  [132, 136, "Data Privacy & Protocol Integration"],
  [137, 141, "Recent & Novel Attacks"],
  [142, 144, "Rounding & Precision"],
  [145, 147, "Permit & Approval Edge Cases"],
  [148, 150, "Lending & Borrowing Edge Cases"],
  [151, 164, "Multi-Hop & Complex DeFi"],
];

function getCategory(index: number): string {
  for (const [start, end, name] of CATEGORY_RANGES) {
    if (index >= start && index <= end) return name;
  }
  return "Other";
}

export const patterns: PatternInfo[] = EXPLOIT_PATTERNS.map((p, i) => ({
  id: p.id,
  name: p.name,
  severity: p.severity,
  description: p.description,
  riskWeight: p.riskWeight,
  category: getCategory(i),
  hasSourcePatterns: !!(p.sourcePatterns && p.sourcePatterns.length > 0),
  hasBytecodePatterns: !!(p.bytecodePatterns && p.bytecodePatterns.length > 0),
}));

export const categories = [...new Set(patterns.map(p => p.category))];
