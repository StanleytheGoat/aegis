/**
 * Aegis Risk Engine - Known exploit pattern signatures.
 *
 * Each pattern defines a bytecode or source-level signature that indicates
 * a potential vulnerability or malicious behavior in a smart contract.
 */

export interface ExploitPattern {
  id: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  /** Risk score contribution (0-100) */
  riskWeight: number;
  /** Regex patterns to match against contract source code */
  sourcePatterns?: RegExp[];
  /** Hex patterns to match against contract bytecode */
  bytecodePatterns?: string[];
  /** Function selectors that indicate the pattern */
  suspiciousSelectors?: string[];
}

export const EXPLOIT_PATTERNS: ExploitPattern[] = [
  // --- Honeypot Patterns ---
  {
    id: "honeypot-sell-tax",
    name: "Asymmetric Buy/Sell Tax",
    severity: "critical",
    description: "Contract applies significantly higher tax on sells than buys, trapping user funds.",
    riskWeight: 90,
    sourcePatterns: [
      /sellTax|sell_tax|_sellFee|sellFee/i,
      /buyTax.*?0.*?sellTax.*?[5-9]\d/s,
      /isSell.*?tax.*?[5-9]\d{2,}/s,
    ],
  },
  {
    id: "honeypot-sell-pause",
    name: "Sell Pause Mechanism",
    severity: "critical",
    description: "Owner can pause selling, preventing users from exiting positions.",
    riskWeight: 85,
    sourcePatterns: [
      /sellPaused|pauseSelling|tradingEnabled.*?false/i,
      /require\(!?.*?paused.*?\)/i,
    ],
  },
  {
    id: "honeypot-max-sell",
    name: "Hidden Max Sell Amount",
    severity: "high",
    description: "Contract enforces a max sell amount that prevents large exits.",
    riskWeight: 70,
    sourcePatterns: [
      /maxSellAmount|maxSell|_maxTxAmount/i,
      /require.*?amount.*?<=.*?max/i,
    ],
  },
  {
    id: "honeypot-fake-renounce",
    name: "Fake Ownership Renounce",
    severity: "critical",
    description: "owner() returns address(0) but a hidden owner variable retains control.",
    riskWeight: 95,
    sourcePatterns: [
      /return\s+address\(0\).*?\/\/.*?renounce/is,
      /_realOwner|_hiddenOwner|shadowOwner/i,
      /function\s+owner\(\).*?returns.*?address.*?\{[^}]*address\(0\)/s,
    ],
  },

  // --- Reentrancy Patterns ---
  {
    id: "reentrancy-external-call-before-state",
    name: "Reentrancy Vulnerability",
    severity: "critical",
    description: "External call made before state update, enabling reentrancy attacks.",
    riskWeight: 90,
    sourcePatterns: [
      /\.call\{value:.*?\}.*?\n.*?balance/s,
      /transfer\(.*?\)[\s\S]{0,50}balance\[/,
    ],
  },

  // --- Access Control Patterns ---
  {
    id: "centralized-mint",
    name: "Unrestricted Minting",
    severity: "high",
    description: "Owner or arbitrary address can mint unlimited tokens.",
    riskWeight: 75,
    sourcePatterns: [
      /function\s+mint\s*\([^)]*\)\s*(?:external|public)\s*(?!.*?onlyMinter)/s,
    ],
  },
  {
    id: "hidden-admin-functions",
    name: "Hidden Admin Functions",
    severity: "high",
    description: "Contract has admin functions that are not immediately visible (no Ownable, custom auth).",
    riskWeight: 65,
    sourcePatterns: [
      /require\(msg\.sender\s*==\s*(?!owner)_?[a-z]/i,
    ],
  },

  // --- Token Safety Patterns ---
  {
    id: "unlimited-approval",
    name: "Unlimited Approval Requirement",
    severity: "medium",
    description: "Contract requires or encourages unlimited token approvals.",
    riskWeight: 40,
    sourcePatterns: [
      /type\(uint256\)\.max|0xffffffff/i,
    ],
  },
  {
    id: "blacklist-mechanism",
    name: "Blacklist Mechanism",
    severity: "medium",
    description: "Contract can blacklist addresses from transacting.",
    riskWeight: 50,
    sourcePatterns: [
      /blacklist|blackList|isBlacklisted|_blacklist/i,
      /require\(!.*?blocked\[/i,
    ],
  },
  {
    id: "proxy-pattern",
    name: "Upgradeable Proxy",
    severity: "medium",
    description: "Contract uses proxy pattern - logic can be changed post-deployment.",
    riskWeight: 45,
    sourcePatterns: [
      /delegatecall|DELEGATECALL/,
      /implementation\(\)|_implementation/i,
    ],
    bytecodePatterns: [
      "363d3d373d3d3d363d", // EIP-1167 minimal proxy prefix
    ],
  },

  // --- Flash Loan Attack Patterns ---
  {
    id: "flash-loan-vulnerability",
    name: "Flash Loan Vulnerability",
    severity: "high",
    description: "Price oracle or balance check is manipulable within a single transaction.",
    riskWeight: 70,
    sourcePatterns: [
      /getReserves\(\).*?price/s,
      /balanceOf\(address\(this\)\).*?price/s,
    ],
  },

  // --- Approval/Permit Patterns ---
  {
    id: "permit-phishing",
    name: "Permit/Approval Phishing",
    severity: "high",
    description: "Contract collects approvals or permits that could drain user funds.",
    riskWeight: 75,
    sourcePatterns: [
      /transferFrom.*?approve.*?type\(uint256\)/s,
      /permit\(.*?\).*?transferFrom/s,
    ],
  },

  // --- Metamorphic and Advanced Exploit Patterns ---
  {
    id: "metamorphic-contract",
    name: "Metamorphic Contract (CREATE2 + SELFDESTRUCT)",
    severity: "critical",
    description:
      "Contract uses CREATE2 with SELFDESTRUCT, allowing code to be destroyed and redeployed at the same address with different logic.",
    riskWeight: 95,
    sourcePatterns: [
      /selfdestruct\s*\(/i,
      /assembly\s*\{[^}]*create2/i,
    ],
  },
  {
    id: "hidden-balance-modifier",
    name: "Hidden Balance Modifier",
    severity: "critical",
    description:
      "Contract contains functions that can directly set or modify token balances, enabling silent minting or theft.",
    riskWeight: 90,
    sourcePatterns: [
      /_balances\s*\[.*\]\s*=\s*/,
      /function\s+\w*(set|adjust|modify|update)\w*[Bb]alanc/i,
    ],
  },
  {
    id: "hidden-fee-modifier",
    name: "Hidden Fee Modifier (Dynamic Tax Change)",
    severity: "high",
    description:
      "Owner can change buy/sell fees after launch, potentially raising them to trap holders.",
    riskWeight: 75,
    sourcePatterns: [
      /function\s+set\w*(fee|tax|rate)/i,
      /(_sellFee|_buyFee|_taxFee|_liquidityFee|_totalFee)\s*=\s*/,
    ],
  },
  {
    id: "hidden-transfer-drain",
    name: "Hidden Transfer / Balance Drain",
    severity: "critical",
    description:
      "Owner-only function that can invoke internal transfers or directly modify balances to drain user funds.",
    riskWeight: 90,
    sourcePatterns: [
      /function\s+\w+.*onlyOwner[^{]*\{[^}]*_transfer\s*\(/,
      /function\s+\w+.*onlyOwner[^{]*\{[^}]*balances\s*\[/,
    ],
  },
  {
    id: "oracle-manipulation",
    name: "Oracle Manipulation / Flash Loan Price Attack",
    severity: "critical",
    description:
      "Contract reads spot reserves from a DEX pair for pricing, making it vulnerable to flash-loan-based price manipulation.",
    riskWeight: 85,
    sourcePatterns: [
      /getReserves\s*\(\s*\)/,
      /reserve[01]\s*[\/\*]\s*reserve[01]/,
      /IUniswapV2Pair.*getReserves/,
    ],
  },
  {
    id: "transfer-callback-trap",
    name: "Transfer Callback Trap (Delayed Honeypot)",
    severity: "critical",
    description:
      "Transfer function checks block timestamp or number, enabling the deployer to activate a honeypot after initial trading appears safe.",
    riskWeight: 90,
    sourcePatterns: [
      /function\s+_transfer[^}]*require\s*\([^)]*block\.(timestamp|number)/,
      /function\s+_transfer[^}]*tradingEnabled/,
    ],
  },
  {
    id: "mev-sandwich-risk",
    name: "MEV Sandwich Risk",
    severity: "high",
    description:
      "Low liquidity pool vulnerable to sandwich attacks targeting automated traders.",
    riskWeight: 60,
    sourcePatterns: [
      /swapExactTokensForTokens|swapExactETHForTokens|swapTokensForExactTokens/,
    ],
  },
  {
    id: "malicious-permit",
    name: "Malicious Permit Implementation",
    severity: "high",
    description:
      "Non-standard permit implementation that approves a different address than the declared spender, enabling silent fund theft via gasless signatures.",
    riskWeight: 80,
    sourcePatterns: [
      /function\s+permit\s*\([^)]*\)[^{]*\{[^}]*_approve\s*\(\s*\w+\s*,\s*(?!spender)/,
    ],
  },
  {
    id: "unaudited-lp-locker",
    name: "Unaudited LP Locker",
    severity: "high",
    description:
      "Liquidity-lock contract includes owner-only emergency withdraw or unlock functions, allowing the deployer to pull liquidity at any time.",
    riskWeight: 70,
    sourcePatterns: [
      /function\s+\w*(withdraw|unlock|release|emergency)\w*.*onlyOwner/i,
    ],
  },
  {
    id: "burn-price-manipulation",
    name: "Burn Mechanism Price Manipulation",
    severity: "high",
    description:
      "Owner can burn tokens directly from the liquidity pair, artificially inflating the token price for a profitable exit.",
    riskWeight: 75,
    sourcePatterns: [
      /function\s+burn\s*\([^)]*\)[^{]*onlyOwner/,
      /_burn\s*\(\s*(pair|lpAddress|uniswapV2Pair)/,
    ],
  },
];

/**
 * Known malicious bytecode signatures (hex substrings)
 */
export const MALICIOUS_BYTECODE_SIGS = [
  { sig: "selfdestruct", hex: "ff", description: "Contract can self-destruct" },
];

/**
 * Suspicious function selectors commonly found in scam contracts
 */
export const SUSPICIOUS_SELECTORS: Record<string, string> = {
  "0x8da5cb5b": "owner()",
  "0x715018a6": "renounceOwnership()",
  "0xa9059cbb": "transfer(address,uint256)",
  "0x23b872dd": "transferFrom(address,address,uint256)",
};
