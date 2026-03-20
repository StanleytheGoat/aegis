/**
 * Aegis Risk Engine - Known exploit pattern signatures.
 *
 * Each pattern defines a bytecode or source-level signature that indicates
 * a potential vulnerability or malicious behavior in a smart contract.
 *
 * 165 patterns across 25 categories:
 *   1. Token Scam & Honeypot (20)
 *   2. Reentrancy Variants (7)
 *   3. Access Control & Authorization (8)
 *   4. Oracle Manipulation (5)
 *   5. Proxy & Upgradeability (7)
 *   6. Signature & Cryptographic (6)
 *   7. Weird ERC20 Behaviors (7)
 *   8. DeFi-Specific (7)
 *   9. DoS Patterns (7)
 *  10. Input Validation & Misc (11)
 *  11. Additional High-Impact (11)
 *  12. Flash Loan Attacks (5)
 *  13. MEV & Front-Running (5)
 *  14. Governance Attacks (5)
 *  15. Cross-Chain & Bridge (5)
 *  16. NFT-Specific (5)
 *  17. Solidity/EVM Specific (8)
 *  18. Unchecked External Interactions (4)
 *  19. Economic & Game Theory Attacks (5)
 *  20. Data Privacy & Protocol Integration (5)
 *  21. Staking, Vaults & Yield (5)
 *  22. Rounding & Precision (3)
 *  23. Permit & Approval Edge Cases (3)
 *  24. Lending & Borrowing Edge Cases (3)
 *  25. Multi-Hop & Complex DeFi (3)
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
  // =========================================================================
  // Category 1: Token Scam & Honeypot Patterns (20)
  // =========================================================================

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
  {
    id: "honeypot-dynamic-tax",
    name: "Dynamic Tax Manipulation",
    severity: "high",
    description:
      "Owner can change buy/sell tax rates after deployment, potentially raising them to 100% to trap holders.",
    riskWeight: 75,
    sourcePatterns: [
      /function\s+set\w*(fee|tax|rate)/i,
      /(_sellFee|_buyFee|_taxFee|_liquidityFee|_totalFee)\s*=\s*/,
    ],
  },
  {
    id: "honeypot-max-wallet",
    name: "Hidden Max Wallet Limit",
    severity: "medium",
    description:
      "Undisclosed cap on wallet holdings prevents accumulation and makes large positions impossible to build.",
    riskWeight: 45,
    sourcePatterns: [
      /maxWallet|_maxWalletSize|maxWalletAmount|maxHoldingAmount/i,
      /require\s*\([^)]*balanceOf[^)]*\+[^)]*amount[^)]*<=\s*\w*max/is,
    ],
  },
  {
    id: "honeypot-transfer-toggle",
    name: "Transfer Restriction Toggle",
    severity: "critical",
    description:
      "Owner can flip a boolean that blocks all transfers, freezing every holder's tokens.",
    riskWeight: 90,
    sourcePatterns: [
      /function\s+\w*(?:set|toggle|enable|disable)\w*(?:Transfer|Trading)\w*\s*\(/i,
      /require\s*\(\s*(?:trading|transfer)(?:Enabled|Active|Open)\s*[,)]/i,
      /(?:trading|transfer)(?:Enabled|Active|Open)\s*=\s*(?:true|false)/i,
    ],
  },
  {
    id: "honeypot-antibot-sell-block",
    name: "Anti-Bot as Sell Block",
    severity: "high",
    description:
      "Anti-bot mechanism that permanently marks early buyers, blocking their ability to sell.",
    riskWeight: 70,
    sourcePatterns: [
      /isBot\s*\[.*?\]\s*=\s*true/i,
      /require\s*\(\s*!?\s*(?:isBot|_isBot|bot)\s*\[/i,
      /function\s+\w*(?:setBot|addBot|markBot)\s*\(/i,
    ],
  },
  {
    id: "honeypot-fee-recipient-drain",
    name: "Fee Recipient Drain",
    severity: "high",
    description:
      "Swap fees are routed to an owner-controlled address that can drain accumulated value.",
    riskWeight: 70,
    sourcePatterns: [
      /(?:_feeAddress|_taxWallet|_marketingWallet|_devWallet)\s*=\s*/i,
      /function\s+set\w*(?:Fee|Tax|Marketing|Dev)\w*(?:Address|Wallet|Receiver)\s*\(/i,
    ],
  },
  {
    id: "honeypot-liquidity-rug",
    name: "Liquidity Removal Rug Pull",
    severity: "critical",
    description:
      "Owner retains LP tokens or has a function to remove all DEX liquidity after buyers enter.",
    riskWeight: 90,
    sourcePatterns: [
      /removeLiquidity(?:ETH)?(?:WithPermit)?/i,
      /function\s+\w*(?:removeLiquidity|pullLiquidity|withdrawLiquidity)\w*.*?onlyOwner/is,
      /IERC20\s*\(\s*(?:pair|lpToken)\s*\).*?transfer\s*\(/i,
    ],
  },
  {
    id: "honeypot-fake-lock",
    name: "Fake Liquidity Lock",
    severity: "high",
    description:
      "Liquidity lock contract has a backdoor or short timelock allowing the deployer to pull LP early.",
    riskWeight: 70,
    sourcePatterns: [
      /function\s+\w*(withdraw|unlock|release|emergency)\w*.*onlyOwner/i,
      /lockTime\s*=\s*block\.timestamp\s*\+\s*(?:[0-9]{1,4})\s*;/,
    ],
  },
  {
    id: "honeypot-balance-manipulation",
    name: "Balance Manipulation",
    severity: "critical",
    description:
      "Contract modifies internal balances arbitrarily, allowing the owner to zero out holders or mint to themselves.",
    riskWeight: 90,
    sourcePatterns: [
      /_balances\s*\[.*\]\s*=\s*/,
      /function\s+\w*(set|adjust|modify|update)\w*[Bb]alanc/i,
      /balanceOf\s*\[.*?\]\s*=\s*0\s*;/,
    ],
  },
  {
    id: "honeypot-trading-backdoor",
    name: "Trading Enable Backdoor",
    severity: "high",
    description:
      "Owner can permanently disable trading after initial enable, trapping all holders.",
    riskWeight: 75,
    sourcePatterns: [
      /function\s+\w*(?:disable|close|stop|pause)Trading\s*\(/i,
      /tradingEnabled\s*=\s*false/i,
      /function\s+_transfer[^}]*tradingEnabled/s,
    ],
  },
  {
    id: "honeypot-hidden-mint",
    name: "Hidden Mint Function",
    severity: "critical",
    description:
      "Obfuscated minting function allows unlimited supply inflation, diluting all holders to zero.",
    riskWeight: 90,
    sourcePatterns: [
      /function\s+mint\s*\([^)]*\)\s*(?:external|public)\s*(?!.*?onlyMinter)/s,
      /function\s+\w+\s*\([^)]*\)\s*(?:external|public)[^{]*\{[^}]*_mint\s*\(/s,
      /totalSupply\s*\+=|totalSupply\s*=\s*totalSupply\s*\+/,
    ],
  },
  {
    id: "honeypot-cooldown-trap",
    name: "Cooldown / Delay Trap",
    severity: "medium",
    description:
      "Excessive cooldown timers on sells prevent timely exits during price drops.",
    riskWeight: 40,
    sourcePatterns: [
      /cooldown|_cooldownTimer|sellCooldown/i,
      /require\s*\([^)]*block\.timestamp\s*-\s*\w*last\w*(?:Sell|Trade|Transfer)/is,
    ],
  },
  {
    id: "honeypot-reflection-exploit",
    name: "Reflection Token Exploit",
    severity: "high",
    description:
      "Reflection or rebase mechanics funnel disproportionate rewards to the owner address.",
    riskWeight: 65,
    sourcePatterns: [
      /reflect\s*\(|_reflectFee|tFeeTotal/i,
      /isExcludedFromReward|_isExcluded\[/i,
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
    id: "honeypot-upgradeable-bait",
    name: "Upgradeable Token Bait-and-Switch",
    severity: "critical",
    description:
      "Token passes audit as a proxy, then the implementation is swapped for a malicious version post-launch.",
    riskWeight: 85,
    sourcePatterns: [
      /function\s+upgrade\w*\s*\([^)]*address\s+\w+impl/i,
      /ERC1967Upgrade|TransparentUpgradeableProxy/,
      /_upgradeTo\s*\(/,
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

  // =========================================================================
  // Category 2: Reentrancy Variants (7)
  // =========================================================================

  {
    id: "reentrancy-external-call-before-state",
    name: "Reentrancy Vulnerability (Classic)",
    severity: "critical",
    description: "External call made before state update, enabling reentrancy attacks.",
    riskWeight: 90,
    sourcePatterns: [
      /\.call\{value:.*?\}.*?\n.*?balance/s,
      /transfer\(.*?\)[\s\S]{0,50}balance\[/,
    ],
  },
  {
    id: "reentrancy-cross-function",
    name: "Cross-Function Reentrancy",
    severity: "critical",
    description:
      "Reentrancy across different functions that share state, allowing an attacker to call function B during function A's external call.",
    riskWeight: 85,
    sourcePatterns: [
      /\.call\{value:.*?\}[\s\S]*?function\s+\w+.*?balance/s,
      /\.call\{value:[\s\S]{0,200}(?!_?locked|nonReentrant|_status)/s,
    ],
  },
  {
    id: "reentrancy-cross-contract",
    name: "Cross-Contract Reentrancy",
    severity: "critical",
    description:
      "Reentrancy via callbacks to a different contract that shares state or makes assumptions about the calling contract's state.",
    riskWeight: 80,
    sourcePatterns: [
      /I\w+\(.*?\)\.\w+\([\s\S]{0,100}\.call\{/s,
      /\.call\{value:[\s\S]{0,100}I\w+\(\w+\)\.\w+\(/s,
    ],
  },
  {
    id: "reentrancy-read-only",
    name: "Read-Only Reentrancy",
    severity: "high",
    description:
      "View function returns stale state during reentrancy, causing other contracts that read it to act on incorrect data.",
    riskWeight: 70,
    sourcePatterns: [
      /function\s+\w+\s*\([^)]*\)\s*(?:external|public)\s+view[\s\S]{0,300}totalSupply|totalAssets/s,
      /\.call\{value:[\s\S]{0,300}function\s+\w+[^{]*view\s/s,
    ],
  },
  {
    id: "reentrancy-erc721-callback",
    name: "ERC721/ERC1155 Callback Reentrancy",
    severity: "high",
    description:
      "onERC721Received or onERC1155Received callback used as a reentrancy vector during safeTransferFrom.",
    riskWeight: 70,
    sourcePatterns: [
      /onERC721Received|onERC1155Received|onERC1155BatchReceived/,
      /_safeMint\s*\([\s\S]{0,200}(?!nonReentrant|_status)/s,
      /safeTransferFrom[\s\S]{0,100}(?!nonReentrant)/s,
    ],
  },
  {
    id: "reentrancy-erc777-hook",
    name: "ERC777 Transfer Hook Reentrancy",
    severity: "high",
    description:
      "ERC777 tokensReceived or tokensToSend hooks enable reentrancy during token transfers.",
    riskWeight: 70,
    sourcePatterns: [
      /tokensReceived|tokensToSend/,
      /IERC777|ERC777/,
    ],
  },
  {
    id: "reentrancy-missing-guard",
    name: "Missing Reentrancy Guard",
    severity: "high",
    description:
      "Function makes external calls or transfers value without a nonReentrant modifier or lock pattern.",
    riskWeight: 65,
    sourcePatterns: [
      /function\s+\w+\s*\([^)]*\)\s*(?:external|public)\s*(?:payable\s*)?(?!.*nonReentrant)[^{]*\{[^}]*\.call\{value:/s,
    ],
  },

  // =========================================================================
  // Category 3: Access Control & Authorization (8)
  // =========================================================================

  {
    id: "unprotected-initializer",
    name: "Unprotected Initializer",
    severity: "critical",
    description:
      "initialize() function is callable by anyone, allowing an attacker to claim ownership of a proxy contract.",
    riskWeight: 90,
    sourcePatterns: [
      /function\s+initialize\s*\([^)]*\)\s*(?:external|public)\s*(?!.*initializer|onlyOwner)/s,
      /function\s+init\s*\([^)]*\)\s*(?:external|public)\s*(?!.*initializer)/s,
    ],
  },
  {
    id: "tx-origin-auth",
    name: "tx.origin Authentication",
    severity: "high",
    description:
      "Using tx.origin instead of msg.sender for authentication, which is vulnerable to phishing attacks via intermediary contracts.",
    riskWeight: 70,
    sourcePatterns: [
      /require\s*\([^)]*tx\.origin/,
      /if\s*\([^)]*tx\.origin/,
      /tx\.origin\s*==\s*/,
    ],
  },
  {
    id: "missing-role-separation",
    name: "Missing Role Separation",
    severity: "medium",
    description:
      "Single admin role controls all critical functions without separation of duties.",
    riskWeight: 40,
    sourcePatterns: [
      /onlyOwner[\s\S]{0,2000}onlyOwner[\s\S]{0,2000}onlyOwner[\s\S]{0,2000}onlyOwner/s,
    ],
  },
  {
    id: "default-visibility",
    name: "Default Function Visibility",
    severity: "high",
    description:
      "Functions without explicit visibility specifier default to public in older Solidity, exposing internal logic.",
    riskWeight: 60,
    sourcePatterns: [
      /function\s+\w+\s*\([^)]*\)\s*(?:returns|{)/,
    ],
  },
  {
    id: "unprotected-selfdestruct",
    name: "Unprotected Self-Destruct",
    severity: "critical",
    description:
      "selfdestruct callable by unauthorized parties, allowing an attacker to destroy the contract and steal all ETH.",
    riskWeight: 95,
    sourcePatterns: [
      /selfdestruct\s*\(\s*(?:payable\s*\()?\s*msg\.sender/i,
      /function\s+\w+[^}]*selfdestruct\s*\([^}]*(?!onlyOwner)/s,
    ],
  },
  {
    id: "unprotected-ether-withdrawal",
    name: "Unprotected Ether Withdrawal",
    severity: "critical",
    description:
      "Functions that send ETH or tokens lack proper authorization checks, allowing anyone to drain the contract.",
    riskWeight: 85,
    sourcePatterns: [
      /function\s+\w*(?:withdraw|drain|claim|sweep)\w*\s*\([^)]*\)\s*(?:external|public)\s*(?!.*onlyOwner|onlyAdmin|onlyRole)/is,
      /msg\.sender\.(?:transfer|call\{value:)[\s\S]{0,100}address\(this\)\.balance/s,
    ],
  },
  {
    id: "delegatecall-privilege-escalation",
    name: "Privilege Escalation via Delegatecall",
    severity: "critical",
    description:
      "Attacker-controlled delegatecall target allows arbitrary code execution in the context of the calling contract.",
    riskWeight: 95,
    sourcePatterns: [
      /\.delegatecall\s*\(/,
      /assembly\s*\{[^}]*delegatecall/i,
    ],
    bytecodePatterns: [
      "f4", // DELEGATECALL opcode
    ],
  },
  {
    id: "missing-two-step-ownership",
    name: "Missing Two-Step Ownership Transfer",
    severity: "medium",
    description:
      "Direct ownership transfer risks permanent loss if transferred to an incorrect address.",
    riskWeight: 35,
    sourcePatterns: [
      /function\s+transferOwnership\s*\([^)]*\)[^{]*\{[^}]*_?owner\s*=\s*/s,
      /owner\s*=\s*newOwner/,
    ],
  },

  // =========================================================================
  // Category 4: Oracle Manipulation (5)
  // =========================================================================

  {
    id: "oracle-spot-price",
    name: "Spot Price Oracle Manipulation",
    severity: "critical",
    description:
      "Contract uses AMM spot price (getReserves) instead of TWAP for pricing, making it trivially manipulable via flash loans.",
    riskWeight: 85,
    sourcePatterns: [
      /getReserves\s*\(\s*\)/,
      /reserve[01]\s*[\/\*]\s*reserve[01]/,
      /IUniswapV2Pair.*getReserves/,
    ],
  },
  {
    id: "oracle-stale-data",
    name: "Stale Oracle Data",
    severity: "high",
    description:
      "Price feed consumed without freshness or staleness checks, allowing use of outdated prices.",
    riskWeight: 70,
    sourcePatterns: [
      /latestRoundData\s*\(\s*\)[\s\S]{0,200}(?!updatedAt|answeredInRound|roundId|staleness|stale|freshness)/s,
      /latestAnswer\s*\(\s*\)/,
      /\.price\s*\(\s*\)\s*(?!.*require)/,
    ],
  },
  {
    id: "oracle-missing-sequencer-check",
    name: "Missing L2 Sequencer Check",
    severity: "high",
    description:
      "On L2 chains, oracle prices may be stale during sequencer downtime. Missing sequencer uptime check risks using invalid prices.",
    riskWeight: 65,
    sourcePatterns: [
      /latestRoundData[\s\S]{0,500}(?!sequencer|isSequencerUp|SEQUENCER)/s,
      /AggregatorV3Interface[\s\S]{0,500}(?!sequencer)/s,
    ],
  },
  {
    id: "oracle-decimal-mismatch",
    name: "Oracle Decimal Mismatch",
    severity: "high",
    description:
      "Incorrect decimal precision handling between different oracle feeds or token decimals.",
    riskWeight: 65,
    sourcePatterns: [
      /latestRoundData[\s\S]{0,300}(?!decimals\(\))/s,
      /answer\s*\*\s*1e(?:10|8|6|2)\b/,
    ],
  },
  {
    id: "oracle-single-source",
    name: "Single Oracle Source Without Fallback",
    severity: "medium",
    description:
      "Contract depends on a single oracle feed with no fallback, creating a single point of failure.",
    riskWeight: 45,
    sourcePatterns: [
      /AggregatorV3Interface\s+\w+\s*(?:=|;)[\s\S]{0,2000}(?!fallback|backup|secondary|alternative)/s,
    ],
  },

  // =========================================================================
  // Category 5: Proxy & Upgradeability Issues (7)
  // =========================================================================

  {
    id: "proxy-pattern",
    name: "Upgradeable Proxy",
    severity: "medium",
    description: "Contract uses proxy pattern -- logic can be changed post-deployment.",
    riskWeight: 45,
    sourcePatterns: [
      /delegatecall|DELEGATECALL/,
      /implementation\(\)|_implementation/i,
    ],
    bytecodePatterns: [
      "363d3d373d3d3d363d", // EIP-1167 minimal proxy prefix
    ],
  },
  {
    id: "proxy-storage-collision",
    name: "Storage Collision (Proxy-Implementation)",
    severity: "critical",
    description:
      "Proxy and implementation contract use the same storage slot for different variables, causing data corruption.",
    riskWeight: 85,
    sourcePatterns: [
      /sload\s*\(\s*0x[0-9a-f]+\s*\)/i,
      /bytes32\s+(?:private\s+)?constant\s+\w*(?:SLOT|POSITION|LOCATION)\s*=\s*(?:0x|keccak256)/i,
      /StorageSlot\.getAddressSlot/,
    ],
  },
  {
    id: "proxy-uninitialized-impl",
    name: "Uninitialized Implementation Contract",
    severity: "critical",
    description:
      "Implementation contract is not initialized, allowing an attacker to call initialize() and claim ownership.",
    riskWeight: 90,
    sourcePatterns: [
      /constructor\s*\(\s*\)\s*\{[\s\S]{0,50}_disableInitializers/s,
      /function\s+initialize[\s\S]{0,500}initializer/s,
    ],
  },
  {
    id: "proxy-selector-clash",
    name: "Function Selector Clash (Proxy)",
    severity: "high",
    description:
      "Proxy and implementation have functions with the same 4-byte selector, causing unexpected behavior.",
    riskWeight: 70,
    sourcePatterns: [
      /TransparentUpgradeableProxy/,
      /ifAdmin/,
    ],
  },
  {
    id: "proxy-uups-bricking",
    name: "UUPS Upgrade Bricking Risk",
    severity: "critical",
    description:
      "UUPS proxy can be permanently bricked by upgrading to an implementation without the upgrade function.",
    riskWeight: 85,
    sourcePatterns: [
      /UUPSUpgradeable/,
      /_authorizeUpgrade\s*\(/,
      /upgradeTo\s*\(|upgradeToAndCall\s*\(/,
    ],
  },
  {
    id: "proxy-missing-gap",
    name: "Missing Storage Gap",
    severity: "medium",
    description:
      "Base contract lacks __gap storage variable, making future upgrades risky due to storage layout shifts.",
    riskWeight: 40,
    sourcePatterns: [
      /contract\s+\w+\s+is\s+[\w,\s]*Upgradeable[\s\S]{0,3000}(?!__gap|_gap)/s,
    ],
  },
  {
    id: "proxy-unauthorized-upgrade",
    name: "Unauthorized Upgrade",
    severity: "critical",
    description:
      "Upgrade functions lack proper access control, allowing anyone to replace the implementation.",
    riskWeight: 90,
    sourcePatterns: [
      /function\s+upgradeTo\w*\s*\([^)]*\)\s*(?:external|public)\s*(?!.*onlyOwner|onlyAdmin|onlyRole|auth)/s,
      /function\s+_authorizeUpgrade[^{]*\{[\s]*\}/s,
    ],
  },

  // =========================================================================
  // Category 6: Signature & Cryptographic Issues (6)
  // =========================================================================

  {
    id: "sig-replay-attack",
    name: "Signature Replay Attack",
    severity: "critical",
    description:
      "Missing nonce tracking allows a valid signature to be reused multiple times.",
    riskWeight: 85,
    sourcePatterns: [
      /ecrecover[\s\S]{0,500}(?!nonce|_nonces|usedSignatures|usedHashes)/s,
      /ECDSA\.recover[\s\S]{0,500}(?!nonce|_nonces)/s,
    ],
  },
  {
    id: "sig-cross-chain-replay",
    name: "Cross-Chain Signature Replay",
    severity: "high",
    description:
      "Signature lacks chain ID binding, allowing it to be replayed on other chains where the contract is deployed.",
    riskWeight: 70,
    sourcePatterns: [
      /ecrecover[\s\S]{0,500}(?!block\.chainid|chainId|chain_id|DOMAIN_SEPARATOR)/s,
    ],
  },
  {
    id: "sig-malleability",
    name: "Signature Malleability",
    severity: "high",
    description:
      "ecrecover allows malleable s-value manipulation. Signatures should enforce s < secp256k1n/2.",
    riskWeight: 65,
    sourcePatterns: [
      /ecrecover\s*\([\s\S]{0,200}(?!ECDSA\.recover|SignatureChecker|s\s*<|s\s*<=)/s,
    ],
  },
  {
    id: "sig-ecrecover-zero",
    name: "ecrecover Returns address(0)",
    severity: "high",
    description:
      "ecrecover returns address(0) for invalid signatures. Not checking for zero address treats invalid signatures as valid.",
    riskWeight: 70,
    sourcePatterns: [
      /ecrecover\s*\([^)]+\)\s*(?![\s\S]{0,50}!=\s*address\(0\)|[\s\S]{0,50}require)/s,
      /address\s+\w+\s*=\s*ecrecover[\s\S]{0,100}(?!require|!=\s*address\(0\))/s,
    ],
  },
  {
    id: "sig-missing-domain-separator",
    name: "Missing EIP-712 Domain Separator",
    severity: "medium",
    description:
      "Signatures lack structured domain binding (EIP-712), making them replayable across contracts.",
    riskWeight: 45,
    sourcePatterns: [
      /ecrecover[\s\S]{0,500}(?!DOMAIN_SEPARATOR|EIP712|_domainSeparatorV4|domainSeparator)/s,
    ],
  },
  {
    id: "sig-permit-replay",
    name: "Permit/EIP-2612 Replay",
    severity: "high",
    description:
      "Permit signatures can be replayed after deadline manipulation or without proper nonce invalidation.",
    riskWeight: 65,
    sourcePatterns: [
      /function\s+permit\s*\([^)]*deadline[\s\S]{0,300}(?!_nonces|nonces\[)/s,
      /function\s+permit[\s\S]{0,500}(?!_useNonce|nonces\[)/s,
    ],
  },

  // =========================================================================
  // Category 7: Weird ERC20 Behaviors (7)
  // =========================================================================

  {
    id: "erc20-missing-return",
    name: "Missing Return Value (USDT-style)",
    severity: "medium",
    description:
      "Token transfer/approve does not return a bool, breaking callers that check the return value (e.g., USDT).",
    riskWeight: 40,
    sourcePatterns: [
      /function\s+transfer\s*\([^)]*\)\s*(?:external|public)\s*(?!.*returns\s*\(\s*bool)/s,
      /function\s+approve\s*\([^)]*\)\s*(?:external|public)\s*(?!.*returns\s*\(\s*bool)/s,
      /\.transfer\s*\([\s\S]{0,50}(?!safeTransfer|SafeERC20)/s,
    ],
  },
  {
    id: "erc20-fee-on-transfer",
    name: "Fee-on-Transfer Token Detection",
    severity: "high",
    description:
      "Protocol assumes received amount equals sent amount, but fee-on-transfer tokens deduct fees, causing accounting errors.",
    riskWeight: 65,
    sourcePatterns: [
      /transferFrom\s*\([^)]*,\s*address\(this\)\s*,\s*(\w+)\s*\)[\s\S]{0,100}\1(?!\s*=\s*\w+\.balanceOf)/s,
      /transferFrom[\s\S]{0,200}(?!balanceOf\(address\(this\)\)\s*-\s*\w+before|balanceAfter\s*-\s*balanceBefore)/s,
    ],
  },
  {
    id: "erc20-rebasing",
    name: "Rebasing Token Detection",
    severity: "high",
    description:
      "Protocol caches token balances but does not handle automatic rebasing, leading to stale balance accounting.",
    riskWeight: 60,
    sourcePatterns: [
      /rebase\s*\(|_rebase|rebaseOptIn|rebaseOptOut/i,
      /scaledBalance|internalBalance|_gonBalance/i,
    ],
  },
  {
    id: "erc20-pausable",
    name: "Pausable Token Risk",
    severity: "medium",
    description:
      "Token admin can pause all transfers, freezing protocol funds that depend on the token.",
    riskWeight: 40,
    sourcePatterns: [
      /function\s+pause\s*\(\s*\)\s*(?:external|public)[\s\S]{0,100}whenNotPaused/s,
      /Pausable|_pause\(\)|_unpause\(\)/,
    ],
  },
  {
    id: "erc20-callback-reentrancy",
    name: "Token with Callbacks (ERC777/ERC1363)",
    severity: "high",
    description:
      "Token implements transfer hooks (ERC777/ERC1363) that enable reentrancy during transfers.",
    riskWeight: 65,
    sourcePatterns: [
      /IERC777|ERC777|IERC1363|ERC1363/,
      /onTransferReceived|tokensReceived/,
    ],
  },
  {
    id: "erc20-return-bomb",
    name: "Return Bomb via Malicious Token",
    severity: "high",
    description:
      "Malicious token returns excessive data from transfer/approve, consuming all available gas.",
    riskWeight: 65,
    sourcePatterns: [
      /assembly\s*\{[^}]*returndatacopy[^}]*returndatasize/s,
      /returndatasize\s*\(\s*\)/,
    ],
  },
  {
    id: "erc20-approval-race",
    name: "Approval Race Condition",
    severity: "medium",
    description:
      "Changing approval from N to M allows spender to spend N+M via a front-run. Use increaseAllowance/decreaseAllowance instead.",
    riskWeight: 35,
    sourcePatterns: [
      /function\s+approve\s*\([^)]*\)[\s\S]{0,200}allowance\s*\[[^]]*\]\s*=\s*\w+\s*;[\s\S]{0,100}(?!increaseAllowance|decreaseAllowance)/s,
    ],
  },

  // =========================================================================
  // Category 8: DeFi-Specific Patterns (7)
  // =========================================================================

  {
    id: "defi-vault-inflation",
    name: "ERC4626 Vault Inflation Attack",
    severity: "critical",
    description:
      "First depositor can donate assets to manipulate the share price, stealing subsequent depositors' funds.",
    riskWeight: 85,
    sourcePatterns: [
      /totalAssets\s*\(\s*\)/,
      /function\s+deposit[\s\S]{0,300}totalSupply\s*\(\s*\)\s*==\s*0/s,
      /ERC4626|ERC-4626/,
    ],
  },
  {
    id: "defi-slippage-bypass",
    name: "Slippage Protection Bypass",
    severity: "high",
    description:
      "Missing or inadequate slippage checks allow MEV bots to extract value from trades.",
    riskWeight: 70,
    sourcePatterns: [
      /amountOutMin\s*(?:=|:)\s*0/,
      /minAmountOut\s*(?:=|:)\s*0/,
      /swapExact\w+\([^)]*,\s*0\s*,/,
      /function\s+swap[\s\S]{0,300}(?!slippage|minAmount|amountOutMin|deadline)/s,
    ],
  },
  {
    id: "defi-flash-loan-unrestricted",
    name: "Flash Loan Vulnerability",
    severity: "high",
    description: "Price oracle or balance check is manipulable within a single transaction.",
    riskWeight: 70,
    sourcePatterns: [
      /getReserves\(\).*?price/s,
      /balanceOf\(address\(this\)\).*?price/s,
      /flashLoan|flashBorrow/,
    ],
  },
  {
    id: "defi-donation-attack",
    name: "Share Price Manipulation via Donation",
    severity: "critical",
    description:
      "Direct token transfer to a vault or pool inflates the share/LP price, enabling theft of subsequent deposits.",
    riskWeight: 85,
    sourcePatterns: [
      /balanceOf\(address\(this\)\)\s*[\/-]\s*totalSupply/,
      /totalAssets[\s\S]{0,100}balanceOf\(address\(this\)\)/s,
    ],
  },
  {
    id: "defi-reward-manipulation",
    name: "Reward Distribution Rounding Exploit",
    severity: "high",
    description:
      "Rounding errors in reward-per-share calculations allow repeated claim/withdraw cycles to extract extra value.",
    riskWeight: 65,
    sourcePatterns: [
      /rewardPerShare|rewardPerToken|accRewardPerShare/i,
      /reward\s*=.*?\/\s*totalSupply/,
      /accumulatedReward|pendingReward/i,
    ],
  },
  {
    id: "defi-liquidation-flaw",
    name: "Liquidation Threshold Bypass",
    severity: "high",
    description:
      "Logic flaws in liquidation mechanics allow positions to avoid liquidation when under-collateralized.",
    riskWeight: 70,
    sourcePatterns: [
      /function\s+liquidate[\s\S]{0,500}(?:healthFactor|collateralRatio)/s,
      /isLiquidatable|canLiquidate/i,
    ],
  },
  {
    id: "defi-interest-rate-manipulation",
    name: "Interest Rate Manipulation",
    severity: "high",
    description:
      "Exploiting the interest rate model to create extreme borrow/supply rates that extract value.",
    riskWeight: 60,
    sourcePatterns: [
      /utilizationRate|getUtilization/i,
      /borrowRate\s*=[\s\S]{0,200}(?:baseRate|multiplier|kink)/s,
    ],
  },

  // =========================================================================
  // Category 9: DoS Patterns (7)
  // =========================================================================

  {
    id: "dos-failed-call",
    name: "DoS with Failed External Call",
    severity: "high",
    description:
      "One failed external call in a loop blocks the entire operation, letting a single malicious actor prevent payouts.",
    riskWeight: 65,
    sourcePatterns: [
      /for\s*\([^)]*\)\s*\{[\s\S]{0,300}\.(?:transfer|send|call)\s*[({]/s,
      /for\s*\([^)]*\)\s*\{[\s\S]{0,300}require[\s\S]{0,100}\.call\{/s,
    ],
  },
  {
    id: "dos-block-gas-limit",
    name: "Block Gas Limit DoS",
    severity: "high",
    description:
      "Unbounded loops iterating over growing arrays can exceed the block gas limit, permanently bricking the function.",
    riskWeight: 65,
    sourcePatterns: [
      /for\s*\(\s*uint\w*\s+\w+\s*=\s*0\s*;\s*\w+\s*<\s*\w+\.length\s*;/,
      /while\s*\(\s*\w+\s*<\s*\w+\.length\s*\)/,
    ],
  },
  {
    id: "dos-return-bomb",
    name: "Return Bomb Attack",
    severity: "high",
    description:
      "Malicious callee returns excessive data, consuming all gas via implicit memory expansion in Solidity.",
    riskWeight: 65,
    sourcePatterns: [
      /\(bool\s+\w+,\s*bytes\s+memory\s+\w+\)\s*=\s*\w+\.call/,
      /\(bool\s+\w+,\s*\)\s*=\s*\w+\.call[\s\S]{0,50}(?!assembly)/s,
    ],
  },
  {
    id: "dos-unbounded-loop",
    name: "Unbounded Loop Over Storage Array",
    severity: "medium",
    description:
      "Growing storage array with unbounded iteration causes gas costs to increase indefinitely.",
    riskWeight: 45,
    sourcePatterns: [
      /\.push\s*\([\s\S]{0,500}for\s*\([^)]*\w+\.length/s,
      /for\s*\([^)]*\w+\.length[\s\S]{0,200}(?!break|return)/s,
    ],
  },
  {
    id: "dos-unexpected-ether",
    name: "Unexpected Ether via Selfdestruct/Coinbase",
    severity: "medium",
    description:
      "Contract logic depends on address(this).balance, which can be manipulated by forcibly sending ETH via selfdestruct.",
    riskWeight: 40,
    sourcePatterns: [
      /require\s*\([^)]*address\(this\)\.balance\s*==\s*/,
      /assert\s*\([^)]*address\(this\)\.balance/,
      /if\s*\([^)]*address\(this\)\.balance\s*==\s*/,
    ],
  },
  {
    id: "dos-gas-griefing",
    name: "Gas Griefing (Insufficient Gas Forwarding)",
    severity: "high",
    description:
      "Relayer or caller forwards insufficient gas to a subcall, causing the inner operation to fail silently.",
    riskWeight: 60,
    sourcePatterns: [
      /\.call\{gas:\s*\d+\}/,
      /gasleft\s*\(\s*\)\s*[\/<]\s*\d+/,
    ],
  },
  {
    id: "dos-calls-in-loop",
    name: "External Calls in Loop",
    severity: "medium",
    description:
      "Multiple external calls inside a loop create both DoS risk and potential reentrancy vectors.",
    riskWeight: 45,
    sourcePatterns: [
      /for\s*\([^)]*\)\s*\{[\s\S]{0,200}\.call\{/s,
      /for\s*\([^)]*\)\s*\{[\s\S]{0,200}\.transfer\s*\(/s,
    ],
  },

  // =========================================================================
  // Category 10: Input Validation & Miscellaneous (11)
  // =========================================================================

  {
    id: "input-missing-zero-address",
    name: "Missing Zero-Address Check",
    severity: "medium",
    description:
      "Functions accept address(0) as parameter, risking permanent loss of funds or ownership.",
    riskWeight: 35,
    sourcePatterns: [
      /function\s+\w+\s*\([^)]*address\s+\w+[^)]*\)[^{]*\{(?![^}]*require\s*\([^)]*!=\s*address\(0\))/s,
    ],
  },
  {
    id: "input-missing-amount-validation",
    name: "Missing Amount Validation",
    severity: "medium",
    description:
      "No check for zero or excessive amounts allows no-op operations or integer overflows.",
    riskWeight: 35,
    sourcePatterns: [
      /function\s+(?:deposit|withdraw|stake|unstake|transfer)\s*\([^)]*uint\d*\s+\w*amount\w*[^)]*\)[^{]*\{(?![^}]*require\s*\([^)]*>\s*0)/s,
    ],
  },
  {
    id: "input-array-length-mismatch",
    name: "Array Length Mismatch",
    severity: "medium",
    description:
      "Multiple array parameters without equal length verification can cause out-of-bounds or partial execution.",
    riskWeight: 40,
    sourcePatterns: [
      /function\s+\w+\s*\([^)]*\[\s*\]\s+\w+\s*,\s*[^)]*\[\s*\]\s+\w+[^)]*\)[\s\S]{0,200}(?!\.length\s*==\s*\w+\.length|require)/s,
    ],
  },
  {
    id: "arithmetic-unchecked-overflow",
    name: "Unchecked Arithmetic Overflow",
    severity: "high",
    description:
      "Arithmetic inside unchecked blocks bypasses Solidity 0.8+ overflow protection, reintroducing overflow risk.",
    riskWeight: 65,
    sourcePatterns: [
      /unchecked\s*\{[\s\S]{0,300}[\+\-\*]/s,
    ],
  },
  {
    id: "arithmetic-precision-loss",
    name: "Precision Loss (Division Before Multiplication)",
    severity: "high",
    description:
      "Dividing before multiplying causes truncation/precision loss, which can be exploited in financial calculations.",
    riskWeight: 60,
    sourcePatterns: [
      /\w+\s*\/\s*\w+\s*\*\s*\w+/,
      /\(\s*\w+\s*\/\s*\d+\s*\)\s*\*/,
    ],
  },
  {
    id: "arithmetic-unsafe-downcast",
    name: "Unsafe Downcasting",
    severity: "high",
    description:
      "Casting uint256 to a smaller type (uint128, uint96, etc.) silently truncates, potentially corrupting values.",
    riskWeight: 60,
    sourcePatterns: [
      /uint(?:8|16|32|64|96|128)\s*\(\s*\w+\s*\)/,
      /int(?:8|16|32|64|96|128)\s*\(\s*\w+\s*\)/,
    ],
  },
  {
    id: "weak-randomness",
    name: "Weak Randomness from Chain Attributes",
    severity: "high",
    description:
      "Using blockhash, block.timestamp, or block.difficulty for randomness is predictable and manipulable by miners/validators.",
    riskWeight: 65,
    sourcePatterns: [
      /keccak256\s*\(\s*abi\.encode(?:Packed)?\s*\([^)]*block\.(?:timestamp|difficulty|number|prevrandao)/,
      /blockhash\s*\([^)]*\)[\s\S]{0,100}(?:random|seed|lottery|winner)/is,
    ],
  },
  {
    id: "unchecked-call-return",
    name: "Unchecked Low-Level Call Return",
    severity: "high",
    description:
      "Not checking the bool return value from .call(), .send(), or .delegatecall() allows silent failures.",
    riskWeight: 65,
    sourcePatterns: [
      /\w+\.call\{[\s\S]{0,50}\}[\s\S]{0,50};\s*(?!require|if\s*\(|assert)/s,
      /\w+\.send\s*\([^)]*\)\s*;(?!\s*require)/,
    ],
  },
  {
    id: "hash-collision-encodepacked",
    name: "Hash Collision with abi.encodePacked",
    severity: "high",
    description:
      "Multiple dynamic types in abi.encodePacked produce ambiguous encoding, enabling hash collision attacks.",
    riskWeight: 60,
    sourcePatterns: [
      /keccak256\s*\(\s*abi\.encodePacked\s*\([^)]*(?:string|bytes)\s+\w+\s*,\s*(?:string|bytes)\s+\w+/,
      /abi\.encodePacked\s*\([^)]*\[\s*\][^)]*,\s*[^)]*\[\s*\]/,
    ],
  },
  {
    id: "arbitrary-storage-write",
    name: "Write to Arbitrary Storage Location",
    severity: "critical",
    description:
      "Attacker-controlled array index allows writing to any storage slot, enabling complete contract takeover.",
    riskWeight: 90,
    sourcePatterns: [
      /assembly\s*\{[^}]*sstore\s*\(\s*\w+/i,
      /\w+\[\s*\w+\s*\]\s*=[\s\S]{0,50}(?!mapping|require)/s,
    ],
  },
  {
    id: "rtlo-character",
    name: "Right-to-Left Override Character",
    severity: "high",
    description:
      "Unicode RTLO character (U+202E) disguises malicious code by reversing text display direction.",
    riskWeight: 70,
    sourcePatterns: [
      /\u202e/,
    ],
  },

  // =========================================================================
  // Additional High-Impact Patterns (11)
  // =========================================================================

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
    id: "mev-sandwich-risk",
    name: "MEV Sandwich Risk",
    severity: "high",
    description:
      "Swap calls without slippage protection are vulnerable to sandwich attacks targeting automated traders.",
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
  {
    id: "locked-ether",
    name: "Locked Ether (No Withdrawal)",
    severity: "medium",
    description:
      "Contract accepts ETH (has receive/fallback or payable functions) but has no withdrawal mechanism, permanently locking funds.",
    riskWeight: 40,
    sourcePatterns: [
      /receive\s*\(\s*\)\s*external\s*payable[\s\S]{0,2000}(?!withdraw|transfer|call\{value)/s,
      /fallback\s*\(\s*\)\s*external\s*payable[\s\S]{0,2000}(?!withdraw)/s,
    ],
  },
  {
    id: "timestamp-dependence",
    name: "Block Timestamp Manipulation",
    severity: "medium",
    description:
      "Miner-manipulable block.timestamp used for critical logic such as deadlines, randomness, or time-locked operations.",
    riskWeight: 35,
    sourcePatterns: [
      /block\.timestamp\s*(?:==|<|>|<=|>=)\s*\w+/,
      /require\s*\([^)]*block\.timestamp/,
    ],
  },
  {
    id: "governance-flash-vote",
    name: "Flash Loan Voting Power",
    severity: "critical",
    description:
      "Flash-borrowed tokens can be used to vote on governance proposals, allowing instant hostile takeover.",
    riskWeight: 80,
    sourcePatterns: [
      /function\s+(?:castVote|vote)\s*\([^)]*\)[\s\S]{0,300}balanceOf/s,
      /votingPower\s*=\s*\w+\.balanceOf/,
    ],
  },
  {
    id: "hardcoded-gas-transfer",
    name: "Hardcoded Gas in .transfer()/.send()",
    severity: "medium",
    description:
      "Using .transfer() or .send() forwards only 2300 gas, which may fail after EIP-1884 gas cost changes.",
    riskWeight: 35,
    sourcePatterns: [
      /payable\s*\([^)]*\)\s*\.transfer\s*\(/,
      /payable\s*\([^)]*\)\s*\.send\s*\(/,
    ],
  },

  // =========================================================================
  // Category 11: Flash Loan Attack Patterns (5)
  // =========================================================================

  {
    id: "flash-loan-oracle-manipulation",
    name: "Flash Loan Oracle Manipulation",
    severity: "critical",
    description:
      "Flash-borrowed funds manipulate AMM spot price used as an oracle, enabling theft of protocol funds within a single transaction.",
    riskWeight: 90,
    sourcePatterns: [
      /flashLoan[\s\S]{0,1000}getReserves/s,
      /flashBorrow[\s\S]{0,1000}getReserves/s,
      /IFlashLoan[\s\S]{0,500}price/s,
    ],
  },
  {
    id: "flash-loan-governance",
    name: "Flash Loan Governance Attack",
    severity: "critical",
    description:
      "Flash-borrowed tokens used to pass malicious governance proposals within a single transaction.",
    riskWeight: 85,
    sourcePatterns: [
      /flashLoan[\s\S]{0,1000}(?:castVote|propose|vote)/s,
      /function\s+(?:propose|castVote)[\s\S]{0,300}balanceOf[\s\S]{0,300}(?!getPastVotes|getPriorVotes)/s,
    ],
  },
  {
    id: "flash-loan-vault-inflation",
    name: "Flash Loan Vault Inflation",
    severity: "high",
    description:
      "Flash loan funds donated to a vault to manipulate share price and steal subsequent deposits.",
    riskWeight: 75,
    sourcePatterns: [
      /flashLoan[\s\S]{0,1000}deposit[\s\S]{0,300}totalAssets/s,
      /IFlashLoan[\s\S]{0,500}(?:donate|transfer)[\s\S]{0,300}vault/s,
    ],
  },
  {
    id: "flash-loan-liquidation-trigger",
    name: "Flash Loan Liquidation Trigger",
    severity: "high",
    description:
      "Flash loan artificially depresses collateral price to trigger profitable liquidations.",
    riskWeight: 70,
    sourcePatterns: [
      /flashLoan[\s\S]{0,1000}liquidat/s,
      /IFlashLoan[\s\S]{0,500}liquidat/s,
    ],
  },
  {
    id: "flash-loan-arbitrage-drain",
    name: "Flash Loan Arbitrage Drain",
    severity: "high",
    description:
      "Flash loan exploits price discrepancies across pools to drain LP value in a single atomic transaction.",
    riskWeight: 65,
    sourcePatterns: [
      /flashLoan[\s\S]{0,1000}swap[\s\S]{0,500}swap/s,
      /IFlashLoan[\s\S]{0,500}IUniswap/s,
    ],
  },

  // =========================================================================
  // Category 12: MEV & Front-Running (5)
  // =========================================================================

  {
    id: "mev-front-running-risk",
    name: "Front-Running (Transaction Order Dependence)",
    severity: "high",
    description:
      "Function outcome depends on transaction ordering, making it vulnerable to miners or MEV bots reordering for profit.",
    riskWeight: 60,
    sourcePatterns: [
      /function\s+(?:reveal|claim|redeem)\s*\([^)]*\)[\s\S]{0,300}(?!commit|deadline)/s,
      /firstComer|firstDepositor|earlyBird/i,
    ],
  },
  {
    id: "mev-jit-liquidity",
    name: "JIT Liquidity Attack",
    severity: "medium",
    description:
      "MEV bot adds concentrated liquidity just before a large swap and removes it after, capturing fees that should go to LPs.",
    riskWeight: 45,
    sourcePatterns: [
      /function\s+mint[\s\S]{0,200}tickLower[\s\S]{0,200}tickUpper/s,
      /INonfungiblePositionManager/,
    ],
  },
  {
    id: "mev-block-stuffing",
    name: "Block Stuffing Attack",
    severity: "medium",
    description:
      "Attacker fills blocks with junk transactions to delay time-sensitive operations like liquidations or auctions.",
    riskWeight: 40,
    sourcePatterns: [
      /block\.number\s*-\s*\w+\s*(?:>=|>)\s*\d+/,
      /deadline\s*=\s*block\.number\s*\+/,
    ],
  },
  {
    id: "mev-displacement-attack",
    name: "Displacement Attack",
    severity: "medium",
    description:
      "Attacker replaces a victim's transaction entirely by submitting a competing one with higher gas.",
    riskWeight: 40,
    sourcePatterns: [
      /function\s+(?:claimFirst|firstToCall|claimReward)\s*\(/i,
      /require\s*\([^)]*!?\s*claimed\s*\[/,
    ],
  },
  {
    id: "mev-commit-reveal-missing",
    name: "Front-Runnable Commit-Reveal",
    severity: "high",
    description:
      "Information leaks during the commit phase of a commit-reveal scheme, allowing extraction before reveal.",
    riskWeight: 65,
    sourcePatterns: [
      /function\s+commit\s*\([^)]*bytes32[\s\S]{0,300}function\s+reveal/s,
      /commitHash[\s\S]{0,300}keccak256[\s\S]{0,200}reveal/s,
    ],
  },

  // =========================================================================
  // Category 13: Governance Attacks (5)
  // =========================================================================

  {
    id: "governance-snapshot-exploit",
    name: "Same-Transaction Snapshot Exploit",
    severity: "high",
    description:
      "Governance snapshot taken in the same block as token acquisition, allowing flash-bought tokens to count for voting.",
    riskWeight: 70,
    sourcePatterns: [
      /function\s+snapshot[\s\S]{0,300}balanceOf/s,
      /votingPower[\s\S]{0,200}(?!getPastVotes|getPriorVotes|snapshot|checkpoints)/s,
    ],
  },
  {
    id: "governance-emergency-bypass",
    name: "Emergency Execute Without Timelock",
    severity: "critical",
    description:
      "Emergency governance functions bypass the timelock, allowing instant execution of arbitrary proposals.",
    riskWeight: 85,
    sourcePatterns: [
      /function\s+emergency\w*\s*\([^)]*\)[\s\S]{0,200}(?:execute|call)\s*\(/s,
      /function\s+\w*emergency\w*\s*\([^)]*\)[\s\S]{0,200}\.call\{/s,
    ],
  },
  {
    id: "governance-low-quorum",
    name: "Low Quorum Exploitation",
    severity: "high",
    description:
      "Governance proposals can pass with extremely low participation, enabling minority takeover.",
    riskWeight: 65,
    sourcePatterns: [
      /quorum\s*(?:=|:)\s*\d{1,3}\b/,
      /quorumNumerator\s*(?:=|:)\s*[1-4]\b/,
      /function\s+quorum[\s\S]{0,200}return\s+\d{1,5}\s*;/s,
    ],
  },
  {
    id: "governance-proposal-obfuscation",
    name: "Proposal Obfuscation",
    severity: "high",
    description:
      "Governance proposal contains encoded calldata that performs different actions than what the description suggests.",
    riskWeight: 70,
    sourcePatterns: [
      /function\s+propose[\s\S]{0,300}bytes\s+(?:memory\s+)?calldata/s,
      /abi\.encode(?:WithSelector|Call)[\s\S]{0,200}propose/s,
    ],
  },
  {
    id: "governance-timelock-takeover",
    name: "Timelock Admin Takeover",
    severity: "critical",
    description:
      "Governance proposal changes the timelock admin to an attacker-controlled address, giving full protocol control.",
    riskWeight: 90,
    sourcePatterns: [
      /setPendingAdmin|updateAdmin|changeAdmin/,
      /function\s+\w+[\s\S]{0,200}TimelockController[\s\S]{0,200}grantRole/s,
    ],
  },

  // =========================================================================
  // Category 14: Cross-Chain & Bridge Vulnerabilities (5)
  // =========================================================================

  {
    id: "bridge-replay-attack",
    name: "Cross-Chain Replay Attack",
    severity: "critical",
    description:
      "Bridge messages lack chain-specific binding, allowing a valid message on one chain to be replayed on another.",
    riskWeight: 90,
    sourcePatterns: [
      /function\s+\w*(?:bridge|relay|receive)\w*[\s\S]{0,500}(?!block\.chainid|chainId|sourceChain)/s,
      /function\s+\w*(?:send|dispatch)\w*Message[\s\S]{0,500}(?!chainId)/s,
    ],
  },
  {
    id: "bridge-fake-deposit",
    name: "False Deposit / Fake Proof",
    severity: "critical",
    description:
      "Minting tokens on the destination chain without a valid deposit or with a forged Merkle proof.",
    riskWeight: 95,
    sourcePatterns: [
      /function\s+\w*(?:mint|release|unlock)\w*[\s\S]{0,300}(?:proof|message)[\s\S]{0,200}(?!verify|MerkleProof)/s,
      /function\s+processMessage[\s\S]{0,500}(?!verifyProof|verifyMessage)/s,
    ],
  },
  {
    id: "bridge-validator-compromise",
    name: "Bridge Validator/Signer Key Compromise",
    severity: "critical",
    description:
      "Bridge security depends on a small set of validator keys; compromising a majority allows minting unbacked tokens.",
    riskWeight: 95,
    sourcePatterns: [
      /threshold\s*(?:=|:)\s*[1-3]\b/,
      /require\s*\([^)]*signatures\.length\s*>=\s*[1-3]\b/,
      /minSignatures\s*(?:=|:)\s*[1-3]\b/,
    ],
  },
  {
    id: "bridge-merkle-flaw",
    name: "Merkle Proof Verification Flaw",
    severity: "critical",
    description:
      "Bug in Merkle proof validation allows forged proofs, enabling unauthorized minting or withdrawals.",
    riskWeight: 90,
    sourcePatterns: [
      /MerkleProof\.verify[\s\S]{0,200}(?:mint|transfer|release)/s,
      /function\s+verify\w*Proof[\s\S]{0,300}keccak256/s,
    ],
  },
  {
    id: "bridge-message-replay",
    name: "Bridge Message Replay",
    severity: "high",
    description:
      "Cross-chain messages can be replayed without proper nonce or hash invalidation, doubling withdrawals.",
    riskWeight: 75,
    sourcePatterns: [
      /function\s+\w*(?:execute|process|relay)\w*Message[\s\S]{0,500}(?!processedMessages|usedNonces|executedMessages)/s,
      /function\s+onMessage[\s\S]{0,300}(?!nonce|processed)/s,
    ],
  },

  // =========================================================================
  // Category 15: NFT-Specific Vulnerabilities (5)
  // =========================================================================

  {
    id: "nft-unsafe-mint",
    name: "Unsafe Mint (Missing onERC721Received)",
    severity: "medium",
    description:
      "Using _mint instead of _safeMint risks sending NFTs to contracts that cannot handle them, permanently locking the token.",
    riskWeight: 35,
    sourcePatterns: [
      /ERC721[\s\S]{0,1000}_mint\s*\([^)]*\)[\s\S]{0,200}(?!_checkOnERC721Received|_safeMint)/s,
      /ERC1155[\s\S]{0,1000}_mint\s*\([^)]*\)[\s\S]{0,200}(?!_doSafeTransfer)/s,
    ],
  },
  {
    id: "nft-metadata-tamper",
    name: "NFT Metadata Tampering",
    severity: "medium",
    description:
      "Mutable on-chain or off-chain metadata allows the owner to change NFT attributes or images post-sale.",
    riskWeight: 40,
    sourcePatterns: [
      /function\s+set\w*(?:URI|BaseURI|TokenURI|Metadata)\s*\(/i,
      /function\s+\w+[^}]*(?:_baseURI|baseURI)\s*=[^}]*onlyOwner/s,
    ],
  },
  {
    id: "nft-price-error",
    name: "NFT Price Calculation Error",
    severity: "critical",
    description:
      "Logic flaws in mint price calculation allow zero-cost minting or purchasing at drastically reduced prices.",
    riskWeight: 85,
    sourcePatterns: [
      /function\s+mint[\s\S]{0,300}msg\.value\s*>=?\s*(?:0|price\s*\*\s*0)/s,
      /require\s*\([^)]*msg\.value[\s\S]{0,50}(?:price|cost)[\s\S]{0,50}\)/s,
    ],
  },
  {
    id: "nft-unrestricted-mint",
    name: "Unrestricted Mint / Public Mint Bypass",
    severity: "high",
    description:
      "Mint quantity limits can be bypassed by calling from multiple contracts or by re-entering the mint function.",
    riskWeight: 70,
    sourcePatterns: [
      /require\s*\([^)]*balanceOf\s*\(\s*msg\.sender\s*\)/,
      /mintedAmount\s*\[\s*msg\.sender\s*\][\s\S]{0,100}(?!tx\.origin)/s,
      /function\s+mint[\s\S]{0,200}maxPerWallet/s,
    ],
  },
  {
    id: "nft-flash-loan-reward",
    name: "NFT Flash Loan for Reward Claiming",
    severity: "high",
    description:
      "Flash-borrowed NFTs used to claim staking rewards, draining the reward pool without actual stake duration.",
    riskWeight: 70,
    sourcePatterns: [
      /function\s+claimReward[\s\S]{0,300}ownerOf/s,
      /function\s+\w*claim\w*[\s\S]{0,300}ERC721[\s\S]{0,200}(?!stakedSince|stakeTimestamp|lastClaimed)/s,
    ],
  },

  // =========================================================================
  // Category 16: Solidity/EVM Specific (8)
  // =========================================================================

  {
    id: "evm-uninitialized-storage",
    name: "Uninitialized Storage Pointer",
    severity: "high",
    description:
      "Local storage variable defaults to slot 0, silently overwriting critical state variables like owner.",
    riskWeight: 70,
    sourcePatterns: [
      /function\s+\w+[^{]*\{[^}]*(?:struct|mapping)\s+\w+\s+\w+\s*;/s,
      /(?:uint|int|address|bool|bytes)\s+storage\s+\w+\s*;/,
    ],
  },
  {
    id: "evm-state-variable-shadowing",
    name: "State Variable Shadowing",
    severity: "medium",
    description:
      "Derived contract declares a variable with the same name as one in the base contract, creating two separate storage slots.",
    riskWeight: 40,
    sourcePatterns: [
      /contract\s+\w+\s+is\s+\w+[\s\S]{0,500}(?:uint|int|address|bool|mapping)\s+(?:public\s+|private\s+|internal\s+)?\w+\s*(?:=|;)/s,
    ],
  },
  {
    id: "evm-incorrect-inheritance",
    name: "Incorrect Inheritance Order",
    severity: "medium",
    description:
      "C3 linearization with incorrect inheritance order causes unexpected function resolution, overriding intended behavior.",
    riskWeight: 45,
    sourcePatterns: [
      /contract\s+\w+\s+is\s+\w+\s*,\s*\w+\s*,\s*\w+/,
    ],
  },
  {
    id: "evm-floating-pragma",
    name: "Floating Pragma",
    severity: "info",
    description:
      "Unlocked compiler version (^0.8.x) risks deployment with a buggy compiler version.",
    riskWeight: 10,
    sourcePatterns: [
      /pragma\s+solidity\s+\^/,
      /pragma\s+solidity\s+>=\s*0\.\d+\.\d+\s*</,
    ],
  },
  {
    id: "evm-deprecated-functions",
    name: "Deprecated Solidity Functions",
    severity: "low",
    description:
      "Use of deprecated functions (suicide, sha3, throw, msg.gas) indicates old code that may have unpatched bugs.",
    riskWeight: 20,
    sourcePatterns: [
      /\bsuicide\s*\(/,
      /\bsha3\s*\(/,
      /\bthrow\b;/,
      /\bmsg\.gas\b/,
    ],
  },
  {
    id: "evm-typo-operator",
    name: "Typographical Error (Wrong Operator)",
    severity: "medium",
    description:
      "Using =+ instead of += or similar typos silently changes assignment semantics, leading to wrong values.",
    riskWeight: 50,
    sourcePatterns: [
      /\w+\s*=\+\s*\w+/,
      /\w+\s*=-\s*\w+/,
    ],
  },
  {
    id: "evm-division-by-zero",
    name: "Division by Zero",
    severity: "medium",
    description:
      "Missing zero-value check on divisor parameters causes transaction reverts in Solidity 0.8+ or incorrect results in earlier versions.",
    riskWeight: 45,
    sourcePatterns: [
      /\/\s*\w+\s*(?:;|\))[\s\S]{0,100}(?!require\s*\([^)]*>\s*0|!=\s*0)/s,
    ],
  },
  {
    id: "evm-push0-incompatibility",
    name: "PUSH0 Opcode Incompatibility",
    severity: "medium",
    description:
      "Solidity 0.8.20+ defaults to Shanghai EVM which uses PUSH0 opcode, but many L2s do not support it yet.",
    riskWeight: 40,
    sourcePatterns: [
      /pragma\s+solidity\s+(?:\^|>=\s*)?0\.8\.(?:2[0-9]|[3-9]\d)/,
    ],
  },

  // =========================================================================
  // Category 17: Unchecked External Interactions (4)
  // =========================================================================

  {
    id: "ext-unchecked-erc20-return",
    name: "Unchecked ERC20 Transfer Return",
    severity: "medium",
    description:
      "Not using safeTransfer for tokens that don't revert on failure (e.g., USDT) allows silent transfer failures.",
    riskWeight: 45,
    sourcePatterns: [
      /IERC20\s*\([^)]*\)\s*\.transfer\s*\([^)]*\)\s*;[\s\S]{0,30}(?!require|if|assert|SafeERC20)/s,
      /\.transferFrom\s*\([^)]*\)\s*;[\s\S]{0,30}(?!require|if|assert|SafeERC20)/s,
    ],
  },
  {
    id: "ext-call-in-modifier",
    name: "External Call in Modifier",
    severity: "medium",
    description:
      "Modifier contains an external call, creating a hidden reentrancy vector that is easy to overlook during review.",
    riskWeight: 50,
    sourcePatterns: [
      /modifier\s+\w+[^{]*\{[\s\S]{0,200}\.call\{/s,
      /modifier\s+\w+[^{]*\{[\s\S]{0,200}I\w+\(\w+\)\.\w+\(/s,
    ],
  },
  {
    id: "ext-unverified-contract",
    name: "Unverified External Contract Call",
    severity: "high",
    description:
      "Calling functions on arbitrary unverified external contracts risks interacting with malicious code.",
    riskWeight: 65,
    sourcePatterns: [
      /address\s+\w+\s*=[\s\S]{0,50};\s*[\s\S]{0,100}\w+\.call\(/s,
      /I\w+\(\s*\w+\s*\)\.\w+\([\s\S]{0,100}(?!require|trusted|verified)/s,
    ],
  },
  {
    id: "ext-arbitrary-call",
    name: "Arbitrary External Call",
    severity: "critical",
    description:
      "User-supplied address used as .call() target allows executing arbitrary code, potentially draining contract funds.",
    riskWeight: 90,
    sourcePatterns: [
      /function\s+\w+\s*\([^)]*address\s+\w+[^)]*\)[^{]*\{[\s\S]{0,200}\w+\.call\{/s,
      /function\s+\w+\s*\([^)]*address\s+\w+[^)]*,\s*bytes\s+(?:memory\s+|calldata\s+)?\w+[^)]*\)/s,
    ],
  },

  // =========================================================================
  // Category 18: Staking, Vaults & Yield (5)
  // =========================================================================

  {
    id: "staking-repeat-claim",
    name: "Staking Reward Manipulation (Repeat Claim)",
    severity: "high",
    description:
      "Flawed accounting allows users to claim staking rewards multiple times without re-staking.",
    riskWeight: 70,
    sourcePatterns: [
      /function\s+(?:claim|harvest|getReward)\w*[\s\S]{0,300}(?!rewardDebt|lastClaimed|userRewardPaid)/s,
      /pendingReward[\s\S]{0,200}(?!userRewardDebt|rewardDebt)/s,
    ],
  },
  {
    id: "staking-donation-attack",
    name: "Donation Attack on Reward Pool",
    severity: "high",
    description:
      "Directly sending tokens to a staking pool inflates the reward rate, allowing the attacker to extract disproportionate rewards.",
    riskWeight: 70,
    sourcePatterns: [
      /rewardRate\s*=[\s\S]{0,100}balanceOf\(address\(this\)\)/s,
      /function\s+notifyReward[\s\S]{0,300}(?!transferFrom)/s,
    ],
  },
  {
    id: "staking-withdrawal-delay",
    name: "Withdrawal Delay Exploitation",
    severity: "medium",
    description:
      "Unstaking delays create a risk window where staked assets lose value but cannot be withdrawn.",
    riskWeight: 40,
    sourcePatterns: [
      /cooldownPeriod|unbondingPeriod|withdrawDelay|lockDuration/i,
      /require\s*\([^)]*block\.timestamp\s*>=?\s*\w*(?:unlock|cooldown|withdraw)\w*/is,
    ],
  },
  {
    id: "staking-compounding-error",
    name: "Compounding Logic Error",
    severity: "medium",
    description:
      "Incorrect auto-compound implementation either under-compounds (losing yield) or over-compounds (creating bad debt).",
    riskWeight: 45,
    sourcePatterns: [
      /function\s+\w*compound\w*\s*\(/i,
      /autoCompound|reinvest|harvestAndDeposit/i,
    ],
  },
  {
    id: "staking-minimum-liquidity-missing",
    name: "Missing Minimum Liquidity / Dead Shares",
    severity: "high",
    description:
      "Vault or pool lacks dead shares (minimum liquidity burn), making it vulnerable to share inflation attacks.",
    riskWeight: 70,
    sourcePatterns: [
      /function\s+deposit[\s\S]{0,300}totalSupply\s*\(\s*\)\s*==\s*0[\s\S]{0,200}(?!MINIMUM_LIQUIDITY|deadShares|_mint\s*\(\s*address\(0\))/s,
      /if\s*\(\s*totalSupply\s*\(\s*\)\s*==\s*0\s*\)[\s\S]{0,200}(?!MINIMUM_LIQUIDITY)/s,
    ],
  },

  // =========================================================================
  // Category 19: Economic & Game Theory Attacks (5)
  // =========================================================================

  {
    id: "economic-bonding-curve",
    name: "Bonding Curve Manipulation",
    severity: "high",
    description:
      "Rapid buy/sell on bonding curves with low liquidity allows extraction of value from the curve's reserves.",
    riskWeight: 65,
    sourcePatterns: [
      /bondingCurve|BondingCurve|curvePrice/i,
      /function\s+(?:buy|sell)\w*[\s\S]{0,300}(?:curve|reserve|supply)\s*[\*\/]/s,
    ],
  },
  {
    id: "economic-liquidation-cascade",
    name: "Toxic Liquidation Spiral",
    severity: "high",
    description:
      "Self-reinforcing liquidation cascade where each liquidation further depresses collateral prices, triggering more liquidations.",
    riskWeight: 70,
    sourcePatterns: [
      /function\s+liquidate[\s\S]{0,500}for\s*\(/s,
      /batchLiquidate|massLiquidate|liquidateMultiple/i,
    ],
  },
  {
    id: "economic-thin-liquidity",
    name: "Market Manipulation via Thin Liquidity",
    severity: "high",
    description:
      "Protocol assumes sufficient market depth, but thin liquidity allows price manipulation with minimal capital.",
    riskWeight: 60,
    sourcePatterns: [
      /function\s+\w+[\s\S]{0,300}getReserves[\s\S]{0,200}(?!require\s*\([^)]*reserve|minLiquidity)/s,
    ],
  },
  {
    id: "economic-collateral-inflation",
    name: "Pump-and-Dump via Collateral Inflation",
    severity: "critical",
    description:
      "Inflate a token's price, use it as collateral to borrow maximum value, then default when the price crashes.",
    riskWeight: 85,
    sourcePatterns: [
      /function\s+borrow[\s\S]{0,500}(?:getPrice|latestAnswer|getReserves)[\s\S]{0,300}(?!TWAP|twap|timeWeighted)/s,
    ],
  },
  {
    id: "economic-griefing",
    name: "Griefing Attack (Economic)",
    severity: "medium",
    description:
      "Attacker performs an unprofitable action solely to cause financial harm to other users, such as blocking auctions.",
    riskWeight: 40,
    sourcePatterns: [
      /function\s+bid[\s\S]{0,300}require[\s\S]{0,100}msg\.value\s*>/s,
      /highestBidder|currentBidder|leadingBid/i,
    ],
  },

  // =========================================================================
  // Category 20: Data Privacy & Protocol Integration (5)
  // =========================================================================

  {
    id: "privacy-private-variable",
    name: "Private Variable Exposure",
    severity: "medium",
    description:
      "Marking variables as private does not hide them; anyone can read storage slots via eth_getStorageAt.",
    riskWeight: 35,
    sourcePatterns: [
      /(?:bytes32|uint256|address)\s+private\s+\w*(?:password|secret|key|seed|pin)\w*/i,
    ],
  },
  {
    id: "privacy-sensitive-events",
    name: "Sensitive Data in Events",
    severity: "medium",
    description:
      "Confidential or sensitive information emitted in event logs, which are publicly visible on-chain.",
    riskWeight: 35,
    sourcePatterns: [
      /emit\s+\w+\([^)]*(?:password|secret|privateKey|seed|pin)/i,
    ],
  },
  {
    id: "integration-composability",
    name: "Composability Attack (Cross-Protocol)",
    severity: "high",
    description:
      "Exploiting implicit assumptions between integrated protocols when state changes in one affect the other.",
    riskWeight: 65,
    sourcePatterns: [
      /I\w+\(\w+\)\.\w+\([\s\S]{0,100}I\w+\(\w+\)\.\w+\(/s,
    ],
  },
  {
    id: "integration-eip4337-exploit",
    name: "EIP-4337 Account Abstraction Exploit",
    severity: "high",
    description:
      "Malicious paymaster or bundler exploits in EIP-4337 can drain user wallets or manipulate transaction execution.",
    riskWeight: 65,
    sourcePatterns: [
      /IPaymaster|BasePaymaster|validatePaymasterUserOp/,
      /UserOperation|handleOps|validateUserOp/,
    ],
  },
  {
    id: "integration-incompatible-standard",
    name: "Incompatible Token Standard Integration",
    severity: "medium",
    description:
      "Protocol assumes ERC20 behavior but receives tokens with different standards (ERC777, ERC1363), causing unexpected callbacks.",
    riskWeight: 45,
    sourcePatterns: [
      /IERC20\s*\([^)]*\)[\s\S]{0,200}(?!SafeERC20|safeTransfer)\.transfer/s,
    ],
  },

  // =========================================================================
  // Category 21: Recent & Novel Attack Vectors (5)
  // =========================================================================

  {
    id: "novel-transient-storage-reentrancy",
    name: "Transient Storage Reentrancy",
    severity: "high",
    description:
      "Incorrect use of EIP-1153 transient storage for reentrancy guards -- tstore/tload semantics differ from sstore/sload.",
    riskWeight: 70,
    sourcePatterns: [
      /assembly\s*\{[^}]*tstore/i,
      /assembly\s*\{[^}]*tload/i,
    ],
  },
  {
    id: "novel-eip3074-abuse",
    name: "EIP-3074 AUTH/AUTHCALL Abuse",
    severity: "high",
    description:
      "Sponsored transaction mechanisms (AUTH/AUTHCALL) exploited to execute unauthorized operations on behalf of the signer.",
    riskWeight: 70,
    sourcePatterns: [
      /assembly\s*\{[^}]*auth(?:call)?\s*\(/i,
      /\bAUTH\b[\s\S]{0,100}\bAUTHCALL\b/,
    ],
  },
  {
    id: "novel-malicious-metadata",
    name: "Malicious Token Metadata XSS",
    severity: "medium",
    description:
      "JavaScript or HTML injected into ERC20 name/symbol fields to exploit vulnerable frontends via stored XSS.",
    riskWeight: 45,
    sourcePatterns: [
      /name\s*=\s*["'][^"']*<script/i,
      /symbol\s*=\s*["'][^"']*<(?:script|img|svg)/i,
    ],
  },
  {
    id: "novel-address-collision-create2",
    name: "Address Collision via CREATE2",
    severity: "high",
    description:
      "Pre-computed deployment address using CREATE2 exploits protocol whitelists or permission checks based on contract address.",
    riskWeight: 70,
    sourcePatterns: [
      /assembly\s*\{[^}]*create2[\s\S]{0,200}salt/s,
      /keccak256\s*\([^)]*0xff[\s\S]{0,100}create2/s,
    ],
  },
  {
    id: "novel-supply-chain-attack",
    name: "Supply Chain Attack on Dependencies",
    severity: "high",
    description:
      "Compromised npm, foundry, or OpenZeppelin dependency injects a backdoor into the compiled contract.",
    riskWeight: 65,
    sourcePatterns: [
      /import\s+["'][^"']*(?:\/\.\.\/|\\\.\.\\)/,
      /import\s+["'][^"']*@[\w-]+\/[\w-]+\/(?!contracts|interfaces|utils|access|token)/,
    ],
  },

  // =========================================================================
  // Category 22: Rounding & Precision (3)
  // =========================================================================

  {
    id: "rounding-direction-exploit",
    name: "Rounding Direction Exploitation",
    severity: "high",
    description:
      "Incorrect rounding direction in share/token calculations allows users to extract extra value on deposits or withdrawals.",
    riskWeight: 65,
    sourcePatterns: [
      /shares\s*=\s*\w+\s*\*\s*\w+\s*\/\s*\w+(?!\s*\+\s*1|\s*\+\s*\(\s*\w+\s*%)/,
      /mulDiv(?:RoundingUp)?|mulDivUp|ceilDiv/,
    ],
  },
  {
    id: "rounding-non-standard-decimals",
    name: "Non-Standard Token Decimals",
    severity: "medium",
    description:
      "Tokens with decimals other than 18 (e.g., USDC=6, WBTC=8) cause calculation errors when hardcoded to 1e18.",
    riskWeight: 40,
    sourcePatterns: [
      /1e18[\s\S]{0,200}(?:USDC|USDT|WBTC|DAI)/s,
      /\*\s*10\s*\*\*\s*18[\s\S]{0,200}(?!decimals\(\))/s,
    ],
  },
  {
    id: "rounding-assert-violation",
    name: "Assert Violation (Panic)",
    severity: "medium",
    description:
      "assert() failure consumes all remaining gas (unlike require/revert), making it a griefing vector.",
    riskWeight: 40,
    sourcePatterns: [
      /assert\s*\([^)]+\)\s*;/,
    ],
  },

  // =========================================================================
  // Category 23: Permit & Approval Edge Cases (3)
  // =========================================================================

  {
    id: "permit-front-run-dos",
    name: "Permit Front-Running DoS",
    severity: "medium",
    description:
      "Attacker front-runs a user's permit call with the same signature, causing the user's transaction to revert.",
    riskWeight: 40,
    sourcePatterns: [
      /function\s+\w+[\s\S]{0,200}permit\s*\([\s\S]{0,200}transferFrom/s,
      /try\s+\w+\.permit[\s\S]{0,100}catch/s,
    ],
  },
  {
    id: "permit2-over-permission",
    name: "Permit2 Over-Permissioning",
    severity: "high",
    description:
      "Unlimited Permit2 allowances with no expiration create a persistent drain vector if the protocol is compromised.",
    riskWeight: 65,
    sourcePatterns: [
      /IAllowanceTransfer|ISignatureTransfer|Permit2/,
      /permit2\.(?:permit|transferFrom)\s*\(/,
    ],
  },
  {
    id: "erc1271-sig-replay",
    name: "ERC-1271 Signature Replay",
    severity: "high",
    description:
      "Smart contract wallet signatures (ERC-1271) can be replayed if isValidSignature does not track used signatures.",
    riskWeight: 65,
    sourcePatterns: [
      /isValidSignature\s*\(/,
      /IERC1271|ERC1271/,
    ],
  },

  // =========================================================================
  // Category 24: Lending & Borrowing Edge Cases (3)
  // =========================================================================

  {
    id: "lending-collateral-manipulation",
    name: "Collateral Price Manipulation",
    severity: "critical",
    description:
      "Inflating the price of an obscure collateral token to over-borrow against it, then defaulting when the price normalizes.",
    riskWeight: 85,
    sourcePatterns: [
      /function\s+borrow[\s\S]{0,300}collateralValue[\s\S]{0,200}getPrice/s,
      /collateralFactor[\s\S]{0,200}getReserves/s,
    ],
  },
  {
    id: "lending-bad-debt",
    name: "Bad Debt Accumulation",
    severity: "high",
    description:
      "Failed liquidations create protocol bad debt when underwater positions cannot be profitably liquidated.",
    riskWeight: 65,
    sourcePatterns: [
      /badDebt|shortfall|deficit|underwater/i,
      /function\s+liquidate[\s\S]{0,500}(?:revert|return)[\s\S]{0,100}(?:insufficien|unprofitable)/is,
    ],
  },
  {
    id: "lending-borrow-factor-miscalc",
    name: "Borrowing Factor Miscalculation",
    severity: "high",
    description:
      "Incorrect LTV or borrowing factor calculations enable users to borrow more than their collateral should allow.",
    riskWeight: 70,
    sourcePatterns: [
      /(?:ltv|loanToValue|borrowFactor|collateralFactor)\s*(?:=|:)\s*/i,
      /function\s+\w*(?:maxBorrow|borrowLimit|borrowCapacity)\w*/i,
    ],
  },

  // =========================================================================
  // Category 25: Multi-Hop & Complex DeFi (3)
  // =========================================================================

  {
    id: "defi-multihop-slippage",
    name: "Multi-Hop Slippage Accumulation",
    severity: "medium",
    description:
      "Cumulative slippage across multiple swap hops not checked, allowing significantly worse execution than expected.",
    riskWeight: 45,
    sourcePatterns: [
      /path\s*(?:=|:)\s*\[[^\]]*,\s*[^\]]*,\s*[^\]]*\]/,
      /exactInput\s*\([\s\S]{0,200}path/s,
    ],
  },
  {
    id: "defi-lp-token-manipulation",
    name: "LP Token Price Manipulation",
    severity: "high",
    description:
      "Manipulating the valuation of LP tokens used as collateral by skewing the underlying pool reserves.",
    riskWeight: 70,
    sourcePatterns: [
      /function\s+\w*(?:getLPPrice|lpValue|lpTokenPrice)\w*/i,
      /sqrt\s*\([\s\S]{0,100}reserve[\s\S]{0,100}reserve/s,
    ],
  },
  {
    id: "defi-sandwich-no-deadline",
    name: "Missing Swap Deadline Protection",
    severity: "high",
    description:
      "Swap transaction has no deadline parameter or uses block.timestamp as the deadline, leaving it vulnerable to sandwich attacks and indefinite pending in the mempool.",
    riskWeight: 65,
    sourcePatterns: [
      /deadline\s*(?:=|:)\s*block\.timestamp/,
      /swap\w*\([^)]*(?:type\(uint256\)\.max|2\*\*256|block\.timestamp)[^)]*\)/,
      /function\s+swap\w*\([^)]*\)\s*(?:external|public)(?:(?!deadline).)*$/ms,
    ],
  },
];

/**
 * Known malicious bytecode signatures (hex substrings)
 */
export const MALICIOUS_BYTECODE_SIGS = [
  { sig: "selfdestruct", hex: "ff", description: "Contract can self-destruct" },
  { sig: "delegatecall", hex: "f4", description: "Contract uses delegatecall" },
  { sig: "create2", hex: "f5", description: "Contract uses CREATE2" },
  { sig: "callcode", hex: "f2", description: "Contract uses deprecated CALLCODE" },
  { sig: "staticcall", hex: "fa", description: "Contract uses STATICCALL" },
  { sig: "sstore", hex: "55", description: "Contract modifies storage" },
  { sig: "extcodecopy", hex: "3c", description: "Contract copies external code" },
];

/**
 * Suspicious function selectors commonly found in scam contracts
 */
export const SUSPICIOUS_SELECTORS: Record<string, string> = {
  "0x8da5cb5b": "owner()",
  "0x715018a6": "renounceOwnership()",
  "0xa9059cbb": "transfer(address,uint256)",
  "0x23b872dd": "transferFrom(address,address,uint256)",
  "0x095ea7b3": "approve(address,uint256)",
  "0xd505accf": "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
  "0x40c10f19": "mint(address,uint256)",
  "0x42966c68": "burn(uint256)",
  "0x3659cfe6": "upgradeTo(address)",
  "0x4f1ef286": "upgradeToAndCall(address,bytes)",
  "0x8129fc1c": "initialize()",
  "0xf2fde38b": "transferOwnership(address)",
  "0x5c975abb": "paused()",
  "0x8456cb59": "pause()",
  "0x3f4ba83a": "unpause()",
  "0xe9fad8ee": "exit()",
  "0x2e1a7d4d": "withdraw(uint256)",
  "0xd0e30db0": "deposit()",
  "0x853828b6": "withdrawAll()",
  "0x0d392cd9": "setFee(uint256)",
  "0xfa461e33": "uniswapV3SwapCallback(int256,int256,bytes)",
  "0x10d1e85c": "flashLoan(address,address,uint256,bytes)",
};
