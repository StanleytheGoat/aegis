# Aegis Exploit Detection Patterns

165 patterns across 8 categories, sourced from `src/risk-engine/patterns.ts`.

## Pattern Reference

| # | Pattern ID | Pattern Name | Category | What It Detects | Severity |
|---|-----------|-------------|----------|----------------|----------|
| 1 | honeypot-sell-tax | Asymmetric Buy/Sell Tax | Honeypot | Contract applies significantly higher tax on sells than buys, trapping user funds | Critical |
| 2 | honeypot-sell-pause | Sell Pause Mechanism | Honeypot | Owner can pause selling, preventing users from exiting positions | Critical |
| 3 | honeypot-max-sell | Hidden Max Sell Amount | Honeypot | Contract enforces a max sell amount that prevents large exits | High |
| 4 | honeypot-fake-renounce | Fake Ownership Renounce | Honeypot | owner() returns address(0) but a hidden owner variable retains control | Critical |
| 5 | reentrancy-external-call-before-state | Reentrancy Vulnerability | Reentrancy | External call made before state update, enabling reentrancy attacks | Critical |
| 6 | centralized-mint | Unrestricted Minting | Access Control | Owner or arbitrary address can mint unlimited tokens | High |
| 7 | hidden-admin-functions | Hidden Admin Functions | Access Control | Contract has admin functions that are not immediately visible (no Ownable, custom auth) | High |
| 8 | unlimited-approval | Unlimited Approval Requirement | Token Safety | Contract requires or encourages unlimited token approvals | Medium |
| 9 | blacklist-mechanism | Blacklist Mechanism | Token Safety | Contract can blacklist addresses from transacting | Medium |
| 10 | proxy-pattern | Upgradeable Proxy | Token Safety | Contract uses proxy pattern - logic can be changed post-deployment | Medium |
| 11 | flash-loan-vulnerability | Flash Loan Vulnerability | Flash Loan | Price oracle or balance check is manipulable within a single transaction | High |
| 12 | permit-phishing | Permit/Approval Phishing | Approval/Permit | Contract collects approvals or permits that could drain user funds | High |
| 13 | metamorphic-contract | Metamorphic Contract (CREATE2 + SELFDESTRUCT) | Advanced Exploit | Contract uses CREATE2 with SELFDESTRUCT, allowing code to be destroyed and redeployed at the same address with different logic | Critical |
| 14 | hidden-balance-modifier | Hidden Balance Modifier | Advanced Exploit | Contract contains functions that can directly set or modify token balances, enabling silent minting or theft | Critical |
| 15 | hidden-fee-modifier | Hidden Fee Modifier (Dynamic Tax Change) | Advanced Exploit | Owner can change buy/sell fees after launch, potentially raising them to trap holders | High |
| 16 | hidden-transfer-drain | Hidden Transfer / Balance Drain | Advanced Exploit | Owner-only function that can invoke internal transfers or directly modify balances to drain user funds | Critical |
| 17 | oracle-manipulation | Oracle Manipulation / Flash Loan Price Attack | Advanced Exploit | Contract reads spot reserves from a DEX pair for pricing, making it vulnerable to flash-loan-based price manipulation | Critical |
| 18 | transfer-callback-trap | Transfer Callback Trap (Delayed Honeypot) | Advanced Exploit | Transfer function checks block timestamp or number, enabling the deployer to activate a honeypot after initial trading appears safe | Critical |
| 19 | mev-sandwich-risk | MEV Sandwich Risk | Advanced Exploit | Low liquidity pool vulnerable to sandwich attacks targeting automated traders | High |
| 20 | malicious-permit | Malicious Permit Implementation | Advanced Exploit | Non-standard permit implementation that approves a different address than the declared spender, enabling silent fund theft via gasless signatures | High |
| 21 | unaudited-lp-locker | Unaudited LP Locker | Advanced Exploit | Liquidity-lock contract includes owner-only emergency withdraw or unlock functions, allowing the deployer to pull liquidity at any time | High |
| 22 | burn-price-manipulation | Burn Mechanism Price Manipulation | Advanced Exploit | Owner can burn tokens directly from the liquidity pair, artificially inflating the token price for a profitable exit | High |

## Severity Distribution

- **Critical**: 9 patterns (honeypot-sell-tax, honeypot-sell-pause, honeypot-fake-renounce, reentrancy, metamorphic-contract, hidden-balance-modifier, hidden-transfer-drain, oracle-manipulation, transfer-callback-trap)
- **High**: 10 patterns (honeypot-max-sell, centralized-mint, hidden-admin-functions, flash-loan-vulnerability, permit-phishing, hidden-fee-modifier, mev-sandwich-risk, malicious-permit, unaudited-lp-locker, burn-price-manipulation)
- **Medium**: 3 patterns (unlimited-approval, blacklist-mechanism, proxy-pattern)

## Categories

1. **Honeypot** (4 patterns) - Contracts that let users buy but prevent selling
2. **Reentrancy** (1 pattern) - Classic state-before-external-call vulnerability
3. **Access Control** (2 patterns) - Overpowered admin/owner functions
4. **Token Safety** (3 patterns) - Approval, blacklist, and upgradeability risks
5. **Flash Loan** (1 pattern) - Single-transaction price manipulation
6. **Approval/Permit** (1 pattern) - Phishing via gasless signature collection
7. **Advanced Exploit** (10 patterns) - Metamorphic contracts, hidden drains, oracle attacks, MEV, and more
