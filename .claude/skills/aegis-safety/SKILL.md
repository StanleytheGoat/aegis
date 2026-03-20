---
name: aegis-safety
description: DeFi safety analysis skill for Aegis. Triggers on: contract scan, safety check, risk assessment, exploit detection, vulnerability analysis, honeypot, rug pull, token check, simulate transaction, price impact, MEV, sandwich attack, flash loan, oracle manipulation, reentrancy. Provides 165 exploit pattern knowledge and attestation flow for on-chain safety verification.
---

# Aegis Safety Analysis

## Workflow

1. When asked to analyze a contract or token, use the `scan_contract` MCP tool with the target address
2. Review the risk score and matched patterns from the scan result
3. If risk score > 50, recommend BLOCK. If 25-50, recommend WARN with details. If < 25, recommend ALLOW
4. For transaction simulation, use `simulate_transaction` with the full calldata
5. For token checks, use `check_token` with the token address
6. For comprehensive assessment, use `assess_risk` which combines all checks
7. For trace analysis of multi-contract txs, use `trace_transaction`
8. If `SOLODIT_API_KEY` is set, `assess_risk` auto-enriches findings with real audit data. Use `search_solodit` to manually query 50K+ audit findings from Cyfrin, Sherlock, Code4rena, Trail of Bits, and OpenZeppelin

## Risk Score Interpretation

| Score | Decision | Action |
|-------|----------|--------|
| 0-24 | ALLOW | Safe to proceed |
| 25-49 | WARN | Proceed with caution, flag specific risks |
| 50-74 | BLOCK | Do not proceed, specific exploit patterns detected |
| 75-100 | CRITICAL | Active exploit or honeypot detected |

## Attestation Flow

1. MCP server signs attestation with deployer key
2. Attestation includes: attestationId, agent address, target contract, function selector, riskScore, chainId, contract address
3. On-chain Gateway verifies signature before executing transaction
4. 5 bps fee collected on each attested transaction

## Key Addresses (Base Mainnet)

- AegisGateway: 0x62c64c063ddbcd438f924184c03d8dad45230fa3
- AegisSafetyHook: 0xaEE532d9707b056f4d0939b91D4031298F7340C0
- Fee Recipient (Safe): 0x3cfFEcfdBC7cE87067990b2863dfBBfD1cfD5952

See references/PATTERNS.md for all 165 exploit detection patterns.
See references/CASE-STUDIES.md for real-world incidents Aegis would prevent.
