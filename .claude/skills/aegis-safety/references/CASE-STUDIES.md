---
title: Case Studies
---

# Case Studies

Real-world incidents that Aegis exploit detection patterns would prevent or mitigate.

## Aave $50M Swap Disaster (March 12, 2026)

- **What happened**: A whale swapped $50M USDT for AAVE via CoW Protocol. The order was routed through a SushiSwap pool with only $73K liquidity. The user received 327 AAVE (~$36K) instead of ~$50M worth. MEV bots extracted approximately $34M in value.
- **Root cause**: No pre-swap simulation to detect extreme price impact in a low-liquidity pool.
- **How Aegis catches it**: `simulate_transaction` flags the extreme price impact (99.9% slippage) before execution. The risk engine returns a BLOCK decision, preventing the swap from proceeding. Pattern #19 (MEV Sandwich Risk) also flags the low-liquidity pool as a sandwich attack target.
- **Patterns matched**: mev-sandwich-risk (#19)
- **Decision**: BLOCK (risk score > 75)

## Cork Protocol $11M Exploit (May 2025)

- **What happened**: An attacker exploited missing access controls in `CorkHook.beforeSwap()` on Uniswap v4. The hook did not validate who was calling it, allowing arbitrary swap manipulation that drained $11M from the protocol.
- **Root cause**: The Uniswap v4 hook lacked access control on its `beforeSwap` callback, allowing anyone to trigger it with crafted parameters.
- **How Aegis catches it**: This is exactly the class of vulnerability that `AegisSafetyHook` prevents. The Aegis hook requires a valid attestation (signed by the Aegis MCP server after risk analysis) before any swap can execute. Without a valid attestation, the hook reverts. Pattern #7 (Hidden Admin Functions) would also flag the missing access controls during contract scanning.
- **Patterns matched**: hidden-admin-functions (#7)
- **Decision**: BLOCK

## Moonwell $1.78M Oracle Exploit (February 2026)

- **What happened**: Moonwell on Base had an oracle misconfiguration that priced cbETH incorrectly. An attacker exploited the mispricing to extract $1.78M by borrowing against inflated collateral values.
- **Root cause**: The oracle used inline reserve-based pricing from a DEX pair rather than a robust external price feed (e.g., Chainlink). This made the price manipulable.
- **How Aegis catches it**: Pattern #17 (Oracle Manipulation / Flash Loan Price Attack) detects contracts that read spot reserves from DEX pairs for pricing. The pattern matches `getReserves()` calls used in price calculations, flagging the contract as vulnerable to flash-loan-based price manipulation.
- **Patterns matched**: oracle-manipulation (#17)
- **Decision**: BLOCK (risk score 85)

## How These Case Studies Inform Aegis

Each incident validated specific detection patterns and reinforced the importance of:

1. **Pre-transaction simulation** - The Aave disaster shows why simulating before executing is critical, especially for large trades.
2. **Hook-level access control** - Cork Protocol proves that on-chain hooks without attestation verification are exploitable.
3. **Oracle integrity checks** - Moonwell demonstrates that inline reserve-based pricing is a known attack vector that must be flagged.
