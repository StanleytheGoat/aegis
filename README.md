# Aegis

**Safety layer for autonomous DeFi agents.** | [Website](https://aegis-defi.netlify.app) | [Docs](./docs/agent-integration.md)

AI agents trading on-chain have no way to tell a legitimate token from a honeypot. Aegis fixes that. It's an MCP server that any agent can plug into, backed by on-chain contracts that enforce the safety checks.

Before an agent swaps, Aegis scans the target contract, simulates the transaction, and returns a simple go/no-go. If the contract has a 99% sell tax or a hidden pause function, the agent never touches it.

## Why this exists

We watched an agent lose its entire wallet to a honeypot token in under 30 seconds. The token looked fine on the surface - verified contract, decent liquidity, active trading. But buried in the code was a 99% sell tax and a hidden owner behind a fake `renounceOwnership()`.

No agent framework had a way to catch this. So we built one.

## How it works

```
Agent -> Aegis (scan + simulate + decide) -> Chain
```

1. Agent connects to Aegis via MCP (one line of config)
2. Before any swap/approve/transfer, agent calls `assess_risk`
3. Aegis scans the contract source, simulates the tx, checks for honeypot patterns
4. Returns ALLOW, WARN, or BLOCK with a risk score (0-100)
5. On-chain: the AegisGateway contract enforces attestations and collects a 5 bps fee

## Quick Start

```bash
# Add to Claude Code
claude mcp add aegis npx aegis-defi

# Or clone and try the demo
git clone https://github.com/StanleytheGoat/aegis
cd aegis && npm install
npx tsx demo/catch-honeypot.ts
```

The demo deploys a deliberately malicious token (99% sell tax, fake ownership renounce, hidden admin) and watches Aegis catch every red flag:

```
Aegis Risk Assessment
  Risk Score: 100/100
  Findings:
    [CRITICAL] Fake Ownership Renounce
    [CRITICAL] Asymmetric Buy/Sell Tax (99% sell)
    [CRITICAL] Sell Pause Mechanism
    [HIGH]     Hidden Max Sell Amount
    [HIGH]     Hidden Admin Functions
  Decision: BLOCK
```

## What's in the box

**MCP Server** (TypeScript)
- `scan_contract` - pattern matching against 22 known exploit types
- `simulate_transaction` - dry-run on a forked chain
- `check_token` - anti-honeypot checks (sellability, concentrated holdings)
- `assess_risk` - all of the above combined into one call. Returns a signed attestation for ALLOW/WARN decisions (falls back to MCP-only mode if no attester key configured)

**Smart Contracts** (Solidity)
- `AegisGateway` - safety wrapper for any DeFi interaction. Verifies attestations, checks risk scores, collects fees. Fees go to a Safe multisig that can never be changed, even by the contract owner. Signatures include chain ID + contract address to prevent cross-chain replay. ecrecover validates against address(0), EIP-2 s-value malleability check enforced, and `withdrawFees` is protected by `nonReentrant`. Includes `rescueStuckEth()` for ETH sent directly to `receive()`.
- `AegisSafetyHook` - Uniswap v4 `beforeSwap` hook. Blocks swaps that don't have a valid safety attestation. Inline attestation verification extracts agent, risk score, and expiry from the signed message - no hardcoded defaults. Hook owner is immutable. Emits `RiskThresholdUpdated`, `PermissiveModeUpdated`, and `AttestationRecorded` events. Signatures include chain ID + hook address to prevent cross-chain replay.
- `MockHoneypot` - a deliberately evil token for testing. Aegis scores it 100/100.

**Paperclip Integration**
- Aegis works as a safety skill in [Paperclip](https://github.com/paperclipai/paperclip) zero-human companies. Any company doing DeFi operations can plug Aegis in as a mandatory pre-transaction check. See [paperclip/](./paperclip/) for the skill definition.

**Deployed on Base Mainnet:**
- AegisGateway: [`0x62c64c063ddbcd438f924184c03d8dad45230fa3`](https://basescan.org/address/0x62c64c063ddbcd438f924184c03d8dad45230fa3#code)
- AegisSafetyHook: [`0xaEE532d9707b056f4d0939b91D4031298F7340C0`](https://basescan.org/address/0xaEE532d9707b056f4d0939b91D4031298F7340C0#code)

## What it catches

| Pattern | Severity |
|---------|----------|
| Asymmetric sell tax (50-99%) | Critical |
| Sell pause mechanism | Critical |
| Fake ownership renounce | Critical |
| Reentrancy | Critical |
| Hidden admin functions | High |
| Unrestricted minting | High |
| Hidden max sell amount | High |
| Flash loan / oracle manipulation | High |
| Permit/approval phishing | High |
| Blacklist mechanism | Medium |
| Upgradeable proxy | Medium |
| Unlimited approval | Medium |

What it does NOT catch: novel zero-days, social engineering, MEV/sandwich attacks, governance attacks.

## Tests

```bash
# TypeScript unit tests
npm test

# Contract tests
npm run test:contracts

# Demo (honeypot detection)
npm run demo
```

106 tests total (30 contract + 64 TypeScript + 12 Base mainnet fork tests):
- 12 risk engine unit tests (pattern matching)
- MCP server tests (tool execution, error handling)
- Simulator unit tests (transaction simulation, token checks)
- 30 contract tests (AegisGateway attestations/fees/admin, MockHoneypot, AegisSafetyHook)
- 12 Base mainnet fork tests (run against real Base mainnet state)
- Full fee flow test (fees verified landing in Safe multisig)

## Revenue model

5 bps (0.05%) on every transaction that goes through the gateway. The fee recipient is a Safe multisig set at deploy time. No one can change where fees go, not even the contract owner. `withdrawFees` is protected by `nonReentrant`. This was a deliberate security decision.

At scale, if 5% of agent transaction volume on Base flows through Aegis, that's roughly $25K/month at current volumes.

## Docs

- [Agent Integration Guide](./docs/agent-integration.md) - how to connect your agent (for both AI agents and human developers)
- [Project Integration Guide](./docs/project-integration.md) - how to integrate Aegis into a product
- [Paperclip Skill](./paperclip/) - how to add Aegis to a Paperclip zero-human company
- [llms.txt](./site/llms.txt) - machine-readable description for agentic search

## Security practices

Built following [ethskills](https://github.com/austintgriffith/ethskills) Ethereum production best practices:

- **Gas**: Base L2 gas is ~0.1-0.5 gwei (not 10-30). Deploy costs under $1.
- **Signatures**: Chain ID + contract address in all signed messages (no cross-chain replay). EIP-2 s-value malleability check. ecrecover validated against address(0).
- **Fee math**: Multiply before divide. Explicit overflow guards. Basis points (not percentages).
- **Access control**: OZ Ownable + ReentrancyGuard on Gateway. Immutable owner on Hook.
- **Deployment**: Safe Singleton Factory CREATE2 deployer. Source verified on Basescan. Ownership transferred to Safe multisig post-deploy.
- **Base-specific**: Uses `block.timestamp` (not `block.number`). Correct chain ID 8453.
- **Testing**: Fork tests against real Base mainnet state. Fuzz-compatible fee math.

## Challenges we ran into

- Uniswap v4 hooks need to be deployed at addresses with specific permission bits set. You can't just deploy normally. We wrote a CREATE2 salt miner that finds addresses with the correct `beforeSwap` + `afterSwap` bits. Hook deployed via CREATE2 at a vanity address.
- The v4 API changed between versions. `SwapParams` moved from `IPoolManager` to its own `PoolOperation.sol` file. Had to dig through the npm package to find the right imports.
- The inline attestation verification in the v4 hook originally returned hardcoded values instead of extracting from the signature. We refactored to pass `(attestationId, agent, riskScore, expiresAt, signature)` in hookData and verify the full signed message on-chain. Signatures now include chain ID + contract/hook address to prevent cross-chain replay.
- Stack-too-deep in the hook's `beforeSwap` required extracting token checks and attestation processing into separate internal functions.
- Fee flow testing on testnet required deploying a helper contract (EthReceiver) because `executeProtected` forwards calls to the target.
- Added comprehensive security hardening: ecrecover address(0) checks, EIP-2 s-value malleability enforcement, zero-address validation on attester, nonReentrant on withdrawFees, immutable hook owner, and rescueStuckEth() for ETH recovery.

## Built for

[The Synthesis](https://synthesis.org) - Ethereum Foundation Hackathon, March 2026

Tracks: Agents that trust, Agents that pay

## License

MIT
