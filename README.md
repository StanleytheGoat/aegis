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
- `scan_contract` - pattern matching against 165 known exploit types
- `simulate_transaction` - dry-run on a forked chain
- `check_token` - anti-honeypot checks (sellability, concentrated holdings)
- `assess_risk` - all of the above combined into one call. Returns a signed attestation for ALLOW/WARN decisions (falls back to MCP-only mode if no attester key configured)
- `trace_transaction` - traces every internal call in a multi-contract transaction, scans each contract individually
- `search_solodit` - cross-references findings against 50,000+ real-world audit results from Cyfrin, Sherlock, Code4rena, Trail of Bits, and others via the Solodit API

**Smart Contracts** (Solidity)
- `AegisGateway` - safety wrapper for any DeFi interaction. Verifies attestations, checks risk scores, collects fees. Fees go to a Safe multisig that can never be changed, even by the contract owner. Signatures include chain ID + contract address to prevent cross-chain replay. ecrecover validates against address(0), EIP-2 s-value malleability check enforced, and `withdrawFees` is protected by `nonReentrant`. Includes `rescueStuckEth()` for ETH sent directly to `receive()`.
- `AegisSafetyHook` - Uniswap v4 `beforeSwap` hook. Blocks swaps that don't have a valid safety attestation. Inline attestation verification extracts agent, risk score, and expiry from the signed message - no hardcoded defaults. Hook owner is immutable. Emits `RiskThresholdUpdated`, `PermissiveModeUpdated`, and `AttestationRecorded` events. Signatures include chain ID + hook address to prevent cross-chain replay.
- `MockHoneypot` - a deliberately evil token for testing. Aegis scores it 100/100.

**Paperclip Integration**
- Aegis works as a safety skill in [Paperclip](https://github.com/paperclipai/paperclip) zero-human companies. Any company doing DeFi operations can plug Aegis in as a mandatory pre-transaction check.

**Deployed on Base Mainnet:**
- AegisGateway: [`0x62c64c063ddbcd438f924184c03d8dad45230fa3`](https://basescan.org/address/0x62c64c063ddbcd438f924184c03d8dad45230fa3#code)
- AegisSafetyHook: [`0xaEE532d9707b056f4d0939b91D4031298F7340C0`](https://basescan.org/address/0xaEE532d9707b056f4d0939b91D4031298F7340C0#code)

## What it catches

| # | Pattern | Severity |
|---|---------|----------|
| 1 | Asymmetric sell tax (50-99%) | Critical |
| 2 | Sell pause mechanism | Critical |
| 3 | Fake ownership renounce | Critical |
| 4 | Reentrancy | Critical |
| 5 | Metamorphic contract | Critical |
| 6 | Hidden balance modifier | Critical |
| 7 | Hidden fee modifier | Critical |
| 8 | Hidden transfer drain | Critical |
| 9 | Delegatecall injection | Critical |
| 10 | Hidden admin functions | High |
| 11 | Unrestricted minting | High |
| 12 | Hidden max sell amount | High |
| 13 | Flash loan vulnerability | High |
| 14 | Permit/approval phishing | High |
| 15 | Transfer callback trap | High |
| 16 | MEV sandwich risk | High |
| 17 | Oracle manipulation | High |
| 18 | Malicious permit | High |
| 19 | Cross-function reentrancy | High |
| 20 | Blacklist mechanism | Medium |
| 21 | Upgradeable proxy / storage collision | Medium |
| 22 | Unlimited approval | Medium |

Plus 13 more patterns added in v0.2.0: metamorphic contract, hidden balance modifier, hidden fee modifier, hidden transfer drain, oracle manipulation, transfer callback trap, MEV sandwich risk, malicious permit, unaudited LP locker, burn price manipulation, proxy storage collision, delegatecall injection, and cross-function reentrancy.

See the full list in [.claude/skills/aegis-safety/references/PATTERNS.md](.claude/skills/aegis-safety/references/PATTERNS.md).

## v0.2.0 - What's New

- **165 exploit patterns** (up from 12) - covers metamorphic contracts, oracle manipulation, MEV sandwich, and more
- **Agent Skills** - installable skill files for Claude Code with progressive disclosure and trigger-based activation
- **Slash commands** - `/scan`, `/status`, `/pitch`, `/incident` for common operations
- **Pre-push security hook** - blocks git pushes containing leaked secrets
- **Flaunch SDK integration** - safety scanning for memecoin launches on Uniswap v4 pools
- **Case studies** - Aave $50M swap disaster, Cork Protocol $11M exploit, Moonwell $1.78M oracle attack
- **Architecture diagram** on landing page showing the full safety pipeline

## Case Studies

**Aave $50M Swap Disaster (March 2026)** - A whale swapped $50M USDT for AAVE tokens via CoW Protocol, routed through a pool with only $73K liquidity. MEV bots extracted $34M. Aegis's `simulate_transaction` would flag the extreme price impact and return BLOCK.

**Cork Protocol $11M Exploit (May 2025)** - Missing access controls in CorkHook.beforeSwap() on Uniswap v4. Exactly the vulnerability AegisSafetyHook prevents by requiring valid attestation before any swap.

**Moonwell $1.78M Oracle Attack (Feb 2026)** - Oracle misconfiguration on Base priced cbETH incorrectly. Pattern 17 (Oracle Manipulation) would detect inline reserve-based pricing.

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

## Agent Skills

Aegis includes installable [Agent Skills](https://agentskills.io/specification) in `.claude/skills/`:

| Skill | Triggers On |
|-------|-------------|
| `aegis-safety` | contract scan, risk assessment, exploit detection, honeypot, simulate transaction |
| `aegis-contracts` | deploy, gateway, hook, Solidity, CREATE2, Basescan |
| `aegis-monitoring` | monitor, alert, incident, fee balance, status check |

Skills use 3-tier progressive disclosure: metadata at startup, full instructions when task matches, reference files on-demand.

Slash commands: `/scan <address>`, `/status`, `/pitch <company>`, `/incident <description>`

## Built for

[The Synthesis](https://synthesis.org) - Ethereum Foundation Hackathon, March 2026

Tracks: Open Track, Uniswap API, Autonomous Trading, Agent Services on Base, ERC-8004

## License

MIT
