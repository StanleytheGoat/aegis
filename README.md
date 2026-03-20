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
5. On-chain: the AegisGateway contract enforces attestations before forwarding the transaction

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

## Tools

**MCP Server** (TypeScript) - 6 tools available to any MCP-compatible agent:

| Tool | Purpose |
|------|---------|
| `scan_contract` | Pattern matching against 165 known exploit types |
| `simulate_transaction` | Dry-run on a forked chain |
| `check_token` | Anti-honeypot checks (sellability, concentrated holdings) |
| `assess_risk` | All-in-one risk assessment with signed attestation |
| `trace_transaction` | Traces every internal call, scans each contract |
| `search_solodit` | Cross-references against 50K+ real audit findings |

**Smart Contracts** (Solidity) - deployed on Base mainnet:

| Contract | Address | Purpose |
|----------|---------|---------|
| AegisGateway | [`0x62c6...0fa3`](https://basescan.org/address/0x62c64c063ddbcd438f924184c03d8dad45230fa3#code) | Safety wrapper for any DeFi interaction. Verifies attestations, checks risk scores. |
| AegisSafetyHook | [`0xaEE5...40C0`](https://basescan.org/address/0xaEE532d9707b056f4d0939b91D4031298F7340C0#code) | Uniswap v4 `beforeSwap` hook. Blocks swaps without valid safety attestation. |

## Docs

- [Agent Integration Guide](./docs/agent-integration.md) - how to connect your agent
- [Project Integration Guide](./docs/project-integration.md) - how to integrate Aegis into a product
- [Flaunch Integration](./integrations/flaunch/) - safety checks for Flaunch memecoin trading
- [llms.txt](./site/llms.txt) - machine-readable description for agentic search

## Security

Built following Ethereum security best practices (informed by [ethskills](https://github.com/austintgriffith/ethskills)):

- **Signatures**: Chain ID + contract address in all signed messages (no cross-chain replay). EIP-2 s-value malleability check. ecrecover validated against address(0).
- **Fee math**: Multiply before divide. Explicit overflow guards. Basis points (not percentages).
- **Access control**: OZ Ownable + ReentrancyGuard on Gateway. Immutable owner on Hook. Immutable fee recipient.
- **Deployment**: Safe Singleton Factory CREATE2 deployer. Source verified on Basescan. Ownership transferred to Safe multisig.
- **Testing**: 165 tests (42 contract + 123 TypeScript). Fork tests against real Base mainnet state.

## Tests

```bash
npm test              # TypeScript unit tests (123)
npm run test:contracts # Solidity contract tests (42)
npm run demo          # Honeypot detection demo
```

## Changelog

### v0.5.0 (Current)
- **Hook attestation support** - `assess_risk` now returns both gateway and hook attestations for Uniswap v4 protected pools
- **EVM address validation** - all MCP tool inputs validate proper address format
- **Expanded well-known contracts** - Paraswap, Balancer Vault, CoW Protocol, Permit2, Uniswap V4 PoolManager
- **SDK exports** - attester and solodit modules now available for programmatic use
- **Hardened fetching** - response.ok checks, 10s timeouts on all external requests
- **Security headers** and SEO files for landing page

### v0.4.0
- **Solodit integration** - `search_solodit` tool queries 50K+ real audit findings from Cyfrin, Sherlock, Code4rena, Trail of Bits, and others
- **Auto-enrichment** - `assess_risk` cross-references detected patterns against real audit findings when `SOLODIT_API_KEY` is set
- **Opt-in API key model** - each agent provisions their own Solodit key, no shared rate limits

### v0.3.0
- **165 exploit patterns** across 25 categories (up from 22)
- **Trace-level analysis** - `trace_transaction` tool follows every internal call and scans each contract

### v0.2.0
- **22 exploit patterns** (up from 12) - metamorphic contracts, oracle manipulation, MEV sandwich
- **Agent Skills** - installable skill files for Claude Code
- **Flaunch SDK integration** - safety scanning for memecoin launches on Uniswap v4 pools

## License

MIT
