# Aegis

**A safety layer for autonomous DeFi agents.**

Aegis is an MCP server + smart contract system that protects AI agents from malicious DeFi interactions. Before any on-chain transaction executes, Aegis simulates it, scans the target contract for exploit patterns, and returns a go/no-go decision — all in under a second.

## The Problem

AI agents are increasingly autonomous in DeFi — swapping tokens, providing liquidity, executing strategies. But they're vulnerable to the same scams that target humans: honeypot tokens, rug pulls, phishing contracts, and exploits. An agent that can't distinguish a legitimate token from a 99%-sell-tax honeypot will lose its funds on the first malicious interaction.

## The Solution

Aegis sits between the agent and the chain as a trust layer:

```
Agent → Aegis (scan + simulate + decide) → Chain
```

- **MCP Server**: Any MCP-compatible agent (Claude, GPT, etc.) connects and gets access to safety tools
- **Risk Engine**: Static analysis of contract source/bytecode against 12+ known exploit patterns
- **Transaction Simulator**: Dry-runs transactions on a forked chain to catch reverts and gas anomalies
- **Uniswap v4 Hook**: On-chain enforcement — swaps are blocked unless a valid safety attestation exists
- **Gateway Contract**: Standalone wrapper for non-Uniswap DeFi interactions

## Quick Start

### As an MCP Server (recommended)

```bash
# Claude Code
claude mcp add aegis npx aegis-defi

# Claude Desktop — add to claude_desktop_config.json
{
  "mcpServers": {
    "aegis": {
      "command": "npx",
      "args": ["aegis-defi"]
    }
  }
}
```

### Demo

```bash
git clone https://github.com/paperclipai/aegis
cd aegis
npm install
npx tsx demo/catch-honeypot.ts
```

Watch Aegis catch a honeypot token in real-time:

```
Step 1: Agent discovers "Totally Safe Token" (SAFE)
Step 2: Agent calls Aegis → scan_contract
Step 3: Aegis Risk Assessment
  Risk Score:   [████████████████████░] 92/100
  Findings:
    [CRITICAL] Fake Ownership Renounce
    [CRITICAL] Asymmetric Buy/Sell Tax (99% sell)
    [CRITICAL] Sell Pause Mechanism
    [HIGH]     Hidden Max Sell Amount
    [HIGH]     Hidden Admin Functions
Step 4: ⛨ BLOCKED — Agent's funds are safe.
```

## Tools

| Tool | Description |
|------|-------------|
| `scan_contract` | Analyze contract source/bytecode for exploit patterns |
| `simulate_transaction` | Dry-run a transaction on a forked chain |
| `check_token` | Anti-honeypot token safety check |
| `assess_risk` | All-in-one comprehensive risk assessment |

## Smart Contracts

### AegisSafetyHook (Uniswap v4)

A `beforeSwap` hook that enforces safety attestations on every trade. Agents must get an Aegis safety attestation before the swap proceeds. Malicious tokens can be flagged to block all swaps instantly.

### AegisGateway

A standalone safety wrapper for any DeFi interaction. Transactions route through the gateway, which verifies attestations, checks risk scores, and collects a small protocol fee (5 bps).

### MockHoneypot

A deliberately malicious token contract for testing. Implements: 99% sell tax, sell pause, fake ownership renounce, hidden max sell amount. Aegis catches all of these.

## Architecture

```
┌─────────────────┐     MCP (stdio)     ┌──────────────────┐
│   AI Agent      │ ◄──────────────────► │  Aegis MCP       │
│   (Claude, GPT) │                      │  Server          │
└─────────────────┘                      └────────┬─────────┘
                                                  │
                                     ┌────────────┼────────────┐
                                     │            │            │
                               ┌─────▼──┐  ┌─────▼──┐  ┌──────▼─────┐
                               │ Risk   │  │ Tx     │  │ Contract   │
                               │ Engine │  │ Sim    │  │ Fetcher    │
                               │        │  │        │  │ (Etherscan)│
                               └────────┘  └────────┘  └────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                         On-Chain Layer                              │
│  ┌──────────────────┐              ┌──────────────────────────┐    │
│  │  AegisGateway    │              │  AegisSafetyHook         │    │
│  │  (any DeFi)      │              │  (Uniswap v4 beforeSwap) │    │
│  └──────────────────┘              └──────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

## Exploit Patterns Detected

| Pattern | Severity | Description |
|---------|----------|-------------|
| Asymmetric Buy/Sell Tax | Critical | Sells taxed 50-99%, buys are free |
| Sell Pause Mechanism | Critical | Owner can disable selling |
| Fake Ownership Renounce | Critical | `owner()` returns 0 but hidden owner exists |
| Reentrancy Vulnerability | Critical | External call before state update |
| Hidden Admin Functions | High | Custom auth bypasses standard Ownable |
| Unrestricted Minting | High | Owner can mint unlimited tokens |
| Hidden Max Sell Amount | High | Prevents large sell transactions |
| Flash Loan Vulnerability | High | Manipulable price oracle |
| Permit/Approval Phishing | High | Collects dangerous approvals |
| Blacklist Mechanism | Medium | Can block addresses from transacting |
| Upgradeable Proxy | Medium | Logic can change post-deployment |
| Unlimited Approval | Medium | Requires max uint256 approval |

## Supported Chains

| Chain | ID | Status |
|-------|------|--------|
| Ethereum Mainnet | 1 | Supported |
| Base | 8453 | Supported |
| Base Sepolia | 84532 | Supported |

## Documentation

- [Agent Integration Guide](./docs/agent-integration.md) — How AI agents connect to and use Aegis
- [Project Integration Guide](./docs/project-integration.md) — How teams integrate Aegis into their products

## Revenue Model

The AegisGateway contract collects a small fee (default 5 bps / 0.05%) on every protected transaction. This creates sustainable, usage-based revenue that scales with adoption — no subscriptions, no tokens, just value-aligned incentives.

## Legal

Aegis is a security analysis and simulation service. It does not custody assets, execute trades, or provide financial advice. The smart contracts are pass-through wrappers with safety enforcement — they do not hold user funds beyond the scope of a single transaction.

## Built For

[The Synthesis](https://synthesis.md) — Ethereum Foundation Hackathon, March 2026

**Tracks:** Agents that trust, Agents that pay

**Bounties:** Uniswap Agentic Finance, MetaMask Delegations

## License

MIT
