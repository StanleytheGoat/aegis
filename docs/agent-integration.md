# Aegis — Agent Integration Guide

How to connect your AI agent to Aegis for DeFi safety checks.

## Quick Start

### For Claude Code / Claude Desktop

Add Aegis as an MCP server:

```bash
# Claude Code
claude mcp add aegis npx aegis-defi

# Claude Desktop — add to claude_desktop_config.json:
{
  "mcpServers": {
    "aegis": {
      "command": "npx",
      "args": ["aegis-defi"]
    }
  }
}
```

### For Any MCP-Compatible Agent

Aegis runs as a standard MCP server over stdio. Start it with:

```bash
npx aegis-defi
```

Your agent framework needs to support MCP client connections. See the [MCP specification](https://modelcontextprotocol.io) for details.

---

## Available Tools

### `scan_contract`

Analyze a smart contract for known exploit patterns, honeypot mechanics, and security vulnerabilities.

**When to use:** Before interacting with any unfamiliar contract.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | string | No* | Solidity source code |
| `bytecode` | string | No* | Contract bytecode (hex) |
| `contractAddress` | string | No* | Contract address (will fetch source from explorer) |
| `chainId` | number | No | Chain ID (default: 1) |

*At least one of `source`, `bytecode`, or `contractAddress` must be provided.

**Example response:**
```json
{
  "riskScore": 92,
  "riskLevel": "critical",
  "findings": [
    {
      "patternId": "honeypot-sell-tax",
      "patternName": "Asymmetric Buy/Sell Tax",
      "severity": "critical",
      "description": "Contract applies significantly higher tax on sells than buys.",
      "riskWeight": 90
    }
  ],
  "recommendation": "avoid"
}
```

### `simulate_transaction`

Simulate a transaction on a forked chain without executing it. Detects reverts, gas anomalies, and red flags.

**When to use:** Before sending any on-chain transaction.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `chainId` | number | No | Chain ID (default: 1) |
| `from` | string | Yes | Sender address |
| `to` | string | Yes | Target contract |
| `data` | string | Yes | Calldata (hex) |
| `value` | string | No | ETH value in wei (default: "0") |

### `check_token`

Anti-honeypot check for tokens. Verifies sellability, checks for concentrated holdings, fake ownership renouncement, and scam indicators.

**When to use:** Before swapping into any unfamiliar token.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tokenAddress` | string | Yes | Token contract address |
| `chainId` | number | No | Chain ID (default: 1) |
| `holderAddress` | string | No | Address to check balance for |

### `assess_risk` (Recommended)

Comprehensive all-in-one risk assessment. Combines contract scanning, transaction simulation, and token checks into a single go/no-go decision.

**When to use:** This is the recommended tool for any DeFi interaction. Call it before every swap, approval, or contract interaction.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `action` | string | Yes | One of: "swap", "approve", "transfer", "interact" |
| `targetContract` | string | Yes | Contract being interacted with |
| `chainId` | number | No | Chain ID (default: 1) |
| `from` | string | Yes | Agent's wallet address |
| `transactionData` | string | No | Calldata (hex) |
| `value` | string | No | ETH value in wei |
| `tokenAddress` | string | No | Token address for swap checks |

**Example response:**
```json
{
  "decision": "BLOCK",
  "overallRiskScore": 92,
  "riskFactors": ["contract_high_risk", "cannot_sell_token"],
  "recommendation": "DO NOT proceed with this transaction. High risk of fund loss.",
  "checks": { ... }
}
```

---

## Supported Chains

| Chain | ID | Status |
|-------|------|--------|
| Ethereum Mainnet | 1 | Supported |
| Base | 8453 | Supported |
| Base Sepolia | 84532 | Supported |

---

## Agent Behavior Recommendations

### Always check before swapping

```
Before any swap:
1. Call assess_risk with action="swap" and the target token
2. If decision is "BLOCK" → do NOT proceed
3. If decision is "WARN" → proceed only if you have additional context that mitigates the risk
4. If decision is "ALLOW" → proceed normally
```

### Handle edge cases

- If Aegis can't fetch contract source, it falls back to bytecode analysis (less accurate but still useful)
- If the RPC endpoint is unreachable, simulation will fail — treat this as a "WARN" condition
- Attestations expire after 5 minutes — re-check if your transaction is delayed

### Environment variables

Set these for better results:

```bash
ETHERSCAN_API_KEY=your_key    # Better rate limits for contract source fetching
ETH_RPC_URL=your_rpc          # Custom RPC for Ethereum mainnet
BASE_RPC=your_rpc             # Custom RPC for Base
```

---

## Architecture

```
┌─────────────────┐     MCP (stdio)     ┌──────────────────┐
│                 │ ◄──────────────────► │                  │
│   AI Agent      │                      │  Aegis MCP       │
│   (Claude, etc) │                      │  Server          │
│                 │                      │                  │
└─────────────────┘                      └───────┬──────────┘
                                                 │
                                    ┌────────────┼────────────┐
                                    │            │            │
                              ┌─────▼──┐  ┌─────▼──┐  ┌──────▼─────┐
                              │ Risk   │  │ Tx     │  │ Contract   │
                              │ Engine │  │ Sim    │  │ Fetcher    │
                              └────────┘  └────────┘  └────────────┘
                                                │
                                         ┌──────▼──────┐
                                         │  Forked     │
                                         │  Chain      │
                                         └─────────────┘
```

On-chain (optional): The `AegisSafetyHook` (Uniswap v4) and `AegisGateway` contracts enforce safety attestations directly in the protocol. See the [Project Integration Guide](./project-integration.md) for details.
