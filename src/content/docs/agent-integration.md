---
title: Agent Integration
description: How to connect your AI agent to Aegis for DeFi safety checks.
---


How to connect your AI agent to Aegis for DeFi safety checks.

> **For AI agents reading this directly:** You can use Aegis by connecting to the MCP server. Run `npx aegis-defi` and connect via stdio. All 6 tools below are available. Call `assess_risk` before any DeFi interaction for maximum protection. No API key required. For Ethereum production context, see [ethskills](https://github.com/austintgriffith/ethskills).

---

## Quick Start

### For Claude Code / Claude Desktop

```bash
# Claude Code - one command
claude mcp add aegis npx aegis-defi

# Claude Desktop - add to claude_desktop_config.json:
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

Aegis runs as a standard MCP server over stdio:

```bash
npx aegis-defi
```

Your agent framework needs to support MCP client connections. See the [MCP specification](https://modelcontextprotocol.io) for details.

### Programmatic Usage (No MCP)

```typescript
import { scanContractSource, simulateTransaction, checkTokenSellability } from "aegis-defi";

// Scan a contract for exploits
const scan = scanContractSource(soliditySource);
if (scan.riskScore > 70) {
  console.log("BLOCKED:", scan.findings);
}

// Simulate a transaction on a forked chain
const sim = await simulateTransaction({
  chainId: 8453,
  from: "0xAgentWallet",
  to: "0xTargetContract",
  data: "0xcalldata",
  value: 0n,
});

// Check if a token is a honeypot
const token = await checkTokenSellability(8453, "0xToken", "0xHolder");
if (!token.canSell) {
  console.log("HONEYPOT DETECTED");
}
```

---

## Available Tools

### `assess_risk` Recommended

Comprehensive all-in-one risk assessment. Combines contract scanning, transaction simulation, and token checks into a single go/no-go decision.

**When to use:** This is the recommended tool for any DeFi interaction. Call it before every swap, approval, or contract interaction.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `action` | string | Yes | One of: `"swap"`, `"approve"`, `"transfer"`, `"interact"` |
| `targetContract` | string | Yes | Contract being interacted with |
| `chainId` | number | No | Chain ID (default: 1) |
| `from` | string | Yes | Agent's wallet address |
| `transactionData` | string | No | Calldata (hex) |
| `value` | string | No | ETH value in wei |
| `tokenAddress` | string | No | Token address for swap checks |

**Response:**
```json
{
  "decision": "BLOCK",
  "overallRiskScore": 92,
  "riskFactors": ["contract_high_risk", "cannot_sell_token"],
  "recommendation": "DO NOT proceed with this transaction. High risk of fund loss.",
  "checks": {
    "contractScan": { "riskScore": 92, "findings": [...] },
    "tokenSafety": { "canSell": false }
  },
  "attestation": null
}
```

**Decision values:**
- `ALLOW` (risk 0-39) - Proceed normally. Returns a signed attestation.
- `WARN` (risk 40-69) - Proceed with caution. Returns a signed attestation.
- `BLOCK` (risk 70-100) - Do NOT proceed. No attestation returned.

When the decision is `ALLOW` or `WARN`, the response includes a signed `attestation` object containing `id`, `signature`, `riskScore`, and `expiresAt`. Agents can submit this attestation directly to the AegisGateway contract via `recordAttestation()`, or encode it as `hookData` for Uniswap v4 hook-protected pools. If no attester key is configured on the server, Aegis operates in MCP-only mode (risk assessment without signed attestations).

---

### `scan_contract`

Analyze a smart contract's source code or bytecode for known exploit patterns.

**When to use:** Before interacting with any unfamiliar contract.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | string | No* | Solidity source code |
| `bytecode` | string | No* | Contract bytecode (hex) |
| `contractAddress` | string | No* | Contract address (will fetch source from explorer) |
| `chainId` | number | No | Chain ID (default: 1) |

*At least one of `source`, `bytecode`, or `contractAddress` must be provided.

**Detects 165 exploit patterns:**
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

---

### `simulate_transaction`

Simulate a transaction on a forked chain WITHOUT actually executing it.

**When to use:** Before sending any on-chain transaction.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `chainId` | number | No | Chain ID (default: 1) |
| `from` | string | Yes | Sender address |
| `to` | string | Yes | Target contract |
| `data` | string | Yes | Calldata (hex) |
| `value` | string | No | ETH value in wei (default: "0") |

**Detects:** Reverts, abnormal gas usage, unexpected state changes.

---

### `check_token`

Anti-honeypot check. Verifies a token can actually be sold.

**When to use:** Before swapping into any unfamiliar token.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tokenAddress` | string | Yes | Token contract address |
| `chainId` | number | No | Chain ID (default: 1) |
| `holderAddress` | string | No | Address to check balance for |

---

## Agent Behavior: Best Practices

### Decision flow

```
Before ANY DeFi interaction:
1. Call assess_risk with all available context
2. If decision = "BLOCK" → STOP. Do not execute.
3. If decision = "WARN"  → Only proceed if you have strong justification
4. If decision = "ALLOW" → Execute normally
```

### Edge cases

- **Can't fetch source:** Falls back to bytecode analysis (less accurate, still useful)
- **RPC unreachable:** Simulation fails - treat as WARN
- **Attestation expired:** Re-check if your transaction is delayed (5 min window)
- **Unknown chain:** Only Ethereum (1), Base (8453), Base Sepolia (84532) supported
- **No attester key:** Aegis falls back to MCP-only mode - risk assessments work but no signed attestations are returned

### On-chain enforcement (optional)

For maximum security, route transactions through the AegisGateway contract:

```
1. Call assess_risk → get signed attestation (returned for ALLOW/WARN decisions)
2. Submit attestation to AegisGateway.recordAttestation()
3. Call AegisGateway.executeProtected() → tx is verified + forwarded
4. 5 bps fee is collected automatically
```

Signatures include chain ID and contract address to prevent cross-chain replay attacks. The attestation signature format is:

```
keccak256(abi.encodePacked(attestationId, agent, target, selector, riskScore, chainId, contractAddress))
```

See [Project Integration Guide](./project-integration.md) for contract details.

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ETHERSCAN_API_KEY` | Better rate limits for source fetching | (none) |
| `ETH_RPC_URL` | Ethereum mainnet RPC | `https://eth.llamarpc.com` |
| `BASE_RPC` | Base mainnet RPC | `https://mainnet.base.org` |
| `BASE_SEPOLIA_RPC` | Base Sepolia RPC | `https://sepolia.base.org` |
| `SOLODIT_API_KEY` | Enables Solodit cross-referencing (see below) | (none) |

---

## Enhanced Scanning with Solodit

Aegis can cross-reference its scan findings against [Solodit](https://solodit.cyfrin.io)'s database of 50,000+ real-world smart contract audit findings from top security firms (Cyfrin, Sherlock, Code4rena, Trail of Bits, OpenZeppelin, and others).

**Without a key:** Aegis works fully -- all 6 tools, 165 exploit patterns, transaction simulation, trace analysis. Solodit enrichment is simply skipped.

**With a key:** When `assess_risk` detects findings, it automatically queries Solodit for matching real-world audit reports and includes them in the response. The `search_solodit` tool also becomes available for manual queries (e.g., "has this type of vulnerability been seen in production audits before?").

### How to get a Solodit API key

1. Go to [solodit.cyfrin.io](https://solodit.cyfrin.io) and create a free account
2. Click your profile dropdown (top right) and select **API Keys**
3. Generate a new key (starts with `sk_`)
4. Set it in your environment:
   ```bash
   export SOLODIT_API_KEY=sk_your_key_here
   ```
   Or add it to your MCP server config:
   ```json
   {
     "mcpServers": {
       "aegis": {
         "command": "npx",
         "args": ["aegis-defi"],
         "env": {
           "SOLODIT_API_KEY": "sk_your_key_here"
         }
       }
     }
   }
   ```

### Rate limits

Each API key gets 20 requests per 60-second window. Aegis caches results for 5 minutes and caps enrichment queries to 5 per scan, so normal usage stays well within limits. Each agent operator uses their own key and their own quota -- there is no shared key.

---

## Supported Chains

| Chain | ID | Status |
|-------|------|--------|
| Ethereum Mainnet | 1 | Supported |
| Base | 8453 | Supported |
| Base Sepolia | 84532 | Supported |

---

## Architecture

```
┌─────────────────┐     MCP (stdio)     ┌──────────────────┐
│                 │ ◄──────────────────► │                  │
│   AI Agent      │                      │  Aegis MCP       │
│  (Claude, GPT,  │                      │  Server          │
│   any agent)    │                      │                  │
└─────────────────┘                      └───────┬──────────┘
                                                 │
                                    ┌────────────┼────────────┐
                                    │            │            │
                              ┌─────▼──┐  ┌─────▼──┐  ┌──────▼─────┐
                              │ Risk   │  │ Tx     │  │ Contract   │
                              │ Engine │  │ Sim    │  │ Fetcher    │
                              │ (165   │  │ (fork  │  │ (Etherscan │
                              │ patterns)│ │  sim)  │  │  Basescan) │
                              └────────┘  └────────┘  └────────────┘
                                                │
                              ┌─────────────────┼─────────────────┐
                              │                 │                 │
                        ┌─────▼──────┐   ┌──────▼──────┐  ┌──────▼──────┐
                        │ AegisGateway│  │ AegisSafety │  │  Uniswap   │
                        │ (fee       │  │ Hook (v4    │  │  v4 Pools  │
                        │  collection)│  │  beforeSwap)│  │            │
                        └────────────┘  └─────────────┘  └────────────┘
```
