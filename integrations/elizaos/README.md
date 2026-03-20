# @aegis-defi/plugin-elizaos

ElizaOS plugin that brings Aegis DeFi safety capabilities to your agent. Scan contracts for vulnerabilities, detect honeypot tokens, simulate transactions, and search real-world audit findings - all through natural conversation.

## Installation

```bash
npm install @aegis-defi/plugin-elizaos aegis-defi
```

## Setup

Register the plugin in your ElizaOS agent configuration:

```typescript
import aegisPlugin from "@aegis-defi/plugin-elizaos";

const agent = {
  // ... your agent config
  plugins: [aegisPlugin],
};
```

Or import the plugin object directly:

```typescript
import { aegisPlugin } from "@aegis-defi/plugin-elizaos";
```

## Actions

### AEGIS_ASSESS_RISK

The primary action. Runs a full safety assessment combining source code scanning, transaction simulation, and honeypot detection. Returns an overall ALLOW / WARN / BLOCK decision.

**Triggers:** "Is this contract safe?", "assess risk", "check risk", "is this safe"

**Example:**
> "Is this contract safe? 0xdAC17F958D2ee523a2206206994597C13D831ec7 on ethereum"

### AEGIS_SCAN_CONTRACT

Scans a smart contract for known vulnerability patterns. Works with on-chain addresses (auto-fetches verified source), raw Solidity source, or bytecode.

**Triggers:** "scan contract", "audit contract", "analyze contract"

**Example:**
> "Scan contract 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 on polygon"

### AEGIS_CHECK_TOKEN

Anti-honeypot check. Verifies that a token can actually be sold after purchase, detecting hidden fees, transfer blocks, and other scam mechanisms.

**Triggers:** "is this a honeypot", "can I sell this token", "check token", "token safety"

**Example:**
> "Is 0x1234...abcd a honeypot on BSC?"

### AEGIS_SEARCH_AUDIT_FINDINGS

Searches the Solodit database of real-world audit findings for vulnerabilities matching your keywords. Supports filtering by impact level.

**Triggers:** "search audit findings", "find vulnerabilities", "known exploits"

**Example:**
> "Search for high impact reentrancy findings"

## Provider

### Safety Provider

Automatically injects Aegis context into the agent's awareness, letting it know that safety capabilities are available and listing the current count of tracked exploit patterns. This helps the agent proactively offer safety checks when users discuss DeFi interactions.

## Chain Support

The plugin recognizes chain names and IDs from user messages:

| Name | Chain ID |
|------|----------|
| Ethereum / ETH | 1 |
| Polygon / Matic | 137 |
| Arbitrum / Arb | 42161 |
| Optimism / OP | 10 |
| Base | 8453 |
| BSC / BNB | 56 |
| Avalanche / AVAX | 43114 |
| Fantom / FTM | 250 |
| zkSync | 324 |
| Linea | 59144 |
| Scroll | 534352 |
| Blast | 81457 |

If no chain is specified, Ethereum mainnet (chain 1) is used by default.

## How It Works

This plugin calls the `aegis-defi` risk engine functions directly (programmatic usage). It does not spawn or connect to an MCP server. The agent parses contract addresses and chain identifiers from the user's natural language message and passes them to the appropriate Aegis functions.

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Watch mode
npm run dev

# Type check
npm run lint
```

## License

MIT
