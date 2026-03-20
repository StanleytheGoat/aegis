# @aegis-defi/agentkit

Coinbase AgentKit ActionProvider for the Aegis DeFi safety engine. Gives your AgentKit agent the ability to assess smart contract risk, detect honeypot tokens, and search real audit findings - all as native actions.

## Installation

```bash
npm install @aegis-defi/agentkit @coinbase/agentkit
```

## Quick start

```typescript
import { AgentKit } from "@coinbase/agentkit";
import { aegisActionProvider } from "@aegis-defi/agentkit";

const agent = await AgentKit.from({
  // ...your wallet config
  actionProviders: [aegisActionProvider()],
});
```

That's it. Your agent now has four new actions:

| Action | What it does |
|---|---|
| `assess_risk` | Full risk assessment before a DeFi transaction. Combines source scanning, simulation, and token checks into a single ALLOW / WARN / BLOCK decision. |
| `scan_contract` | Pulls verified source from the block explorer and runs pattern-based vulnerability detection. |
| `check_token` | Anti-honeypot check. Verifies that a token can actually be sold after purchase. |
| `search_audit_findings` | Searches Solodit for real audit findings matching your keywords and severity filter. |

## Supported networks

- Ethereum mainnet (chain 1)
- Base (chain 8453)
- Base Sepolia (chain 84532)

## How `assess_risk` works

`assess_risk` is the primary action. It runs up to three checks in sequence:

1. **Source scan** - Fetches the contract's verified source and runs static analysis against known exploit patterns.
2. **Transaction simulation** - If you provide `transactionData`, it simulates the call and surfaces any issues (reverts, unexpected state changes).
3. **Token sellability** - For swap/approve/transfer actions, it checks whether the token exhibits honeypot behavior.

Results are combined into a single risk score (0-100) and a decision:

- **ALLOW** (0-39) - Low risk. Safe to proceed.
- **WARN** (40-69) - Moderate concerns. Review the findings before continuing.
- **BLOCK** (70-100) - High risk. The agent should not proceed.

## Example: Pre-flight check before a swap

```typescript
// The LLM will call this automatically when it plans a swap,
// but you can also invoke it programmatically:

const result = await agent.run(
  "Assess the risk of swapping on contract 0xabc...def on Base"
);
```

The agent will call `assess_risk` with the contract address, chain ID 8453, and action "swap", then use the ALLOW/WARN/BLOCK decision to determine whether to proceed.

## Building from source

```bash
npm install
npm run build
```

## License

MIT
