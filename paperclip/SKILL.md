---
name: aegis-defi-safety
description: >
  Mandatory DeFi safety layer for any Paperclip company transacting on-chain.
  Scans contracts, simulates transactions, checks tokens, and assesses risk
  before value leaves the treasury. Use before ANY on-chain transaction
  involving token swaps, approvals, liquidity provision, or contract
  interactions. Do NOT skip even for known protocols - exploits appear in
  upgradeable proxies and newly deployed pools.
---

# Aegis DeFi Safety Skill

Aegis is an MCP server + on-chain safety contracts that protect AI agents from
honeypots, rug pulls, and exploits. This skill makes Aegis a **mandatory
pre-flight check** before any agent in your Paperclip company moves value
on-chain.

## When This Skill Triggers

You MUST invoke Aegis tools **before** any action that:

- Swaps tokens (DEX trades, aggregator routes)
- Approves a spender on any ERC-20 / ERC-721 / ERC-1155
- Provides or removes liquidity
- Interacts with an unfamiliar or recently deployed contract
- Bridges assets to another chain
- Executes any transaction where `msg.value > 0` or token transfer is involved

**Never skip the safety check.** If Aegis is unreachable, do NOT proceed with
the transaction. Mark the task `blocked` and escalate.

## MCP Server Connection

Aegis runs as an MCP server. Your adapter must have it configured:

```json
{
  "mcpServers": {
    "aegis": {
      "command": "npx",
      "args": ["aegis-defi"]
    }
  }
}
```

Or via Claude Code CLI:

```bash
claude mcp add aegis npx aegis-defi
```

Once connected, four MCP tools become available.

## Available Tools

### 1. `scan_contract`

Deep-scan a contract address for known exploit patterns, proxy risks, and
malicious bytecode.

```
scan_contract({ address: "0x...", chain: "ethereum" })
```

Use before interacting with any contract you have not scanned in the current
heartbeat window.

### 2. `simulate_transaction`

Dry-run a transaction and return the projected outcome - balance changes, gas,
reverts, and hidden side-effects (re-entrancy, unexpected approvals).

```
simulate_transaction({
  from: "0xTreasury",
  to: "0xRouter",
  data: "0xcalldata...",
  value: "1000000000000000000",
  chain: "ethereum"
})
```

Use for every transaction before signing. Compare simulated balance deltas
against your expected outcome.

### 3. `check_token`

Evaluate a token for rug-pull signals - locked liquidity, ownership
renouncement, honeypot flags, holder concentration.

```
check_token({ address: "0xTokenAddress", chain: "ethereum" })
```

Use before buying, accepting, or providing liquidity for any token not on your
company's pre-approved allow-list.

### 4. `assess_risk`

Aggregate risk score combining contract scan, token health, and on-chain
activity patterns. Returns a risk level (`low`, `medium`, `high`, `critical`)
with a human-readable summary. When the decision is `ALLOW` or `WARN`, also
returns a signed attestation that agents can submit directly to the
AegisGateway contract or encode as hookData for Uniswap v4 hook-protected
pools. Falls back to MCP-only mode if no attester key is configured.

```
assess_risk({ address: "0x...", chain: "ethereum" })
```

Use as the final gate. If risk is `high` or `critical`, do NOT proceed. Mark
the task `blocked`, post a comment with the Aegis risk summary, and escalate
to your chain of command.

## Decision Procedure

Follow this sequence for every on-chain action:

1. **`check_token`** on every token involved (skip for ETH/native gas token).
2. **`scan_contract`** on the target contract.
3. **`simulate_transaction`** with the exact calldata you intend to sign.
4. **`assess_risk`** for a composite score.
5. **Evaluate result:**
   - `low` - proceed with the transaction.
   - `medium` - proceed only if within budget tolerance; post an Aegis summary
     comment on the task for audit trail.
   - `high` or `critical` - **halt**. Do NOT execute. Mark task `blocked`.
     Post the full Aegis report as a comment and escalate.

## On-Chain Safety Contracts (Optional)

For additional protection, route transactions through Aegis on-chain contracts:

- **AegisGateway** - Proxy contract that enforces safety checks before
  forwarding calls. Collects a 5 bps fee per transaction (Safe multisig
  recipient, `withdrawFees` protected by `nonReentrant`). Signatures include
  chain ID + contract address to prevent cross-chain replay. Use when you want
  on-chain enforcement in addition to MCP pre-flight checks.
- **AegisSafetyHook** - Uniswap v4 `beforeSwap` hook that blocks swaps
  against flagged tokens. Hook owner is immutable. Emits `RiskThresholdUpdated`,
  `PermissiveModeUpdated`, and `AttestationRecorded` events. Zero additional
  fee (standard Uniswap fees apply).

## Cost

| Path | Cost |
|------|------|
| MCP tools only (scan, simulate, check, assess) | **Free** |
| Transactions routed through AegisGateway | **5 bps** per transaction |
| AegisSafetyHook (Uniswap v4) | **No additional fee** |

## Governance Fit

Aegis complements Paperclip's governance model:

- **Budget enforcement** - Paperclip ensures agents cannot overspend. Aegis
  ensures the spend itself is not directed at a malicious contract. Together
  they cover both quantity and quality of spend.
- **Approval gates** - High-risk Aegis results should trigger Paperclip
  approval workflows. Configure your company so `high`/`critical` risk scores
  require human or senior-agent approval before proceeding.
- **Audit trail** - Every Aegis scan result should be posted as a task comment
  with the `X-Paperclip-Run-Id` header, linking the safety check to the
  heartbeat run for full traceability.
- **Atomic checkout** - The agent checking out a DeFi task owns both the
  Paperclip checkout and the Aegis pre-flight. No other agent can race the
  same transaction.

## Critical Rules

1. **Never skip Aegis.** Every on-chain value transfer must pass through the
   decision procedure above, regardless of protocol familiarity.
2. **Never override a `critical` risk score.** Only a human operator can
   whitelist a critical-risk contract.
3. **Always log results.** Post scan/simulation output as a Paperclip task
   comment so the audit trail is complete.
4. **Treat Aegis downtime as a blocker.** If the MCP server is unreachable,
   mark the task `blocked` and escalate. Do not fall back to unchecked
   transactions.
5. **Recheck on contract changes.** If a contract has been upgraded (proxy
   implementation change) since your last scan, re-run the full decision
   procedure.
