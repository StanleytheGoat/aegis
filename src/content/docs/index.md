---
title: Introduction
description: What Aegis is and how it protects autonomous DeFi agents.
---

Aegis is a safety layer for autonomous DeFi agents. It scans contracts for exploit patterns, simulates transactions on forked chains, and enforces on-chain protection before your agent executes trades.

## What it does

- **165 exploit patterns** - Scans contract source and bytecode for known scam mechanics
- **Fork simulation** - Runs transactions on a forked chain to detect reverts, slippage, and gas anomalies
- **Honeypot detection** - Checks if tokens can actually be sold after buying
- **On-chain enforcement** - Smart contracts on Base that require safety attestations before execution

## How agents use it

Aegis runs as an MCP server. Any MCP-compatible agent (Claude, GPT, custom agents) connects and gets 6 safety tools:

| Tool | Purpose |
|------|---------|
| `scan_contract` | Static analysis for 165 exploit patterns |
| `simulate_transaction` | Forked-chain transaction simulation |
| `check_token` | Anti-honeypot token checks |
| `assess_risk` | All-in-one risk assessment with attestation |
| `trace_transaction` | Multi-contract call tree analysis |
| `search_solodit` | Cross-reference 50K+ real audit findings |

## Next steps

- [Quick Start](/docs/quickstart) - Get running in 30 seconds
- [Agent Integration](/docs/agent-integration) - Connect your AI agent
- [Project Integration](/docs/project-integration) - Add Aegis to your product
- [API Reference](/docs/api) - HTTP API endpoints
