# Aegis Paperclip Operations

Autonomous agent setup for running Aegis as a zero-human company.

## Quick Start

1. Get an Anthropic API key from console.anthropic.com
2. Run: `npx paperclipai onboard --yes`
3. Set ANTHROPIC_API_KEY in the Paperclip env
4. Import the company config below via the web UI at localhost:3100

## Agents

### Gateway Monitor (10-min heartbeat)
Checks AegisGateway on Base mainnet for new transactions, logs activity.

### Fee Harvester (hourly heartbeat)  
Reads accumulatedFees from Gateway. Calls withdrawFees when above threshold.

### PR Watcher (6-hour heartbeat)
Checks GitHub PRs (ethskills #128, awesome-mcp-servers #3511) for merge status.

## Requirements
- Node.js 20+
- pnpm 9.15+
- Anthropic API key
- This machine (or a VPS) staying on 24/7
