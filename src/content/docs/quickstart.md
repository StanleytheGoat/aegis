---
title: Quick Start
description: Get Aegis running in 30 seconds with Claude Code, Claude Desktop, or any MCP agent.
---

## Claude Code

One command:

```bash
claude mcp add aegis npx aegis-defi
```

Your agent now has 6 safety tools. Ask it to scan a contract or assess a transaction.

## Claude Desktop

Add to `claude_desktop_config.json`:

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

Restart Claude Desktop. Aegis tools appear automatically.

## Any MCP Agent

Run the server directly:

```bash
npx aegis-defi
```

Connect via stdio. The server exposes standard MCP tool definitions.

## HTTP API

No MCP? Use the REST API:

```bash
curl -X POST https://aegis-defi.netlify.app/api/scan \
  -H "Content-Type: application/json" \
  -d '{"contractAddress": "0x...", "chainId": 1}'
```

Three endpoints available: `/api/scan`, `/api/check-token`, `/api/simulate`.

## Web Scanner

No install at all - paste an address at [aegis-defi.netlify.app/scan](/scan).
