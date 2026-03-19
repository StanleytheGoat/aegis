#!/usr/bin/env node

/**
 * Aegis — A Safety Layer for Autonomous DeFi Agents
 *
 * Starts the Aegis MCP server, which provides DeFi safety tools
 * to any MCP-compatible AI agent.
 *
 * Usage:
 *   npx aegis-defi          # Start the MCP server
 *   npx aegis-defi --stdio  # Start with stdio transport (default)
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createAegisServer } from "./mcp-server/server.js";

async function main() {
  const server = createAegisServer();
  const transport = new StdioServerTransport();

  await server.connect(transport);

  console.error("Aegis MCP server running on stdio");
  console.error("Connect from Claude Code: claude mcp add aegis npx aegis-defi");
  console.error("Or add to claude_desktop_config.json");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
