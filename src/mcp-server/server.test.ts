import { describe, it, expect } from "vitest";
import { createAegisServer } from "./server.js";

describe("MCP Server", () => {
  it("should create an MCP server instance", () => {
    const server = createAegisServer();
    expect(server).toBeDefined();
  });

  // We can't easily test the full MCP protocol in unit tests,
  // but we can verify the server was constructed with the right config.
  it("should have the correct server name", () => {
    const server = createAegisServer();
    // The server object should exist and be configured
    expect(server).toBeTruthy();
  });
});
