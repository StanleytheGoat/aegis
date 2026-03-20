import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createAegisServer } from "./server.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Invoke an MCP tool registered on the server and return the parsed JSON body.
 * McpServer stores tools in an internal map keyed by name. Each entry carries
 * the Zod schema used for validation plus the handler callback. We reach into
 * that map, validate the arguments, and call the handler directly - no
 * transport layer needed.
 */
async function callTool(
  server: ReturnType<typeof createAegisServer>,
  name: string,
  args: Record<string, unknown>,
) {
  // McpServer stores tools in a plain object keyed by name.
  // Each value has { description, inputSchema (zod), callback }.
  const tools = (server as any)._registeredTools as Record<
    string,
    { handler: (args: any, extra: any) => Promise<any> }
  >;

  const tool = tools[name];
  if (!tool) throw new Error(`Tool "${name}" not registered`);

  // Provide a minimal "extra" context object (the MCP SDK passes one to every handler).
  const result = await tool.handler(args, {});
  return result;
}

/** Extract the JSON payload from a tool result envelope. */
function parseToolResult(result: any): any {
  const text = result.content?.[0]?.text;
  if (!text) return undefined;
  return JSON.parse(text);
}

// ---------------------------------------------------------------------------
// Mocks - prevent any real network access
// ---------------------------------------------------------------------------

// Mock global fetch (used by fetchContractSource inside server.ts)
const fetchMock = vi.fn();

// Mock the risk-engine modules so we never touch the network
vi.mock("../risk-engine/scanner.js", () => ({
  scanContractSource: vi.fn((source: string) => ({
    riskScore: source.includes("honeypot") ? 90 : 5,
    riskLevel: source.includes("honeypot") ? "critical" : "safe",
    findings: source.includes("honeypot")
      ? [{ patternId: "honeypot-sell-tax", patternName: "Sell Tax", severity: "critical", description: "High sell tax", riskWeight: 90 }]
      : [],
    summary: source.includes("honeypot") ? "Dangerous" : "Safe",
    recommendation: source.includes("honeypot") ? "avoid" : "proceed",
    scannedAt: "2025-01-01T00:00:00.000Z",
  })),
  scanBytecode: vi.fn((_bytecode: string) => ({
    riskScore: 0,
    riskLevel: "safe",
    findings: [],
    summary: "No issues",
    recommendation: "proceed",
    scannedAt: "2025-01-01T00:00:00.000Z",
  })),
}));

vi.mock("../risk-engine/simulator.js", () => ({
  simulateTransaction: vi.fn(async (req: any) => ({
    success: true,
    gasUsed: 50000n,
    gasAnomaly: false,
    returnData: "0x",
    riskIndicators: [],
    estimatedCostEth: "0.001000",
  })),
  simulateWithTrace: vi.fn(async (req: any) => ({
    success: true,
    gasUsed: 50000n,
    gasAnomaly: false,
    returnData: "0x",
    riskIndicators: [],
    estimatedCostEth: "0.001000",
    trace: {
      contractsScanned: 1,
      maxRiskScore: 5,
      maxRiskLevel: "safe",
      hasDelegatecall: false,
      contracts: [{
        address: req.to || "0x1234",
        callType: "CALL",
        riskScore: 5,
        riskLevel: "safe",
        findings: [],
      }],
    },
  })),
  fetchContractSource: vi.fn(async (address: string, chainId: number) => ({
    source: "contract {}",
    bytecode: "0x00",
    name: "MockContract",
  })),
  checkTokenSellability: vi.fn(async (_chainId: number, _token: string, _holder: string) => ({
    canSell: true,
    indicators: [],
  })),
}));

vi.mock("../risk-engine/solodit.js", () => ({
  enrichWithSolodit: vi.fn(async (findings: any[]) => ({
    aegisFindings: findings,
    soloditMatches: [],
    crossReferenceCount: 0,
  })),
  querySolodit: vi.fn(async (keywords: string) => ({
    query: keywords,
    totalResults: 1,
    findings: [
      {
        title: "Mock Solodit Finding",
        severity: "HIGH",
        tags: ["Reentrancy"],
        protocolCategory: "DeFi",
        qualityScore: 85,
        slug: "mock-finding-1",
        url: "https://solodit.cyfrin.io/issues/mock-finding-1",
      },
    ],
    cached: false,
  })),
}));

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("MCP Server", () => {
  let server: ReturnType<typeof createAegisServer>;

  beforeEach(() => {
    server = createAegisServer();

    // Replace global fetch with our mock
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);

    // Default: fetchContractSource gets no data (empty responses)
    fetchMock.mockResolvedValue({
      json: async () => ({ result: [{ SourceCode: "" }] }),
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // -----------------------------------------------------------------------
  // Construction
  // -----------------------------------------------------------------------
  it("should create an MCP server instance", () => {
    expect(server).toBeDefined();
  });

  it("should register all six tools", () => {
    const tools = (server as any)._registeredTools as Record<string, unknown>;
    expect(tools["scan_contract"]).toBeDefined();
    expect(tools["simulate_transaction"]).toBeDefined();
    expect(tools["check_token"]).toBeDefined();
    expect(tools["assess_risk"]).toBeDefined();
    expect(tools["trace_transaction"]).toBeDefined();
    expect(tools["search_solodit"]).toBeDefined();
  });

  // -----------------------------------------------------------------------
  // scan_contract
  // -----------------------------------------------------------------------
  describe("scan_contract", () => {
    it("should return error when no params provided", async () => {
      const result = await callTool(server, "scan_contract", {});
      const data = parseToolResult(result);
      expect(data.error).toContain("Provide at least one of");
    });

    it("should scan provided source code", async () => {
      const result = await callTool(server, "scan_contract", {
        source: "contract CleanToken { }",
      });
      const data = parseToolResult(result);
      expect(data.riskScore).toBeDefined();
      expect(data.riskLevel).toBeDefined();
      expect(data.recommendation).toBe("proceed");
    });

    it("should scan provided bytecode", async () => {
      const result = await callTool(server, "scan_contract", {
        bytecode: "0x6080604052",
      });
      const data = parseToolResult(result);
      expect(data.riskScore).toBeDefined();
      expect(data.recommendation).toBe("proceed");
    });

    it("should fetch source from explorer when contractAddress given", async () => {
      const { fetchContractSource } = await import("../risk-engine/simulator.js");
      (fetchContractSource as any).mockResolvedValueOnce({
        source: "contract Fetched { }",
        bytecode: "0x6080",
        name: "Fetched",
      });

      const result = await callTool(server, "scan_contract", {
        contractAddress: "0x1234567890abcdef1234567890abcdef12345678",
        chainId: 1,
      });
      const data = parseToolResult(result);
      expect(fetchContractSource).toHaveBeenCalled();
      expect(data.riskScore).toBeDefined();
    });

    it("should fall back to bytecode when source unavailable from explorer", async () => {
      // First call: source is empty
      fetchMock.mockResolvedValueOnce({
        json: async () => ({ result: [{ SourceCode: "" }] }),
      });
      // Second call: bytecode fetch
      fetchMock.mockResolvedValueOnce({
        json: async () => ({ result: "0x6080604052" }),
      });

      const result = await callTool(server, "scan_contract", {
        contractAddress: "0x1234567890abcdef1234567890abcdef12345678",
        chainId: 1,
      });
      const data = parseToolResult(result);
      expect(data.riskScore).toBeDefined();
    });

    it("should return error when fetch fails and no source/bytecode", async () => {
      const { fetchContractSource } = await import("../risk-engine/simulator.js");
      (fetchContractSource as any).mockResolvedValueOnce({
        source: null,
        bytecode: null,
        name: null,
      });

      const result = await callTool(server, "scan_contract", {
        contractAddress: "0x1234567890abcdef1234567890abcdef12345678",
        chainId: 1,
      });
      const data = parseToolResult(result);
      expect(data.error).toContain("Could not fetch");
    });

    it("should return error for unsupported chain when only address provided", async () => {
      const { fetchContractSource } = await import("../risk-engine/simulator.js");
      (fetchContractSource as any).mockResolvedValueOnce({
        source: null,
        bytecode: null,
        name: null,
      });

      const result = await callTool(server, "scan_contract", {
        contractAddress: "0x1234567890abcdef1234567890abcdef12345678",
        chainId: 999,
      });
      const data = parseToolResult(result);
      expect(data.error).toContain("Could not fetch");
    });

    it("should detect dangerous source code", async () => {
      const result = await callTool(server, "scan_contract", {
        source: "contract honeypot { uint sellTax = 99; }",
      });
      const data = parseToolResult(result);
      expect(data.riskScore).toBeGreaterThanOrEqual(70);
      expect(data.riskLevel).toBe("critical");
    });

    it("should return valid response structure", async () => {
      const result = await callTool(server, "scan_contract", {
        source: "contract Test { }",
      });
      expect(result.content).toBeDefined();
      expect(result.content.length).toBeGreaterThan(0);
      expect(result.content[0].type).toBe("text");
      // Should be valid JSON
      expect(() => JSON.parse(result.content[0].text)).not.toThrow();
    });
  });

  // -----------------------------------------------------------------------
  // simulate_transaction
  // -----------------------------------------------------------------------
  describe("simulate_transaction", () => {
    it("should simulate a transaction and return result", async () => {
      const result = await callTool(server, "simulate_transaction", {
        chainId: 1,
        from: "0x1111111111111111111111111111111111111111",
        to: "0x2222222222222222222222222222222222222222",
        data: "0xabcdef",
        value: "0",
      });
      const data = parseToolResult(result);
      expect(data.success).toBe(true);
      expect(data.gasUsed).toBeDefined();
      // gasUsed should be serialized as string (BigInt -> string)
      expect(typeof data.gasUsed).toBe("string");
      expect(data.estimatedCostEth).toBeDefined();
    });

    it("should serialize gasUsed as string", async () => {
      const result = await callTool(server, "simulate_transaction", {
        chainId: 1,
        from: "0x1111111111111111111111111111111111111111",
        to: "0x2222222222222222222222222222222222222222",
        data: "0x",
        value: "0",
      });
      const data = parseToolResult(result);
      // BigInt values cannot be serialized to JSON directly
      expect(typeof data.gasUsed).toBe("string");
    });

    it("should return valid response envelope", async () => {
      const result = await callTool(server, "simulate_transaction", {
        chainId: 1,
        from: "0x1111111111111111111111111111111111111111",
        to: "0x2222222222222222222222222222222222222222",
        data: "0x",
        value: "0",
      });
      expect(result.content).toBeDefined();
      expect(result.content[0].type).toBe("text");
    });
  });

  // -----------------------------------------------------------------------
  // check_token
  // -----------------------------------------------------------------------
  describe("check_token", () => {
    it("should check token safety and return assessment", async () => {
      const result = await callTool(server, "check_token", {
        tokenAddress: "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        chainId: 1,
      });
      const data = parseToolResult(result);
      expect(data.tokenAddress).toBe("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
      expect(data.chainId).toBe(1);
      expect(data.sellability).toBeDefined();
      expect(data.overallAssessment).toBeDefined();
    });

    it("should use default holder address if none provided", async () => {
      const result = await callTool(server, "check_token", {
        tokenAddress: "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        chainId: 1,
      });
      const data = parseToolResult(result);
      // Should succeed without a holderAddress
      expect(data.sellability).toBeDefined();
    });

    it("should use provided holder address", async () => {
      const result = await callTool(server, "check_token", {
        tokenAddress: "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        chainId: 1,
        holderAddress: "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
      });
      const data = parseToolResult(result);
      expect(data.sellability).toBeDefined();
    });

    it("should include contract scan when source is available", async () => {
      fetchMock.mockResolvedValue({
        json: async () => ({
          result: [{ SourceCode: "contract Token { }" }],
        }),
      });

      const result = await callTool(server, "check_token", {
        tokenAddress: "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        chainId: 1,
      });
      const data = parseToolResult(result);
      expect(data.contractScan).toBeDefined();
    });

    it("should mark dangerous token when sellability fails", async () => {
      const { checkTokenSellability } = await import("../risk-engine/simulator.js");
      (checkTokenSellability as any).mockResolvedValueOnce({
        canSell: false,
        indicators: ["zero_balance"],
      });

      const result = await callTool(server, "check_token", {
        tokenAddress: "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        chainId: 1,
      });
      const data = parseToolResult(result);
      expect(data.overallAssessment).toBe("POTENTIALLY_DANGEROUS");
    });

    it("should mark dangerous when contract scan is risky", async () => {
      const { fetchContractSource } = await import("../risk-engine/simulator.js");
      (fetchContractSource as any).mockResolvedValueOnce({
        source: "contract honeypot { uint sellTax = 99; }",
        bytecode: "0x6080",
        name: "Honeypot",
      });

      const result = await callTool(server, "check_token", {
        tokenAddress: "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        chainId: 1,
      });
      const data = parseToolResult(result);
      expect(data.overallAssessment).toBe("POTENTIALLY_DANGEROUS");
    });

    it("should return LIKELY_SAFE for safe token", async () => {
      const result = await callTool(server, "check_token", {
        tokenAddress: "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        chainId: 1,
      });
      const data = parseToolResult(result);
      expect(data.overallAssessment).toBe("LIKELY_SAFE");
    });
  });

  // -----------------------------------------------------------------------
  // assess_risk
  // -----------------------------------------------------------------------
  describe("assess_risk", () => {
    it("should return ALLOW for safe interactions", async () => {
      const result = await callTool(server, "assess_risk", {
        action: "swap",
        targetContract: "0x2222222222222222222222222222222222222222",
        chainId: 1,
        from: "0x1111111111111111111111111111111111111111",
      });
      const data = parseToolResult(result);
      expect(data.decision).toBe("ALLOW");
      expect(data.overallRiskScore).toBeLessThan(40);
      expect(data.recommendation).toContain("safe");
    });

    it("should simulate transaction when calldata provided", async () => {
      const result = await callTool(server, "assess_risk", {
        action: "interact",
        targetContract: "0x2222222222222222222222222222222222222222",
        chainId: 1,
        from: "0x1111111111111111111111111111111111111111",
        transactionData: "0xabcdef",
        value: "0",
      });
      const data = parseToolResult(result);
      expect(data.checks.simulation).toBeDefined();
      expect(data.checks.simulation.gasUsed).toBeDefined();
    });

    it("should check token when tokenAddress provided", async () => {
      const result = await callTool(server, "assess_risk", {
        action: "swap",
        targetContract: "0x2222222222222222222222222222222222222222",
        chainId: 1,
        from: "0x1111111111111111111111111111111111111111",
        tokenAddress: "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      });
      const data = parseToolResult(result);
      expect(data.checks.tokenSafety).toBeDefined();
    });

    it("should BLOCK when simulation shows revert", async () => {
      const { simulateWithTrace } = await import("../risk-engine/simulator.js");
      (simulateWithTrace as any).mockResolvedValueOnce({
        success: false,
        gasUsed: 0n,
        gasAnomaly: false,
        revertReason: "Execution reverted",
        riskIndicators: ["transaction_reverts"],
        estimatedCostEth: "0",
        trace: { contractsScanned: 0, maxRiskScore: 0, maxRiskLevel: "safe", hasDelegatecall: false, contracts: [] },
      });

      const result = await callTool(server, "assess_risk", {
        action: "approve",
        targetContract: "0x2222222222222222222222222222222222222222",
        chainId: 1,
        from: "0x1111111111111111111111111111111111111111",
        transactionData: "0xabcdef",
        value: "0",
      });
      const data = parseToolResult(result);
      expect(data.decision).toBe("BLOCK");
      expect(data.riskFactors).toContain("transaction_reverts");
      expect(data.recommendation).toContain("DO NOT");
    });

    it("should WARN on gas anomaly", async () => {
      const { simulateWithTrace } = await import("../risk-engine/simulator.js");
      (simulateWithTrace as any).mockResolvedValueOnce({
        success: true,
        gasUsed: 2000000n,
        gasAnomaly: true,
        riskIndicators: ["high_gas_usage"],
        estimatedCostEth: "0.05",
        trace: { contractsScanned: 0, maxRiskScore: 0, maxRiskLevel: "safe", hasDelegatecall: false, contracts: [] },
      });

      const result = await callTool(server, "assess_risk", {
        action: "interact",
        targetContract: "0x2222222222222222222222222222222222222222",
        chainId: 1,
        from: "0x1111111111111111111111111111111111111111",
        transactionData: "0xabcdef",
        value: "0",
      });
      const data = parseToolResult(result);
      expect(data.decision).toBe("WARN");
      expect(data.riskFactors).toContain("gas_anomaly");
    });

    it("should BLOCK when token cannot be sold", async () => {
      const { checkTokenSellability } = await import("../risk-engine/simulator.js");
      (checkTokenSellability as any).mockResolvedValueOnce({
        canSell: false,
        indicators: ["zero_balance"],
      });

      const result = await callTool(server, "assess_risk", {
        action: "swap",
        targetContract: "0x2222222222222222222222222222222222222222",
        chainId: 1,
        from: "0x1111111111111111111111111111111111111111",
        tokenAddress: "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      });
      const data = parseToolResult(result);
      expect(data.decision).toBe("BLOCK");
      expect(data.riskFactors).toContain("cannot_sell_token");
    });

    it("should BLOCK when contract scan is high risk", async () => {
      const { fetchContractSource } = await import("../risk-engine/simulator.js");
      (fetchContractSource as any).mockResolvedValueOnce({
        source: "contract honeypot { uint sellTax = 99; }",
        bytecode: "0x6080",
        name: "Honeypot",
      });

      const result = await callTool(server, "assess_risk", {
        action: "swap",
        targetContract: "0x2222222222222222222222222222222222222222",
        chainId: 1,
        from: "0x1111111111111111111111111111111111111111",
      });
      const data = parseToolResult(result);
      expect(data.decision).toBe("BLOCK");
      expect(data.riskFactors).toContain("contract_high_risk");
    });

    it("should include all action types", async () => {
      for (const action of ["swap", "approve", "transfer", "interact"] as const) {
        const result = await callTool(server, "assess_risk", {
          action,
          targetContract: "0x2222222222222222222222222222222222222222",
          chainId: 1,
          from: "0x1111111111111111111111111111111111111111",
        });
        const data = parseToolResult(result);
        expect(data.action).toBe(action);
      }
    });

    it("should return valid response structure", async () => {
      const result = await callTool(server, "assess_risk", {
        action: "swap",
        targetContract: "0x2222222222222222222222222222222222222222",
        chainId: 1,
        from: "0x1111111111111111111111111111111111111111",
      });
      const data = parseToolResult(result);
      expect(data).toHaveProperty("decision");
      expect(data).toHaveProperty("overallRiskScore");
      expect(data).toHaveProperty("riskFactors");
      expect(data).toHaveProperty("action");
      expect(data).toHaveProperty("checks");
      expect(data).toHaveProperty("recommendation");
      expect(["ALLOW", "WARN", "BLOCK"]).toContain(data.decision);
    });
  });

  // -----------------------------------------------------------------------
  // search_solodit
  // -----------------------------------------------------------------------
  describe("search_solodit", () => {
    it("should return findings from Solodit", async () => {
      const result = await callTool(server, "search_solodit", {
        keywords: "reentrancy",
        impact: ["HIGH"],
        pageSize: 5,
      });
      const data = parseToolResult(result);
      expect(data.query).toBe("reentrancy");
      expect(data.findings).toBeInstanceOf(Array);
      expect(data.findings.length).toBeGreaterThan(0);
      expect(data.findings[0].title).toBe("Mock Solodit Finding");
    });

    it("should cap pageSize at 20", async () => {
      const { querySolodit } = await import("../risk-engine/solodit.js");
      await callTool(server, "search_solodit", {
        keywords: "oracle",
        pageSize: 50,
      });
      expect(querySolodit).toHaveBeenCalledWith("oracle", expect.objectContaining({
        pageSize: 20,
      }));
    });
  });

  // -----------------------------------------------------------------------
  // Response format
  // -----------------------------------------------------------------------
  describe("response format", () => {
    it("all tools should return content array with text type", async () => {
      const tools = ["scan_contract", "simulate_transaction", "check_token", "assess_risk"];
      const args = [
        { source: "contract T {}" },
        { chainId: 1, from: "0x1111111111111111111111111111111111111111", to: "0x2222222222222222222222222222222222222222", data: "0x", value: "0" },
        { tokenAddress: "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", chainId: 1 },
        { action: "swap", targetContract: "0x2222222222222222222222222222222222222222", chainId: 1, from: "0x1111111111111111111111111111111111111111" },
      ];

      for (let i = 0; i < tools.length; i++) {
        const result = await callTool(server, tools[i], args[i]);
        expect(result.content).toBeInstanceOf(Array);
        expect(result.content.length).toBeGreaterThan(0);
        expect(result.content[0].type).toBe("text");
        expect(typeof result.content[0].text).toBe("string");
        // Should be parseable JSON
        expect(() => JSON.parse(result.content[0].text)).not.toThrow();
      }
    });
  });
});
