import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  flattenCallTree,
  deduplicateAddresses,
  filterScanTargets,
  isWellKnown,
  WELL_KNOWN_CONTRACTS,
  type RawCallFrame,
  type TraceCall,
} from "./tracer.js";

// ---------------------------------------------------------------------------
// Mock viem before importing traceTransaction (which calls createPublicClient)
// ---------------------------------------------------------------------------

const mockRequest = vi.fn();

vi.mock("viem", async () => {
  const actual = await vi.importActual("viem");
  return {
    ...actual,
    createPublicClient: vi.fn(() => ({
      request: mockRequest,
    })),
  };
});

// Import after mocks are set up
const { traceTransaction } = await import("./tracer.js");

// ---------------------------------------------------------------------------
// flattenCallTree
// ---------------------------------------------------------------------------

describe("flattenCallTree", () => {
  it("should flatten a single-frame trace", () => {
    const frame: RawCallFrame = {
      type: "CALL",
      from: "0xaaaa",
      to: "0xbbbb",
      value: "0x0",
      input: "0xa9059cbb0000",
      gasUsed: "21000",
    };

    const result = flattenCallTree(frame, 0);

    expect(result).toHaveLength(1);
    expect(result[0].address).toBe("0xbbbb");
    expect(result[0].type).toBe("CALL");
    expect(result[0].depth).toBe(0);
    expect(result[0].selector).toBe("0xa9059cbb");
  });

  it("should recursively flatten nested calls", () => {
    const frame: RawCallFrame = {
      type: "CALL",
      from: "0xaaaa",
      to: "0x1111111111111111111111111111111111111111",
      value: "0x0",
      input: "0x12345678",
      calls: [
        {
          type: "STATICCALL",
          from: "0x1111111111111111111111111111111111111111",
          to: "0x2222222222222222222222222222222222222222",
          input: "0xabcdef01",
        },
        {
          type: "CALL",
          from: "0x1111111111111111111111111111111111111111",
          to: "0x3333333333333333333333333333333333333333",
          input: "0x11223344",
          calls: [
            {
              type: "DELEGATECALL",
              from: "0x3333333333333333333333333333333333333333",
              to: "0x4444444444444444444444444444444444444444",
              input: "0x55667788",
            },
          ],
        },
      ],
    };

    const result = flattenCallTree(frame, 0);

    expect(result).toHaveLength(4);
    expect(result[0].depth).toBe(0);
    expect(result[0].address).toBe("0x1111111111111111111111111111111111111111");
    expect(result[1].depth).toBe(1);
    expect(result[1].type).toBe("STATICCALL");
    expect(result[2].depth).toBe(1);
    expect(result[3].depth).toBe(2);
    expect(result[3].type).toBe("DELEGATECALL");
    expect(result[3].address).toBe("0x4444444444444444444444444444444444444444");
  });

  it("should handle frames without a 'to' address (e.g., CREATE)", () => {
    const frame: RawCallFrame = {
      type: "CREATE",
      from: "0xaaaa",
      value: "0x0",
      input: "0x6080604052",
    };

    const result = flattenCallTree(frame, 0);

    // Falls back to 'from' when 'to' is missing
    expect(result).toHaveLength(1);
    expect(result[0].address).toBe("0xaaaa");
    expect(result[0].type).toBe("CREATE");
  });

  it("should handle empty calls array", () => {
    const frame: RawCallFrame = {
      type: "CALL",
      from: "0xaaaa",
      to: "0xbbbb",
      calls: [],
    };

    const result = flattenCallTree(frame, 0);
    expect(result).toHaveLength(1);
  });

  it("should extract selector from input when >= 10 chars", () => {
    const frame: RawCallFrame = {
      type: "CALL",
      from: "0xaaaa",
      to: "0xbbbb",
      input: "0xa9059cbb000000000000000000000000",
    };

    const result = flattenCallTree(frame, 0);
    expect(result[0].selector).toBe("0xa9059cbb");
  });

  it("should not set selector when input is too short", () => {
    const frame: RawCallFrame = {
      type: "CALL",
      from: "0xaaaa",
      to: "0xbbbb",
      input: "0xa905",
    };

    const result = flattenCallTree(frame, 0);
    expect(result[0].selector).toBeUndefined();
  });

  it("should handle deeply nested traces (12+ levels)", () => {
    // Simulate a deeply nested call chain
    let current: RawCallFrame = {
      type: "CALL",
      from: "0x0000000000000000000000000000000000000001",
      to: "0x000000000000000000000000000000000000000c",
      input: "0xdeadbeef",
    };

    for (let i = 11; i >= 1; i--) {
      current = {
        type: "CALL",
        from: `0x000000000000000000000000000000000000000${(i - 1).toString(16)}`,
        to: `0x000000000000000000000000000000000000000${i.toString(16)}`,
        input: "0xdeadbeef",
        calls: [current],
      };
    }

    const result = flattenCallTree(current, 0);

    expect(result).toHaveLength(12);
    expect(result[0].depth).toBe(0);
    expect(result[11].depth).toBe(11);
  });
});

// ---------------------------------------------------------------------------
// deduplicateAddresses
// ---------------------------------------------------------------------------

describe("deduplicateAddresses", () => {
  it("should remove duplicate addresses", () => {
    const calls: TraceCall[] = [
      { address: "0xaaaa" as any, type: "CALL", depth: 0, value: "0x0" },
      { address: "0xbbbb" as any, type: "CALL", depth: 1, value: "0x0" },
      { address: "0xaaaa" as any, type: "STATICCALL", depth: 1, value: "0x0" },
      { address: "0xcccc" as any, type: "CALL", depth: 2, value: "0x0" },
      { address: "0xbbbb" as any, type: "CALL", depth: 2, value: "0x0" },
    ];

    const result = deduplicateAddresses(calls);

    expect(result).toHaveLength(3);
    expect(result).toEqual(["0xaaaa", "0xbbbb", "0xcccc"]);
  });

  it("should normalize case for deduplication", () => {
    const calls: TraceCall[] = [
      { address: "0xAAAA" as any, type: "CALL", depth: 0, value: "0x0" },
      { address: "0xaaaa" as any, type: "CALL", depth: 1, value: "0x0" },
    ];

    const result = deduplicateAddresses(calls);
    expect(result).toHaveLength(1);
  });

  it("should preserve first-seen order", () => {
    const calls: TraceCall[] = [
      { address: "0xcccc" as any, type: "CALL", depth: 0, value: "0x0" },
      { address: "0xaaaa" as any, type: "CALL", depth: 1, value: "0x0" },
      { address: "0xbbbb" as any, type: "CALL", depth: 2, value: "0x0" },
    ];

    const result = deduplicateAddresses(calls);
    expect(result).toEqual(["0xcccc", "0xaaaa", "0xbbbb"]);
  });

  it("should handle empty input", () => {
    expect(deduplicateAddresses([])).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// isWellKnown & filterScanTargets
// ---------------------------------------------------------------------------

describe("isWellKnown", () => {
  it("should recognize WETH on mainnet", () => {
    expect(isWellKnown("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2" as any)).toBe(true);
  });

  it("should recognize Uniswap V2 Router", () => {
    expect(isWellKnown("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D" as any)).toBe(true);
  });

  it("should be case-insensitive", () => {
    expect(isWellKnown("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2" as any)).toBe(true);
    expect(isWellKnown("0xC02AAA39B223FE8D0A0E5C4F27EAD9083C756CC2" as any)).toBe(true);
  });

  it("should return false for unknown contracts", () => {
    expect(isWellKnown("0x1234567890123456789012345678901234567890" as any)).toBe(false);
  });
});

describe("filterScanTargets", () => {
  it("should remove well-known contracts", () => {
    const addresses = [
      "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // WETH
      "0x1234567890123456789012345678901234567890", // unknown
      "0x7a250d5630b4cf539739df2c5dacb4c659f2488d", // Uniswap V2 Router
    ] as any[];

    const result = filterScanTargets(addresses);

    expect(result).toHaveLength(1);
    expect(result[0]).toBe("0x1234567890123456789012345678901234567890");
  });

  it("should remove the zero address", () => {
    const addresses = [
      "0x0000000000000000000000000000000000000000",
      "0x1111111111111111111111111111111111111111",
    ] as any[];

    const result = filterScanTargets(addresses);
    expect(result).toHaveLength(1);
    expect(result[0]).toBe("0x1111111111111111111111111111111111111111");
  });

  it("should return empty for all well-known addresses", () => {
    const addresses = [
      "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
      "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    ] as any[];

    expect(filterScanTargets(addresses)).toHaveLength(0);
  });

  it("should pass through all unknown addresses", () => {
    const addresses = [
      "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ] as any[];

    expect(filterScanTargets(addresses)).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// WELL_KNOWN_CONTRACTS
// ---------------------------------------------------------------------------

describe("WELL_KNOWN_CONTRACTS", () => {
  it("should contain mainnet WETH", () => {
    expect(WELL_KNOWN_CONTRACTS.has("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")).toBe(true);
  });

  it("should contain Base WETH", () => {
    expect(WELL_KNOWN_CONTRACTS.has("0x4200000000000000000000000000000000000006")).toBe(true);
  });

  it("should store all addresses in lowercase", () => {
    for (const addr of WELL_KNOWN_CONTRACTS) {
      expect(addr).toBe(addr.toLowerCase());
    }
  });
});

// ---------------------------------------------------------------------------
// traceTransaction (integration with mocked RPC)
// ---------------------------------------------------------------------------

describe("traceTransaction", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const baseReq = {
    chainId: 1,
    from: "0x1111111111111111111111111111111111111111" as `0x${string}`,
    to: "0x2222222222222222222222222222222222222222" as `0x${string}`,
    data: "0xabcdef01" as `0x${string}`,
  };

  it("should return full trace when debug_traceCall succeeds", async () => {
    const mockTrace: RawCallFrame = {
      type: "CALL",
      from: "0x1111111111111111111111111111111111111111",
      to: "0x2222222222222222222222222222222222222222",
      input: "0xabcdef01",
      calls: [
        {
          type: "STATICCALL",
          from: "0x2222222222222222222222222222222222222222",
          to: "0x3333333333333333333333333333333333333333",
          input: "0x70a08231",
        },
      ],
    };

    mockRequest.mockResolvedValue(mockTrace);

    const result = await traceTransaction(baseReq);

    expect(result.fullTrace).toBe(true);
    expect(result.calls).toHaveLength(2);
    expect(result.uniqueAddresses).toHaveLength(2);
    expect(result.fallbackReason).toBeUndefined();
  });

  it("should fall back gracefully when debug_traceCall is unsupported", async () => {
    mockRequest.mockRejectedValue(new Error("method not found"));

    const result = await traceTransaction(baseReq);

    expect(result.fullTrace).toBe(false);
    expect(result.calls).toHaveLength(1);
    expect(result.calls[0].address).toBe(baseReq.to);
    expect(result.uniqueAddresses).toHaveLength(1);
    expect(result.fallbackReason).toContain("does not support debug_traceCall");
  });

  it("should fall back with generic error message", async () => {
    mockRequest.mockRejectedValue(new Error("timeout exceeded"));

    const result = await traceTransaction(baseReq);

    expect(result.fullTrace).toBe(false);
    expect(result.fallbackReason).toContain("timeout exceeded");
  });

  it("should fall back for non-Error rejections", async () => {
    mockRequest.mockRejectedValue("random string error");

    const result = await traceTransaction(baseReq);

    expect(result.fullTrace).toBe(false);
    expect(result.fallbackReason).toBe("Unknown error during trace");
  });

  it("should return fallback for unsupported chain ID", async () => {
    const result = await traceTransaction({
      ...baseReq,
      chainId: 999,
    });

    expect(result.fullTrace).toBe(false);
    expect(result.fallbackReason).toContain("Unsupported chain ID");
    expect(result.uniqueAddresses).toEqual([baseReq.to]);
    expect(mockRequest).not.toHaveBeenCalled();
  });

  it("should handle trace with value transfer", async () => {
    const mockTrace: RawCallFrame = {
      type: "CALL",
      from: "0x1111111111111111111111111111111111111111",
      to: "0x2222222222222222222222222222222222222222",
      value: "0xde0b6b3a7640000", // 1 ETH
      input: "0x",
    };

    mockRequest.mockResolvedValue(mockTrace);

    const result = await traceTransaction({
      ...baseReq,
      value: 1000000000000000000n,
    });

    expect(result.fullTrace).toBe(true);
    expect(result.calls[0].value).toBe("0xde0b6b3a7640000");
  });

  it("should deduplicate contracts called multiple times", async () => {
    const mockTrace: RawCallFrame = {
      type: "CALL",
      from: "0x1111111111111111111111111111111111111111",
      to: "0x2222222222222222222222222222222222222222",
      input: "0xabcdef01",
      calls: [
        {
          type: "CALL",
          from: "0x2222222222222222222222222222222222222222",
          to: "0x3333333333333333333333333333333333333333",
          input: "0x12345678",
        },
        {
          type: "CALL",
          from: "0x2222222222222222222222222222222222222222",
          to: "0x3333333333333333333333333333333333333333",
          input: "0x12345678",
        },
        {
          type: "STATICCALL",
          from: "0x2222222222222222222222222222222222222222",
          to: "0x2222222222222222222222222222222222222222",
          input: "0x70a08231",
        },
      ],
    };

    mockRequest.mockResolvedValue(mockTrace);

    const result = await traceTransaction(baseReq);

    // 4 total calls but only 2 unique addresses
    expect(result.calls).toHaveLength(4);
    expect(result.uniqueAddresses).toHaveLength(2);
  });

  it("should support all valid chain IDs", async () => {
    const mockTrace: RawCallFrame = {
      type: "CALL",
      from: "0x1111111111111111111111111111111111111111",
      to: "0x2222222222222222222222222222222222222222",
      input: "0xabcdef01",
    };
    mockRequest.mockResolvedValue(mockTrace);

    for (const chainId of [1, 8453, 84532]) {
      const result = await traceTransaction({ ...baseReq, chainId });
      expect(result.fullTrace).toBe(true);
    }
  });
});
