import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ---------------------------------------------------------------------------
// Mock viem BEFORE importing the module under test.
// We replace createPublicClient so no real RPC calls are made.
// ---------------------------------------------------------------------------

const mockEstimateGas = vi.fn();
const mockCall = vi.fn();
const mockGetGasPrice = vi.fn();
const mockReadContract = vi.fn();

vi.mock("viem", async () => {
  const actual = await vi.importActual("viem");
  return {
    ...actual,
    createPublicClient: vi.fn(() => ({
      estimateGas: mockEstimateGas,
      call: mockCall,
      getGasPrice: mockGetGasPrice,
      readContract: mockReadContract,
    })),
  };
});

// Now import the functions - they'll use our mocked viem
import { simulateTransaction, checkTokenSellability } from "./simulator.js";
import type { SimulationRequest } from "./simulator.js";

// ---------------------------------------------------------------------------
// Tests: simulateTransaction
// ---------------------------------------------------------------------------

describe("simulateTransaction", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const baseReq: SimulationRequest = {
    chainId: 1,
    from: "0x1111111111111111111111111111111111111111",
    to: "0x2222222222222222222222222222222222222222",
    data: "0xabcdef",
    value: 0n,
  };

  it("should return success for a normal transaction", async () => {
    mockEstimateGas.mockResolvedValue(50_000n);
    mockCall.mockResolvedValue({ data: "0x0000" });
    mockGetGasPrice.mockResolvedValue(20_000_000_000n); // 20 gwei

    const result = await simulateTransaction(baseReq);

    expect(result.success).toBe(true);
    expect(result.gasUsed).toBe(50_000n);
    expect(result.gasAnomaly).toBe(false);
    expect(result.riskIndicators).toEqual([]);
    expect(result.returnData).toBe("0x0000");
    expect(parseFloat(result.estimatedCostEth)).toBeGreaterThan(0);
  });

  it("should detect high gas usage anomaly", async () => {
    mockEstimateGas.mockResolvedValue(2_000_000n); // > 1M threshold
    mockCall.mockResolvedValue({ data: "0x" });
    mockGetGasPrice.mockResolvedValue(20_000_000_000n);

    const result = await simulateTransaction(baseReq);

    expect(result.success).toBe(true);
    expect(result.gasAnomaly).toBe(true);
    expect(result.riskIndicators).toContain("high_gas_usage");
  });

  it("should detect extremely high gas usage", async () => {
    mockEstimateGas.mockResolvedValue(6_000_000n); // > 5M threshold
    mockCall.mockResolvedValue({ data: "0x" });
    mockGetGasPrice.mockResolvedValue(20_000_000_000n);

    const result = await simulateTransaction(baseReq);

    expect(result.gasAnomaly).toBe(true);
    expect(result.riskIndicators).toContain("high_gas_usage");
    expect(result.riskIndicators).toContain("extremely_high_gas");
  });

  it("should handle transaction revert", async () => {
    mockEstimateGas.mockRejectedValue(
      new Error('execution reverted with reason string \'Insufficient balance\''),
    );

    const result = await simulateTransaction(baseReq);

    expect(result.success).toBe(false);
    expect(result.gasUsed).toBe(0n);
    expect(result.revertReason).toContain("Insufficient balance");
    expect(result.riskIndicators).toContain("transaction_reverts");
    expect(result.estimatedCostEth).toBe("0");
  });

  it("should handle generic RPC errors", async () => {
    mockEstimateGas.mockRejectedValue(new Error("could not connect to RPC"));

    const result = await simulateTransaction(baseReq);

    expect(result.success).toBe(false);
    expect(result.riskIndicators).toContain("transaction_reverts");
    expect(result.revertReason).toContain("could not connect");
  });

  it("should handle unknown error type", async () => {
    mockEstimateGas.mockRejectedValue("something went wrong");

    const result = await simulateTransaction(baseReq);

    expect(result.success).toBe(false);
    expect(result.revertReason).toBe("Unknown error");
  });

  it("should return error for unsupported chain ID", async () => {
    const result = await simulateTransaction({
      ...baseReq,
      chainId: 999,
    });

    expect(result.success).toBe(false);
    expect(result.revertReason).toContain("Unsupported chain ID");
    expect(result.riskIndicators).toContain("unsupported_chain");
    // Should NOT call any RPC methods
    expect(mockEstimateGas).not.toHaveBeenCalled();
  });

  it("should pass value to gas estimation", async () => {
    mockEstimateGas.mockResolvedValue(21_000n);
    mockCall.mockResolvedValue({ data: "0x" });
    mockGetGasPrice.mockResolvedValue(10_000_000_000n);

    await simulateTransaction({
      ...baseReq,
      value: 1_000_000_000_000_000_000n, // 1 ETH
    });

    expect(mockEstimateGas).toHaveBeenCalledWith(
      expect.objectContaining({
        value: 1_000_000_000_000_000_000n,
      }),
    );
  });

  it("should calculate estimated cost correctly", async () => {
    mockEstimateGas.mockResolvedValue(100_000n);
    mockCall.mockResolvedValue({ data: "0x" });
    mockGetGasPrice.mockResolvedValue(10_000_000_000n); // 10 gwei

    const result = await simulateTransaction(baseReq);

    // 100_000 * 10 gwei = 1_000_000 gwei = 0.001 ETH
    expect(parseFloat(result.estimatedCostEth)).toBeCloseTo(0.001, 5);
  });

  it("should extract revert reason from reason= format", async () => {
    mockEstimateGas.mockRejectedValue(
      new Error('Transaction failed (reason="Not enough tokens")'),
    );

    const result = await simulateTransaction(baseReq);
    expect(result.revertReason).toBe("Not enough tokens");
  });

  it("should support all valid chain IDs", async () => {
    for (const chainId of [1, 8453, 84532]) {
      mockEstimateGas.mockResolvedValue(21_000n);
      mockCall.mockResolvedValue({ data: "0x" });
      mockGetGasPrice.mockResolvedValue(10_000_000_000n);

      const result = await simulateTransaction({ ...baseReq, chainId });
      expect(result.success).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// Tests: checkTokenSellability
// ---------------------------------------------------------------------------

describe("checkTokenSellability", () => {
  const tokenAddr = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" as `0x${string}`;
  const holderAddr = "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" as `0x${string}`;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should return canSell=true for a normal token", async () => {
    // owner() call
    mockReadContract.mockResolvedValueOnce(holderAddr);
    // totalSupply + balanceOf
    mockReadContract.mockResolvedValueOnce(1_000_000n);
    mockReadContract.mockResolvedValueOnce(10_000n);

    const result = await checkTokenSellability(1, tokenAddr, holderAddr);

    expect(result.canSell).toBe(true);
    expect(result.indicators).not.toContain("zero_balance");
  });

  it("should detect zero balance", async () => {
    mockReadContract.mockResolvedValueOnce(holderAddr); // owner
    mockReadContract.mockResolvedValueOnce(1_000_000n); // totalSupply
    mockReadContract.mockResolvedValueOnce(0n); // balanceOf = 0

    const result = await checkTokenSellability(1, tokenAddr, holderAddr);

    expect(result.canSell).toBe(false);
    expect(result.indicators).toContain("zero_balance");
  });

  it("should detect concentrated holdings", async () => {
    mockReadContract.mockResolvedValueOnce(holderAddr); // owner
    mockReadContract.mockResolvedValueOnce(1_000n); // totalSupply
    mockReadContract.mockResolvedValueOnce(950n); // 95% of supply

    const result = await checkTokenSellability(1, tokenAddr, holderAddr);

    expect(result.indicators).toContain("concentrated_holdings");
  });

  it("should detect renounced ownership", async () => {
    mockReadContract.mockResolvedValueOnce("0x0000000000000000000000000000000000000000"); // owner = zero
    mockReadContract.mockResolvedValueOnce(1_000_000n); // totalSupply
    mockReadContract.mockResolvedValueOnce(10_000n); // balance

    const result = await checkTokenSellability(1, tokenAddr, holderAddr);

    expect(result.indicators).toContain("ownership_renounced_or_faked");
    expect(result.canSell).toBe(true); // renounced alone doesn't block selling
  });

  it("should handle missing owner() function gracefully", async () => {
    // owner() reverts (no such function)
    mockReadContract.mockRejectedValueOnce(new Error("function not found"));
    // totalSupply + balanceOf succeed
    mockReadContract.mockResolvedValueOnce(1_000_000n);
    mockReadContract.mockResolvedValueOnce(10_000n);

    const result = await checkTokenSellability(1, tokenAddr, holderAddr);

    expect(result.canSell).toBe(true);
    // Should not crash, should not include ownership indicator
    expect(result.indicators).not.toContain("ownership_renounced_or_faked");
  });

  it("should handle balance read failure", async () => {
    mockReadContract.mockResolvedValueOnce(holderAddr); // owner
    // totalSupply + balanceOf both fail
    mockReadContract.mockRejectedValueOnce(new Error("call failed"));

    const result = await checkTokenSellability(1, tokenAddr, holderAddr);

    expect(result.indicators).toContain("failed_to_read_balances");
  });

  it("should return unsupported_chain for unknown chain", async () => {
    const result = await checkTokenSellability(999, tokenAddr, holderAddr);

    expect(result.canSell).toBe(false);
    expect(result.indicators).toContain("unsupported_chain");
    expect(mockReadContract).not.toHaveBeenCalled();
  });

  it("should handle complete contract interaction failure", async () => {
    // When all readContract calls fail, the inner try-catch blocks handle them:
    // - owner() failure is silently caught
    // - balance/supply failure adds "failed_to_read_balances"
    // Since zero_balance is never explicitly added, canSell remains true
    mockReadContract.mockRejectedValue(new Error("network down"));

    const result = await checkTokenSellability(1, tokenAddr, holderAddr);

    expect(result.indicators).toContain("failed_to_read_balances");
    // canSell is true because zero_balance was never pushed (balance read failed entirely)
    expect(result.canSell).toBe(true);
  });

  it("should support Base chain", async () => {
    mockReadContract.mockResolvedValueOnce(holderAddr); // owner
    mockReadContract.mockResolvedValueOnce(1_000_000n); // totalSupply
    mockReadContract.mockResolvedValueOnce(10_000n); // balance

    const result = await checkTokenSellability(8453, tokenAddr, holderAddr);
    expect(result.canSell).toBe(true);
  });

  it("should support Base Sepolia chain", async () => {
    mockReadContract.mockResolvedValueOnce(holderAddr); // owner
    mockReadContract.mockResolvedValueOnce(1_000_000n);
    mockReadContract.mockResolvedValueOnce(10_000n);

    const result = await checkTokenSellability(84532, tokenAddr, holderAddr);
    expect(result.canSell).toBe(true);
  });
});
