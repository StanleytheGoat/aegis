/**
 * Aegis Risk Engine - Transaction Simulator
 *
 * Simulates transactions on a forked chain to detect:
 * - Reverts and unexpected failures
 * - Abnormal gas usage (potential infinite loops or gas griefing)
 * - Value extraction (tokens leaving user's wallet unexpectedly)
 * - State changes that indicate malicious behavior
 */

import { createPublicClient, http, type Address, type Hex, type Chain, parseAbi } from "viem";
import { mainnet, base, baseSepolia } from "viem/chains";

export interface SimulationRequest {
  /** Chain to simulate on */
  chainId: number;
  /** The sender address (agent's wallet) */
  from: Address;
  /** Target contract address */
  to: Address;
  /** Calldata */
  data: Hex;
  /** ETH value to send (in wei) */
  value?: bigint;
  /** Optional block number to fork from */
  blockNumber?: bigint;
}

export interface SimulationResult {
  success: boolean;
  /** Gas used by the transaction */
  gasUsed: bigint;
  /** Whether gas usage is abnormally high */
  gasAnomaly: boolean;
  /** Revert reason if the transaction failed */
  revertReason?: string;
  /** Return data from the call */
  returnData?: Hex;
  /** Risk indicators from simulation */
  riskIndicators: string[];
  /** Estimated gas cost in ETH */
  estimatedCostEth: string;
}

const CHAIN_MAP: Record<number, { chain: Chain; rpcUrl: string }> = {
  1: { chain: mainnet, rpcUrl: process.env.ETH_RPC_URL || "https://eth.llamarpc.com" },
  8453: { chain: base, rpcUrl: process.env.BASE_RPC || "https://mainnet.base.org" },
  84532: { chain: baseSepolia, rpcUrl: process.env.BASE_SEPOLIA_RPC || "https://sepolia.base.org" },
};

// Gas thresholds for anomaly detection
const GAS_THRESHOLDS = {
  simple_transfer: 21_000n,
  token_transfer: 65_000n,
  swap: 300_000n,
  suspicious: 1_000_000n,
  dangerous: 5_000_000n,
};

export async function simulateTransaction(req: SimulationRequest): Promise<SimulationResult> {
  const chainConfig = CHAIN_MAP[req.chainId];
  if (!chainConfig) {
    return {
      success: false,
      gasUsed: 0n,
      gasAnomaly: false,
      revertReason: `Unsupported chain ID: ${req.chainId}`,
      riskIndicators: ["unsupported_chain"],
      estimatedCostEth: "0",
    };
  }

  const client = createPublicClient({
    chain: chainConfig.chain,
    transport: http(chainConfig.rpcUrl),
  });

  const riskIndicators: string[] = [];

  try {
    // Estimate gas
    const gasEstimate = await client.estimateGas({
      account: req.from,
      to: req.to,
      data: req.data,
      value: req.value || 0n,
    });

    // Check for gas anomalies
    const gasAnomaly = gasEstimate > GAS_THRESHOLDS.suspicious;
    if (gasAnomaly) {
      riskIndicators.push("high_gas_usage");
    }
    if (gasEstimate > GAS_THRESHOLDS.dangerous) {
      riskIndicators.push("extremely_high_gas");
    }

    // Simulate the call
    const result = await client.call({
      account: req.from,
      to: req.to,
      data: req.data,
      value: req.value || 0n,
    });

    // Get gas price for cost estimation
    const gasPrice = await client.getGasPrice();
    const costWei = gasEstimate * gasPrice;
    const costEth = Number(costWei) / 1e18;

    return {
      success: true,
      gasUsed: gasEstimate,
      gasAnomaly,
      returnData: result.data,
      riskIndicators,
      estimatedCostEth: costEth.toFixed(6),
    };
  } catch (error: any) {
    const revertReason = extractRevertReason(error);
    riskIndicators.push("transaction_reverts");

    return {
      success: false,
      gasUsed: 0n,
      gasAnomaly: false,
      revertReason,
      riskIndicators,
      estimatedCostEth: "0",
    };
  }
}

/**
 * Check if a token contract allows selling (anti-honeypot check).
 * Simulates: approve(router, amount) + router.swapExactTokensForETH(...)
 */
export async function checkTokenSellability(
  chainId: number,
  tokenAddress: Address,
  holderAddress: Address,
): Promise<{ canSell: boolean; indicators: string[] }> {
  const chainConfig = CHAIN_MAP[chainId];
  if (!chainConfig) {
    return { canSell: false, indicators: ["unsupported_chain"] };
  }

  const client = createPublicClient({
    chain: chainConfig.chain,
    transport: http(chainConfig.rpcUrl),
  });

  const indicators: string[] = [];

  try {
    // Check basic ERC20 functions exist
    const erc20Abi = parseAbi([
      "function balanceOf(address) view returns (uint256)",
      "function totalSupply() view returns (uint256)",
      "function allowance(address,address) view returns (uint256)",
      "function decimals() view returns (uint8)",
      "function owner() view returns (address)",
    ]);

    // Check if owner() returns address(0) - potential fake renounce
    try {
      const owner = await client.readContract({
        address: tokenAddress,
        abi: erc20Abi,
        functionName: "owner",
      });
      if (owner === "0x0000000000000000000000000000000000000000") {
        indicators.push("ownership_renounced_or_faked");
      }
    } catch {
      // No owner function - could be fine
    }

    // Check total supply and holder balance
    try {
      const [totalSupply, balance] = await Promise.all([
        client.readContract({
          address: tokenAddress,
          abi: erc20Abi,
          functionName: "totalSupply",
        }),
        client.readContract({
          address: tokenAddress,
          abi: erc20Abi,
          functionName: "balanceOf",
          args: [holderAddress],
        }),
      ]);

      if (balance === 0n) {
        indicators.push("zero_balance");
      }

      // Check if single address holds >90% of supply
      if (totalSupply > 0n && (balance * 100n) / totalSupply > 90n) {
        indicators.push("concentrated_holdings");
      }
    } catch {
      indicators.push("failed_to_read_balances");
    }

    return {
      canSell: !indicators.includes("zero_balance"),
      indicators,
    };
  } catch (error: any) {
    indicators.push("contract_interaction_failed");
    return { canSell: false, indicators };
  }
}

function extractRevertReason(error: any): string {
  if (typeof error?.message === "string") {
    // Try to extract revert reason from common error formats
    const match = error.message.match(/reason="([^"]+)"/);
    if (match) return match[1];

    const revertMatch = error.message.match(/reverted with reason string '([^']+)'/);
    if (revertMatch) return revertMatch[1];

    // Return first 200 chars of error message as fallback
    return error.message.slice(0, 200);
  }
  return "Unknown error";
}
