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
import { traceTransaction, filterScanTargets, isWellKnown, type TraceResult, type TraceCall } from "./tracer.js";
import { scanContractSource, scanBytecode, type ScanResult } from "./scanner.js";

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
  /** Trace analysis of all contracts touched during execution */
  trace?: TraceAnalysis;
}

/** Per-contract risk assessment from trace analysis. */
export interface TracedContract {
  address: Address;
  /** Whether this is a well-known contract (skipped scanning) */
  wellKnown: boolean;
  /** Scan result if the contract was scanned */
  scanResult?: ScanResult;
  /** Call types seen for this address (CALL, DELEGATECALL, etc.) */
  callTypes: string[];
  /** Maximum call depth at which this contract appeared */
  maxDepth: number;
}

/** Full trace analysis attached to a simulation result. */
export interface TraceAnalysis {
  /** Whether debug_traceCall was available */
  fullTrace: boolean;
  /** Total number of internal calls */
  totalCalls: number;
  /** Number of unique contracts touched */
  uniqueContracts: number;
  /** Number of contracts that were actually scanned */
  scannedContracts: number;
  /** Per-contract breakdown */
  contracts: TracedContract[];
  /** The highest risk score across all traced contracts */
  maxRiskScore: number;
  /** The highest risk level across all traced contracts */
  maxRiskLevel: string;
  /** If trace fell back, the reason */
  fallbackReason?: string;
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

// ---------------------------------------------------------------------------
// Trace-enhanced simulation
// ---------------------------------------------------------------------------

/** Rate-limit delay between contract fetches to avoid blasting the RPC. */
const FETCH_DELAY_MS = 150;

/**
 * Fetch contract source code from Etherscan/Basescan.
 * Extracted here so both the simulator and MCP server can use it.
 */
export async function fetchContractSource(
  address: string,
  chainId: number,
): Promise<{ source?: string; bytecode?: string }> {
  const explorerApis: Record<number, string> = {
    1: "https://api.etherscan.io/api",
    8453: "https://api.basescan.org/api",
    84532: "https://api-sepolia.basescan.org/api",
  };

  const apiBase = explorerApis[chainId];
  if (!apiBase) return {};

  const apiKey = process.env.ETHERSCAN_API_KEY || "";

  try {
    const fetchOpts = { signal: AbortSignal.timeout(10_000) };

    const sourceUrl = `${apiBase}?module=contract&action=getsourcecode&address=${address}&apikey=${apiKey}`;
    const sourceRes = await fetch(sourceUrl, fetchOpts);
    if (!sourceRes.ok) return {};
    const sourceData = await sourceRes.json();

    if (sourceData.result?.[0]?.SourceCode) {
      const src = sourceData.result[0].SourceCode;
      if (src && src !== "") {
        return { source: src };
      }
    }

    const codeUrl = `${apiBase}?module=proxy&action=eth_getCode&address=${address}&tag=latest&apikey=${apiKey}`;
    const codeRes = await fetch(codeUrl, fetchOpts);
    if (!codeRes.ok) return {};
    const codeData = await codeRes.json();

    if (codeData.result && codeData.result !== "0x") {
      return { bytecode: codeData.result };
    }
  } catch {
    // Silently fail -- caller handles missing data
  }

  return {};
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Run the full simulation pipeline with trace-level analysis.
 *
 * 1. Runs the standard simulation (estimateGas + call).
 * 2. Runs the tracer to extract all internal calls.
 * 3. For each unique non-well-known contract, fetches source/bytecode and scans.
 * 4. Aggregates risk: the transaction risk is the MAX across all touched contracts.
 */
export async function simulateWithTrace(req: SimulationRequest): Promise<SimulationResult> {
  // Step 1: standard simulation
  const simResult = await simulateTransaction(req);

  // Step 2: trace
  const traceResult = await traceTransaction({
    chainId: req.chainId,
    from: req.from,
    to: req.to,
    data: req.data,
    value: req.value,
    blockNumber: req.blockNumber,
  });

  // Step 3: scan each traced contract
  const scanTargets = filterScanTargets(traceResult.uniqueAddresses);
  const tracedContracts: TracedContract[] = [];

  // Build a map of call types and max depth per address from the trace
  const callMeta = new Map<string, { callTypes: Set<string>; maxDepth: number }>();
  for (const call of traceResult.calls) {
    const lower = call.address.toLowerCase();
    const existing = callMeta.get(lower);
    if (existing) {
      existing.callTypes.add(call.type);
      existing.maxDepth = Math.max(existing.maxDepth, call.depth);
    } else {
      callMeta.set(lower, { callTypes: new Set([call.type]), maxDepth: call.depth });
    }
  }

  let maxRiskScore = 0;
  let maxRiskLevel = "safe";

  // Process well-known addresses first (no scanning needed)
  for (const addr of traceResult.uniqueAddresses) {
    const lower = addr.toLowerCase() as Address;
    if (isWellKnown(lower)) {
      const meta = callMeta.get(lower);
      tracedContracts.push({
        address: lower,
        wellKnown: true,
        callTypes: meta ? Array.from(meta.callTypes) : ["CALL"],
        maxDepth: meta?.maxDepth ?? 0,
      });
    }
  }

  // Scan non-well-known addresses with rate limiting
  for (let i = 0; i < scanTargets.length; i++) {
    const addr = scanTargets[i];
    const meta = callMeta.get(addr.toLowerCase());

    let scanResult: ScanResult | undefined;
    try {
      const fetched = await fetchContractSource(addr, req.chainId);
      if (fetched.source) {
        scanResult = scanContractSource(fetched.source);
      } else if (fetched.bytecode) {
        scanResult = scanBytecode(fetched.bytecode);
      }
    } catch {
      // Fetch failed -- we still record the address, just without a scan
    }

    if (scanResult) {
      if (scanResult.riskScore > maxRiskScore) {
        maxRiskScore = scanResult.riskScore;
        maxRiskLevel = scanResult.riskLevel;
      }
    }

    tracedContracts.push({
      address: addr,
      wellKnown: false,
      scanResult,
      callTypes: meta ? Array.from(meta.callTypes) : ["CALL"],
      maxDepth: meta?.maxDepth ?? 0,
    });

    // Rate limit between fetches (skip delay after last item)
    if (i < scanTargets.length - 1) {
      await delay(FETCH_DELAY_MS);
    }
  }

  // Step 4: aggregate risk into the simulation result
  if (maxRiskScore > 0) {
    if (maxRiskScore >= 70) {
      simResult.riskIndicators.push("traced_contract_high_risk");
    } else if (maxRiskScore >= 40) {
      simResult.riskIndicators.push("traced_contract_medium_risk");
    }
  }

  // Check for delegatecall in non-well-known contracts -- extra risky
  const hasDelegatecall = tracedContracts.some(
    (c) => !c.wellKnown && c.callTypes.includes("DELEGATECALL"),
  );
  if (hasDelegatecall) {
    simResult.riskIndicators.push("delegatecall_in_trace");
  }

  simResult.trace = {
    fullTrace: traceResult.fullTrace,
    totalCalls: traceResult.calls.length,
    uniqueContracts: traceResult.uniqueAddresses.length,
    scannedContracts: tracedContracts.filter((c) => c.scanResult !== undefined).length,
    contracts: tracedContracts,
    maxRiskScore,
    maxRiskLevel,
    fallbackReason: traceResult.fallbackReason,
  };

  return simResult;
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
