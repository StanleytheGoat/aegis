/**
 * Aegis Risk Engine - Transaction Tracer
 *
 * After simulating a transaction via viem's call(), uses debug_traceCall
 * with the callTracer preset to extract the full internal call tree. This
 * surfaces every contract touched during execution so the scanner can
 * evaluate each one individually.
 *
 * When debug_traceCall is unavailable (most public RPC endpoints don't
 * support it), falls back gracefully to returning only the entry-point
 * contract.
 */

import {
  createPublicClient,
  http,
  type Address,
  type Hex,
  type Chain,
  type PublicClient,
  type Transport,
} from "viem";
import { mainnet, base, baseSepolia } from "viem/chains";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A single internal call extracted from the trace. */
export interface TraceCall {
  /** Contract address that was called */
  address: Address;
  /** Call type (CALL, DELEGATECALL, STATICCALL, CREATE, etc.) */
  type: string;
  /** Nesting depth in the call tree (0 = top-level) */
  depth: number;
  /** ETH value transferred in this call (wei, hex-encoded) */
  value: string;
  /** The 4-byte function selector if calldata is present */
  selector?: Hex;
  /** Gas used by this frame */
  gasUsed?: string;
}

/** Result of a trace operation. */
export interface TraceResult {
  /** Whether the trace used debug_traceCall (true) or fell back (false) */
  fullTrace: boolean;
  /** Ordered list of every call frame */
  calls: TraceCall[];
  /** De-duplicated list of contract addresses touched */
  uniqueAddresses: Address[];
  /** If the trace failed, a human-readable reason */
  fallbackReason?: string;
}

/** Raw shape returned by debug_traceCall with { tracer: "callTracer" }. */
export interface RawCallFrame {
  type: string;
  from: string;
  to?: string;
  value?: string;
  gas?: string;
  gasUsed?: string;
  input?: string;
  output?: string;
  calls?: RawCallFrame[];
  error?: string;
}

// ---------------------------------------------------------------------------
// Well-known contracts (skip scanning these)
// ---------------------------------------------------------------------------

/**
 * Addresses that are part of core infrastructure and don't need scanning.
 * All stored as lowercase for fast lookup.
 */
export const WELL_KNOWN_CONTRACTS: Set<string> = new Set([
  // -- Ethereum mainnet --
  "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // WETH
  "0x7a250d5630b4cf539739df2c5dacb4c659f2488d", // Uniswap V2 Router
  "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45", // Uniswap V3 Router (SwapRouter02)
  "0xe592427a0aece92de3edee1f18e0157c05861564", // Uniswap V3 SwapRouter
  "0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b", // Uniswap Universal Router
  "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad", // Uniswap Universal Router v2
  "0x6b175474e89094c44da98b954eedeac495271d0f", // DAI
  "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // USDC
  "0xdac17f958d2ee523a2206206994597c13d831ec7", // USDT
  "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599", // WBTC
  "0x1111111254eeb25477b68fb85ed929f73a960582", // 1inch v5
  "0x1111111254fb6c44bac0bed2854e76f90643097d", // 1inch v4

  // -- Base mainnet --
  "0x4200000000000000000000000000000000000006", // WETH on Base
  "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", // USDC on Base
  "0x2626664c2603336e57b271c5c0b26f421741e481", // Uniswap V3 SwapRouter on Base
  "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad", // Universal Router on Base
  "0x2ae3f1ec7f1f5012cfeab0185bfc7aa3cf0dec22", // Uniswap V3 Factory on Base
]);

// ---------------------------------------------------------------------------
// Chain config (mirrors simulator.ts)
// ---------------------------------------------------------------------------

const CHAIN_MAP: Record<number, { chain: Chain; rpcUrl: string }> = {
  1: { chain: mainnet, rpcUrl: process.env.ETH_RPC_URL || "https://eth.llamarpc.com" },
  8453: { chain: base, rpcUrl: process.env.BASE_RPC || "https://mainnet.base.org" },
  84532: { chain: baseSepolia, rpcUrl: process.env.BASE_SEPOLIA_RPC || "https://sepolia.base.org" },
};

// ---------------------------------------------------------------------------
// Core tracer
// ---------------------------------------------------------------------------

export interface TraceRequest {
  chainId: number;
  from: Address;
  to: Address;
  data: Hex;
  value?: bigint;
  blockNumber?: bigint;
}

/**
 * Trace a transaction to extract every contract it touches internally.
 *
 * Tries debug_traceCall first. If the RPC doesn't support it, falls back
 * to returning just the entry contract.
 */
export async function traceTransaction(req: TraceRequest): Promise<TraceResult> {
  const chainConfig = CHAIN_MAP[req.chainId];
  if (!chainConfig) {
    return {
      fullTrace: false,
      calls: [{ address: req.to, type: "CALL", depth: 0, value: req.value?.toString() ?? "0" }],
      uniqueAddresses: [req.to],
      fallbackReason: `Unsupported chain ID: ${req.chainId}`,
    };
  }

  const client = createPublicClient({
    chain: chainConfig.chain,
    transport: http(chainConfig.rpcUrl),
  });

  try {
    const rawTrace = await requestDebugTrace(client, req);
    const calls = flattenCallTree(rawTrace, 0);
    const uniqueAddresses = deduplicateAddresses(calls);

    return {
      fullTrace: true,
      calls,
      uniqueAddresses,
    };
  } catch (err: any) {
    // debug_traceCall not supported -- fall back to entry contract only
    return {
      fullTrace: false,
      calls: [{ address: req.to, type: "CALL", depth: 0, value: req.value?.toString() ?? "0" }],
      uniqueAddresses: [req.to],
      fallbackReason: extractFallbackReason(err),
    };
  }
}

/**
 * Issue a raw debug_traceCall JSON-RPC request through viem's transport.
 */
async function requestDebugTrace(
  client: PublicClient<Transport, Chain>,
  req: TraceRequest,
): Promise<RawCallFrame> {
  const txObj: Record<string, string> = {
    from: req.from,
    to: req.to,
    data: req.data,
  };
  if (req.value && req.value > 0n) {
    txObj.value = "0x" + req.value.toString(16);
  }

  const blockTag = req.blockNumber ? "0x" + req.blockNumber.toString(16) : "latest";

  const result = await client.request({
    method: "debug_traceCall" as any,
    params: [txObj, blockTag, { tracer: "callTracer", tracerConfig: { onlyTopCall: false } }] as any,
  });

  return result as unknown as RawCallFrame;
}

/**
 * Recursively flatten a nested call frame tree into a flat list.
 */
export function flattenCallTree(frame: RawCallFrame, depth: number): TraceCall[] {
  const calls: TraceCall[] = [];

  const address = (frame.to || frame.from || "").toLowerCase() as Address;
  if (address && address !== "0x") {
    const input = frame.input || "";
    const selector = input.length >= 10 ? (input.slice(0, 10) as Hex) : undefined;

    calls.push({
      address,
      type: (frame.type || "CALL").toUpperCase(),
      depth,
      value: frame.value || "0x0",
      selector,
      gasUsed: frame.gasUsed,
    });
  }

  if (frame.calls) {
    for (const child of frame.calls) {
      calls.push(...flattenCallTree(child, depth + 1));
    }
  }

  return calls;
}

/**
 * Deduplicate addresses, preserving order of first appearance.
 * Normalizes to lowercase for comparison.
 */
export function deduplicateAddresses(calls: TraceCall[]): Address[] {
  const seen = new Set<string>();
  const result: Address[] = [];

  for (const call of calls) {
    const lower = call.address.toLowerCase();
    if (!seen.has(lower)) {
      seen.add(lower);
      result.push(lower as Address);
    }
  }

  return result;
}

/**
 * Check whether an address is a well-known contract that doesn't need scanning.
 */
export function isWellKnown(address: Address): boolean {
  return WELL_KNOWN_CONTRACTS.has(address.toLowerCase());
}

/**
 * Filter trace addresses down to only those that need scanning.
 * Removes well-known contracts and the zero address.
 */
export function filterScanTargets(addresses: Address[]): Address[] {
  return addresses.filter((addr) => {
    const lower = addr.toLowerCase();
    if (lower === "0x0000000000000000000000000000000000000000") return false;
    return !WELL_KNOWN_CONTRACTS.has(lower);
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function extractFallbackReason(err: any): string {
  if (typeof err?.message === "string") {
    if (err.message.includes("method not found") || err.message.includes("not supported")) {
      return "RPC does not support debug_traceCall";
    }
    if (err.message.includes("method not available") || err.message.includes("Method not found")) {
      return "RPC does not support debug_traceCall";
    }
    return err.message.slice(0, 200);
  }
  return "Unknown error during trace";
}
