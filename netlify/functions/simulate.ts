/**
 * POST /api/simulate
 *
 * Simulate a transaction on a forked chain.
 * Accepts: { chainId?, from, to, data, value? }
 * Returns: simulation results (success, gasUsed, revert reason, etc.)
 */

import type { Config } from "@netlify/functions";
import type { Address, Hex } from "viem";
import { simulateTransaction } from "../../src/risk-engine/simulator.js";
import {
  apiHandler,
  jsonResponse,
  errorResponse,
  isValidAddress,
  isValidChainId,
  isValidHex,
} from "./shared.js";

export default apiHandler(async (body) => {
  const { chainId = 1, from, to, data, value = "0" } = body;

  // Validate inputs
  if (!from) {
    return errorResponse("from address is required.", 400);
  }
  if (!to) {
    return errorResponse("to address is required.", 400);
  }
  if (!data) {
    return errorResponse("data (transaction calldata) is required.", 400);
  }

  if (!isValidAddress(from)) {
    return errorResponse(
      "Invalid from address. Must be a 0x-prefixed 40-character hex string.",
      400,
    );
  }
  if (!isValidAddress(to)) {
    return errorResponse(
      "Invalid to address. Must be a 0x-prefixed 40-character hex string.",
      400,
    );
  }
  if (!isValidHex(data)) {
    return errorResponse(
      "Invalid data. Must be a 0x-prefixed hex string.",
      400,
    );
  }

  const chain = typeof chainId === "number" ? chainId : Number(chainId);
  if (!isValidChainId(chain)) {
    return errorResponse(
      "Unsupported chainId. Supported: 1 (Ethereum), 8453 (Base), 84532 (Base Sepolia).",
      400,
    );
  }

  // Parse value as BigInt
  let parsedValue: bigint;
  try {
    parsedValue = BigInt(typeof value === "string" ? value : String(value));
  } catch {
    return errorResponse(
      "Invalid value. Must be a numeric string representing wei.",
      400,
    );
  }

  const result = await simulateTransaction({
    chainId: chain,
    from: from as Address,
    to: to as Address,
    data: data as Hex,
    value: parsedValue,
  });

  return jsonResponse({
    chainId: chain,
    from,
    to,
    ...result,
    gasUsed: result.gasUsed.toString(),
  });
});

export const config: Config = {
  path: "/api/simulate",
};
