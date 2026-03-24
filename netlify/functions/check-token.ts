/**
 * POST /api/check-token
 *
 * Check if a token is safe to trade (anti-honeypot).
 * Accepts: { tokenAddress, chainId?, holderAddress? }
 * Returns: sellability check + contract scan results
 */

import type { Config } from "@netlify/functions";
import type { Address } from "viem";
import { scanContractSource, scanBytecode } from "../../src/risk-engine/scanner.js";
import { checkTokenSellability, fetchContractSource } from "../../src/risk-engine/simulator.js";
import {
  apiHandler,
  jsonResponse,
  errorResponse,
  isValidAddress,
  isValidChainId,
} from "./shared.js";

export default apiHandler(async (body) => {
  const { tokenAddress, chainId = 1, holderAddress } = body;

  // Validate inputs
  if (!tokenAddress) {
    return errorResponse("tokenAddress is required.", 400);
  }

  if (!isValidAddress(tokenAddress)) {
    return errorResponse(
      "Invalid tokenAddress. Must be a 0x-prefixed 40-character hex string.",
      400,
    );
  }

  if (holderAddress && !isValidAddress(holderAddress)) {
    return errorResponse(
      "Invalid holderAddress. Must be a 0x-prefixed 40-character hex string.",
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

  const holder = (holderAddress || "0x0000000000000000000000000000000000000001") as Address;

  // Run sellability check
  const sellCheck = await checkTokenSellability(
    chain,
    tokenAddress as Address,
    holder,
  );

  // Also scan the contract source if available
  const fetched = await fetchContractSource(tokenAddress as string, chain);
  let scanResult = null;
  if (fetched.source) {
    scanResult = scanContractSource(fetched.source);
  } else if (fetched.bytecode) {
    scanResult = scanBytecode(fetched.bytecode);
  }

  return jsonResponse({
    tokenAddress,
    chainId: chain,
    sellability: sellCheck,
    contractScan: scanResult,
    overallAssessment:
      sellCheck.canSell && (!scanResult || scanResult.riskScore < 70)
        ? "LIKELY_SAFE"
        : "POTENTIALLY_DANGEROUS",
  });
});

export const config: Config = {
  path: "/api/check-token",
};
