/**
 * POST /api/scan
 *
 * Scan a smart contract for exploit patterns.
 * Accepts: { contractAddress, chainId?, source?, bytecode? }
 * Returns: ScanResult JSON (riskScore, findings, recommendation)
 */

import type { Config } from "@netlify/functions";
import { scanContractSource, scanBytecode } from "../../src/risk-engine/scanner.js";
import { fetchContractSource } from "../../src/risk-engine/simulator.js";
import {
  apiHandler,
  jsonResponse,
  errorResponse,
  isValidAddress,
  isValidChainId,
} from "./shared.js";

export default apiHandler(async (body) => {
  const { contractAddress, chainId = 1, source, bytecode } = body;

  // Validate inputs
  if (!source && !bytecode && !contractAddress) {
    return errorResponse(
      "Provide at least one of: contractAddress, source, or bytecode.",
      400,
    );
  }

  if (contractAddress && !isValidAddress(contractAddress)) {
    return errorResponse(
      "Invalid contractAddress. Must be a 0x-prefixed 40-character hex string.",
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

  // Resolve source/bytecode from address if needed
  let resolvedSource = typeof source === "string" ? source : undefined;
  let resolvedBytecode = typeof bytecode === "string" ? bytecode : undefined;

  if (contractAddress && !resolvedSource && !resolvedBytecode) {
    const fetched = await fetchContractSource(contractAddress as string, chain);
    if (fetched.source) resolvedSource = fetched.source;
    if (fetched.bytecode) resolvedBytecode = fetched.bytecode;
  }

  if (!resolvedSource && !resolvedBytecode) {
    return errorResponse(
      "Could not fetch contract source or bytecode. Provide them directly.",
      422,
    );
  }

  const result = resolvedSource
    ? scanContractSource(resolvedSource)
    : scanBytecode(resolvedBytecode!);

  return jsonResponse({
    contractAddress: contractAddress || null,
    chainId: chain,
    ...result,
  });
});

export const config: Config = {
  path: "/api/scan",
};
