import { type Action } from "@elizaos/core";
import {
  scanContractSource,
  scanBytecode,
  fetchContractSource,
} from "aegis-defi";
import { extractAddress, extractChainId } from "../util.js";

/**
 * Scan a smart contract for known vulnerability patterns.
 * Accepts either an on-chain address (source is fetched automatically)
 * or raw source / bytecode pasted directly into the message.
 */
export const scanContractAction: Action = {
  name: "AEGIS_SCAN_CONTRACT",
  similes: [
    "SCAN_CONTRACT",
    "AUDIT_CONTRACT",
    "CHECK_CONTRACT_SOURCE",
    "ANALYZE_CONTRACT",
  ],
  description:
    "Scan a smart contract for vulnerabilities and exploit patterns. " +
    "Provide a contract address (source will be fetched) or paste " +
    "source code / bytecode directly.",

  validate: async (_runtime, message) => {
    const text = message.content?.text ?? "";
    // Valid if there's an address or if the message contains what looks like source / bytecode
    return (
      extractAddress(text) !== null ||
      text.includes("pragma solidity") ||
      /^0x[0-9a-fA-F]{64,}/.test(text.trim())
    );
  },

  handler: async (_runtime, message, _state, _options, callback) => {
    const text = message.content?.text ?? "";

    // Case 1: raw bytecode in the message
    const bytecodeMatch = text.match(/\b(0x[0-9a-fA-F]{64,})\b/);
    if (bytecodeMatch && !text.includes("pragma solidity")) {
      await callback?.({ text: "Scanning provided bytecode..." });
      try {
        const result = await scanBytecode(bytecodeMatch[1]);
        const summary = formatScanSummary(result);
        await callback?.({ text: summary });
        return { success: true, text: summary };
      } catch (err) {
        const msg = `Bytecode scan failed: ${String(err)}`;
        await callback?.({ text: msg });
        return { success: false, text: msg };
      }
    }

    // Case 2: raw Solidity source in the message
    if (text.includes("pragma solidity")) {
      await callback?.({ text: "Scanning provided Solidity source..." });
      try {
        const result = await scanContractSource(text);
        const summary = formatScanSummary(result);
        await callback?.({ text: summary });
        return { success: true, text: summary };
      } catch (err) {
        const msg = `Source scan failed: ${String(err)}`;
        await callback?.({ text: msg });
        return { success: false, text: msg };
      }
    }

    // Case 3: address - fetch source, then scan
    const address = extractAddress(text);
    if (!address) {
      await callback?.({ text: "Please provide a contract address, Solidity source, or bytecode to scan." });
      return { success: false, text: "No scannable input found." };
    }

    const chainId = extractChainId(text) ?? 1;
    await callback?.({ text: `Fetching source for \`${address}\` on chain ${chainId}...` });

    try {
      const source = await fetchContractSource(address, chainId);
      if (!source) {
        const msg = "Contract source is not verified on-chain. Try providing the source code or bytecode directly.";
        await callback?.({ text: msg });
        return { success: false, text: msg };
      }

      await callback?.({ text: "Source retrieved. Scanning for vulnerabilities..." });
      const result = await scanContractSource(source);
      const summary = formatScanSummary(result);
      await callback?.({ text: summary });
      return { success: true, text: summary };
    } catch (err) {
      const msg = `Scan failed: ${String(err)}`;
      await callback?.({ text: msg });
      return { success: false, text: msg };
    }
  },

  examples: [
    [
      {
        user: "user",
        content: { text: "Scan contract 0xdAC17F958D2ee523a2206206994597C13D831ec7" },
      },
      {
        user: "agent",
        content: { text: "Fetching source for `0xdAC17F958D2ee523a2206206994597C13D831ec7` on chain 1..." },
      },
    ],
    [
      {
        user: "user",
        content: { text: "Audit this contract on polygon: 0xABC123" },
      },
      {
        user: "agent",
        content: { text: "Fetching source for `0xABC123` on chain 137..." },
      },
    ],
  ],
};

function formatScanSummary(result: { riskScore: number; findings: Array<{ name: string; severity: string; description: string }>; summary: string }): string {
  const lines: string[] = [];
  lines.push(`**Risk Score:** ${result.riskScore}/100`);
  lines.push(`**Summary:** ${result.summary}`);

  if (result.findings.length > 0) {
    lines.push("");
    lines.push(`**Findings (${result.findings.length}):**`);
    for (const f of result.findings) {
      lines.push(`- [${f.severity.toUpperCase()}] ${f.name}: ${f.description}`);
    }
  } else {
    lines.push("\nNo vulnerability patterns detected.");
  }

  return lines.join("\n");
}
