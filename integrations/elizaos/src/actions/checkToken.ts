import { type Action } from "@elizaos/core";
import { checkTokenSellability } from "aegis-defi";
import { extractAddress, extractChainId } from "../util.js";

/**
 * Anti-honeypot check. Verifies whether a token can actually be sold
 * after purchase, catching common scam patterns like blocked transfers,
 * hidden fees, and frozen liquidity.
 */
export const checkTokenAction: Action = {
  name: "AEGIS_CHECK_TOKEN",
  similes: [
    "HONEYPOT_CHECK",
    "IS_HONEYPOT",
    "CHECK_TOKEN",
    "CAN_I_SELL",
    "TOKEN_SAFETY",
  ],
  description:
    "Check if a token is a honeypot. Tests whether the token can " +
    "actually be sold after buying, detecting hidden fees, transfer " +
    "blocks, and other scam mechanisms.",

  validate: async (_runtime, message) => {
    const text = message.content?.text ?? "";
    return extractAddress(text) !== null;
  },

  handler: async (_runtime, message, _state, _options, callback) => {
    const text = message.content?.text ?? "";
    const address = extractAddress(text);
    if (!address) {
      await callback?.({ text: "Please include a token address (0x...) to check." });
      return { success: false, text: "No token address found." };
    }

    const chainId = extractChainId(text) ?? 1;
    await callback?.({ text: `Checking if \`${address}\` on chain ${chainId} is a honeypot...` });

    try {
      const result = await checkTokenSellability(address, chainId);
      const summary = formatTokenCheck(result, address, chainId);
      await callback?.({ text: summary });
      return { success: true, text: summary };
    } catch (err) {
      const msg = `Token check failed: ${String(err)}`;
      await callback?.({ text: msg });
      return { success: false, text: msg };
    }
  },

  examples: [
    [
      {
        user: "user",
        content: { text: "Is 0xAbCdEf1234567890AbCdEf1234567890AbCdEf12 a honeypot?" },
      },
      {
        user: "agent",
        content: { text: "Checking if `0xAbCdEf1234567890AbCdEf1234567890AbCdEf12` on chain 1 is a honeypot..." },
      },
    ],
    [
      {
        user: "user",
        content: { text: "Can I sell this token on BSC? 0x1234..." },
      },
      {
        user: "agent",
        content: { text: "Checking if `0x1234...` on chain 56 is a honeypot..." },
      },
    ],
  ],
};

function formatTokenCheck(
  result: Record<string, unknown>,
  address: string,
  chainId: number,
): string {
  const lines: string[] = [];
  lines.push(`**Token Honeypot Check** - \`${address}\` (chain ${chainId})`);
  lines.push("");

  // The result shape depends on the aegis-defi implementation, so we
  // handle it generically while surfacing the most useful fields.
  if (typeof result === "object" && result !== null) {
    if ("sellable" in result) {
      lines.push(result.sellable ? "Sellable: Yes" : "Sellable: **NO - potential honeypot**");
    }
    if ("buyTax" in result) {
      lines.push(`Buy tax: ${result.buyTax}%`);
    }
    if ("sellTax" in result) {
      lines.push(`Sell tax: ${result.sellTax}%`);
    }
    if ("reason" in result && result.reason) {
      lines.push(`Details: ${result.reason}`);
    }

    // Fallback: dump any remaining useful fields
    const shown = new Set(["sellable", "buyTax", "sellTax", "reason"]);
    for (const [key, value] of Object.entries(result)) {
      if (!shown.has(key) && value !== undefined && value !== null) {
        lines.push(`${key}: ${JSON.stringify(value)}`);
      }
    }
  } else {
    lines.push(JSON.stringify(result, null, 2));
  }

  return lines.join("\n");
}
