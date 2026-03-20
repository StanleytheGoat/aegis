import { type Action } from "@elizaos/core";
import {
  scanContractSource,
  simulateTransaction,
  checkTokenSellability,
  fetchContractSource,
} from "aegis-defi";
import { extractAddress, extractChainId, formatRiskVerdict } from "../util.js";

/**
 * Primary risk assessment action. Pulls together contract scanning,
 * transaction simulation, and honeypot detection into a single
 * allow / warn / block verdict.
 */
export const assessRiskAction: Action = {
  name: "AEGIS_ASSESS_RISK",
  similes: [
    "CHECK_RISK",
    "DEFI_SAFETY_CHECK",
    "IS_THIS_SAFE",
    "RISK_CHECK",
    "ASSESS_CONTRACT",
  ],
  description:
    "Run a full Aegis safety assessment on a contract or token. " +
    "Combines source scanning, transaction simulation, and sell-ability " +
    "checks to produce an overall allow/warn/block decision.",

  validate: async (_runtime, message) => {
    const text = message.content?.text ?? "";
    return extractAddress(text) !== null;
  },

  handler: async (_runtime, message, _state, _options, callback) => {
    const text = message.content?.text ?? "";
    const address = extractAddress(text);
    if (!address) {
      await callback?.({ text: "I couldn't find a contract or token address in your message. Please include a 0x address." });
      return { success: false, text: "No address found." };
    }

    const chainId = extractChainId(text) ?? 1;
    await callback?.({ text: `Starting Aegis risk assessment for \`${address}\` on chain ${chainId}...` });

    // 1. Fetch and scan contract source
    let scanResult = null;
    try {
      const source = await fetchContractSource(address, chainId);
      if (source) {
        await callback?.({ text: "Scanning contract source code..." });
        scanResult = await scanContractSource(source);
      } else {
        await callback?.({ text: "Source code not verified - skipping source scan." });
      }
    } catch (err) {
      await callback?.({ text: `Source scan encountered an error: ${String(err)}` });
    }

    // 2. Simulate a basic transfer to detect traps
    let simResult = null;
    try {
      await callback?.({ text: "Simulating a test transaction..." });
      simResult = await simulateTransaction({
        chainId,
        from: "0x0000000000000000000000000000000000000001",
        to: address,
        data: "0x",
      });
    } catch (err) {
      await callback?.({ text: `Transaction simulation encountered an error: ${String(err)}` });
    }

    // 3. Token sell-ability check (honeypot detection)
    let sellCheck = null;
    try {
      await callback?.({ text: "Checking token sell-ability (honeypot detection)..." });
      sellCheck = await checkTokenSellability(address, chainId);
    } catch (err) {
      // Not every address is a token, so this failing is expected sometimes
    }

    // Build verdict
    const verdict = formatRiskVerdict({ scanResult, simResult, sellCheck, address, chainId });
    await callback?.({ text: verdict });

    return { success: true, text: verdict };
  },

  examples: [
    [
      {
        user: "user",
        content: { text: "Is this contract safe? 0xdAC17F958D2ee523a2206206994597C13D831ec7" },
      },
      {
        user: "agent",
        content: {
          text: "Starting Aegis risk assessment for `0xdAC17F958D2ee523a2206206994597C13D831ec7` on chain 1...",
        },
      },
    ],
    [
      {
        user: "user",
        content: { text: "Assess risk for 0xAbC123 on arbitrum" },
      },
      {
        user: "agent",
        content: {
          text: "Starting Aegis risk assessment for `0xAbC123` on chain 42161...",
        },
      },
    ],
  ],
};
