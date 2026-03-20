import { type Provider } from "@elizaos/core";
import { EXPLOIT_PATTERNS } from "aegis-defi";

/**
 * Provides ambient safety context to the ElizaOS agent. When the agent
 * assembles its context window, this provider injects a note about
 * available Aegis capabilities and the current exploit pattern count.
 */
export const safetyProvider: Provider = {
  get: async (_runtime, _message) => {
    const patternCount = EXPLOIT_PATTERNS?.length ?? 0;

    return [
      "Aegis DeFi safety layer is active.",
      `The risk engine tracks ${patternCount} known exploit patterns.`,
      "Available safety actions: full risk assessment (AEGIS_ASSESS_RISK),",
      "contract scanning (AEGIS_SCAN_CONTRACT), honeypot detection",
      "(AEGIS_CHECK_TOKEN), and audit finding search (AEGIS_SEARCH_AUDIT_FINDINGS).",
      "When a user asks about contract safety, token legitimacy, or DeFi risks,",
      "use the appropriate Aegis action to give them a concrete answer.",
    ].join(" ");
  },
};
