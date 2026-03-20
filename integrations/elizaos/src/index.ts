import { type Plugin } from "@elizaos/core";
import { assessRiskAction } from "./actions/assessRisk.js";
import { scanContractAction } from "./actions/scanContract.js";
import { checkTokenAction } from "./actions/checkToken.js";
import { searchAuditFindingsAction } from "./actions/searchAuditFindings.js";
import { safetyProvider } from "./providers/safetyProvider.js";

export const aegisPlugin: Plugin = {
  name: "plugin-aegis",
  description:
    "Aegis DeFi safety plugin. Gives your ElizaOS agent the ability to " +
    "scan smart contracts, detect honeypot tokens, simulate transactions, " +
    "and search real-world audit findings - all powered by the Aegis risk engine.",
  actions: [
    assessRiskAction,
    scanContractAction,
    checkTokenAction,
    searchAuditFindingsAction,
  ],
  providers: [safetyProvider],
};

export default aegisPlugin;

// Re-export individual pieces for advanced usage
export { assessRiskAction } from "./actions/assessRisk.js";
export { scanContractAction } from "./actions/scanContract.js";
export { checkTokenAction } from "./actions/checkToken.js";
export { searchAuditFindingsAction } from "./actions/searchAuditFindings.js";
export { safetyProvider } from "./providers/safetyProvider.js";
