import {
  ActionProvider,
  CreateAction,
  WalletProvider,
} from "@coinbase/agentkit";
import type { Network } from "@coinbase/agentkit";
import { z } from "zod";
import {
  scanContractSource,
  simulateTransaction,
  checkTokenSellability,
  fetchContractSource,
  querySolodit,
} from "aegis-defi";
import {
  AssessRiskSchema,
  ScanContractSchema,
  CheckTokenSchema,
  SearchAuditFindingsSchema,
} from "./schemas.js";

const SUPPORTED_CHAINS = new Set([1, 8453, 84532]);

/**
 * Determines an overall verdict from a risk score.
 * - 0-39: ALLOW (low risk, safe to proceed)
 * - 40-69: WARN (some concerns, proceed with caution)
 * - 70-100: BLOCK (high risk, do not proceed)
 */
function verdict(riskScore: number): "ALLOW" | "WARN" | "BLOCK" {
  if (riskScore >= 70) return "BLOCK";
  if (riskScore >= 40) return "WARN";
  return "ALLOW";
}

class AegisActionProvider extends ActionProvider<WalletProvider> {
  constructor() {
    super("aegis-safety", []);
  }

  supportsNetwork(network: Network): boolean {
    const chainId =
      typeof network.chainId === "string"
        ? parseInt(network.chainId, 10)
        : Number(network.chainId);
    return SUPPORTED_CHAINS.has(chainId);
  }

  // ---------------------------------------------------------------
  // assess_risk - primary action combining scan + simulate + token
  // ---------------------------------------------------------------
  @CreateAction({
    name: "assess_risk",
    description:
      "Run a full safety assessment on a contract before interacting with it. " +
      "Combines source code analysis, transaction simulation, and token sellability checks " +
      "into a single ALLOW / WARN / BLOCK decision. Use this before any DeFi transaction.",
    schema: AssessRiskSchema,
  })
  async assessRisk(
    walletProvider: WalletProvider,
    args: z.infer<typeof AssessRiskSchema>,
  ): Promise<string> {
    const { contractAddress, chainId, action, transactionData, value } = args;
    const agentAddress = walletProvider.getAddress();

    const results: {
      scan?: Awaited<ReturnType<typeof scanContractSource>>;
      simulation?: Awaited<ReturnType<typeof simulateTransaction>>;
      tokenCheck?: Awaited<ReturnType<typeof checkTokenSellability>>;
      errors: string[];
    } = { errors: [] };

    // 1. Fetch and scan source code
    try {
      const source = await fetchContractSource(contractAddress, chainId);
      if (source) {
        results.scan = await scanContractSource(source);
      } else {
        results.errors.push(
          "Contract source not verified - could not perform static analysis",
        );
      }
    } catch (err: unknown) {
      results.errors.push(
        `Source scan failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    // 2. Simulate the transaction if we have calldata
    if (transactionData) {
      try {
        results.simulation = await simulateTransaction({
          chainId,
          from: agentAddress,
          to: contractAddress,
          data: transactionData,
          value,
        });
      } catch (err: unknown) {
        results.errors.push(
          `Simulation failed: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }

    // 3. Token sellability check (relevant for swap/approve/transfer actions)
    const tokenActions = new Set(["swap", "approve", "transfer"]);
    if (tokenActions.has(action)) {
      try {
        results.tokenCheck = await checkTokenSellability(
          contractAddress,
          chainId,
        );
      } catch (err: unknown) {
        results.errors.push(
          `Token check failed: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }

    // 4. Combine into a single risk score
    const scores: number[] = [];
    if (results.scan) scores.push(results.scan.riskScore);

    // Unverified source is itself a risk signal
    if (!results.scan && results.errors.length > 0) scores.push(50);

    const maxScore =
      scores.length > 0 ? Math.max(...scores) : 50; // default moderate if nothing ran

    const decision = verdict(maxScore);

    return JSON.stringify({
      decision,
      riskScore: maxScore,
      contractAddress,
      chainId,
      action,
      agentAddress,
      scan: results.scan ?? null,
      simulation: results.simulation ?? null,
      tokenCheck: results.tokenCheck ?? null,
      errors: results.errors,
    });
  }

  // ---------------------------------------------------------------
  // scan_contract - static analysis of a verified contract
  // ---------------------------------------------------------------
  @CreateAction({
    name: "scan_contract",
    description:
      "Fetch a contract's verified source code from the block explorer and scan it " +
      "for known vulnerability patterns. Returns a risk score and a list of findings " +
      "with severity levels.",
    schema: ScanContractSchema,
  })
  async scanContract(
    _walletProvider: WalletProvider,
    args: z.infer<typeof ScanContractSchema>,
  ): Promise<string> {
    const { contractAddress, chainId } = args;

    const source = await fetchContractSource(contractAddress, chainId);
    if (!source) {
      return JSON.stringify({
        error: "Contract source is not verified on the block explorer",
        contractAddress,
        chainId,
      });
    }

    const result = await scanContractSource(source);

    return JSON.stringify({
      contractAddress,
      chainId,
      riskScore: result.riskScore,
      decision: verdict(result.riskScore),
      findings: result.findings,
      summary: result.summary,
    });
  }

  // ---------------------------------------------------------------
  // check_token - honeypot / sellability check
  // ---------------------------------------------------------------
  @CreateAction({
    name: "check_token",
    description:
      "Check whether an ERC-20 token can actually be sold after buying. " +
      "Detects common honeypot tricks like hidden transfer fees, sell blockers, " +
      "and owner-only transfer restrictions.",
    schema: CheckTokenSchema,
  })
  async checkToken(
    _walletProvider: WalletProvider,
    args: z.infer<typeof CheckTokenSchema>,
  ): Promise<string> {
    const { tokenAddress, chainId } = args;
    const result = await checkTokenSellability(tokenAddress, chainId);
    return JSON.stringify({ tokenAddress, chainId, ...result });
  }

  // ---------------------------------------------------------------
  // search_audit_findings - query Solodit's database
  // ---------------------------------------------------------------
  @CreateAction({
    name: "search_audit_findings",
    description:
      "Search the Solodit database for real-world audit findings that match your keywords. " +
      "Useful for understanding known attack vectors before interacting with a protocol. " +
      "Returns titles, descriptions, and severity for each matching finding.",
    schema: SearchAuditFindingsSchema,
  })
  async searchAuditFindings(
    _walletProvider: WalletProvider,
    args: z.infer<typeof SearchAuditFindingsSchema>,
  ): Promise<string> {
    const { keywords, impact, limit } = args;
    const findings = await querySolodit(keywords, impact, limit);
    return JSON.stringify({ keywords, impact, count: findings.length, findings });
  }
}

export const aegisActionProvider = () => new AegisActionProvider();
