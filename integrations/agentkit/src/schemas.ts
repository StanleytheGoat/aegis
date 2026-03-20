import { z } from "zod";

export const AssessRiskSchema = z.object({
  contractAddress: z
    .string()
    .describe("The contract address to assess (0x-prefixed hex)"),
  chainId: z
    .number()
    .describe("Chain ID where the contract is deployed (1 for Ethereum, 8453 for Base, 84532 for Base Sepolia)"),
  action: z
    .enum(["swap", "approve", "transfer", "mint", "stake", "other"])
    .describe("What kind of transaction the agent is about to perform"),
  transactionData: z
    .string()
    .optional()
    .describe("Hex-encoded calldata for the transaction, if available. Enables deeper simulation."),
  value: z
    .string()
    .optional()
    .describe("ETH value to send with the transaction, in wei"),
});

export const ScanContractSchema = z.object({
  contractAddress: z
    .string()
    .describe("The contract address to scan (0x-prefixed hex)"),
  chainId: z
    .number()
    .describe("Chain ID where the contract lives (1, 8453, or 84532)"),
});

export const CheckTokenSchema = z.object({
  tokenAddress: z
    .string()
    .describe("ERC-20 token contract address to check for honeypot behavior"),
  chainId: z
    .number()
    .describe("Chain ID where the token is deployed"),
});

export const SearchAuditFindingsSchema = z.object({
  keywords: z
    .string()
    .describe("Search terms for finding relevant audit issues (e.g. 'reentrancy', 'flash loan', 'price oracle')"),
  impact: z
    .enum(["critical", "high", "medium", "low"])
    .optional()
    .describe("Filter results by severity level"),
  limit: z
    .number()
    .optional()
    .default(10)
    .describe("Maximum number of findings to return"),
});
