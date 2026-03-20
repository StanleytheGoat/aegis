/**
 * Attestation Signing Module
 *
 * Signs safety attestations that can be verified on-chain by the
 * AegisGateway and AegisSafetyHook contracts.
 *
 * Signatures include chain ID and contract address to prevent cross-chain replay.
 *
 * The attester private key is loaded from ATTESTER_PRIVATE_KEY env var.
 * This key must match the `attester` address set in the deployed contracts.
 *
 * SECURITY: The private key should ONLY be stored locally in .env.
 * Never commit it, never expose it via API, never log it.
 */

import { keccak256, encodePacked, type Address, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";

export interface AttestationInput {
  agent: Address;
  target: Address;
  selector: Hex;
  riskScore: number;
  chainId?: number;
  contractAddress?: Address;
}

export interface SignedAttestation {
  attestationId: Hex;
  agent: Address;
  target: Address;
  selector: Hex;
  riskScore: number;
  expiresAt: number;
  signature: Hex;
}

/**
 * Generate a unique attestation ID from the attestation parameters.
 */
export function generateAttestationId(
  agent: Address,
  target: Address,
  selector: Hex,
  riskScore: number,
  timestamp: number,
): Hex {
  return keccak256(
    encodePacked(
      ["address", "address", "bytes4", "uint8", "uint256"],
      [agent, target, selector as `0x${string}`, riskScore, BigInt(timestamp)],
    ),
  );
}

/**
 * Sign a safety attestation for the AegisGateway contract.
 *
 * The signed message matches what AegisGateway.recordAttestation() expects:
 * keccak256(abi.encodePacked(attestationId, agent, target, selector, riskScore, chainId, contractAddress))
 *
 * Includes chain ID and contract address to prevent cross-chain replay attacks.
 */
export async function signAttestation(input: AttestationInput): Promise<SignedAttestation> {
  const privateKey = process.env.ATTESTER_PRIVATE_KEY || process.env.PRIVATE_KEY;
  if (!privateKey) {
    throw new Error(
      "No attester key configured. Set ATTESTER_PRIVATE_KEY or PRIVATE_KEY in .env",
    );
  }

  const account = privateKeyToAccount(privateKey as Hex);
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + 300; // 5 minutes
  const chainId = input.chainId || 8453; // Default to Base mainnet
  const contractAddress = input.contractAddress || ("0x0000000000000000000000000000000000000000" as Address);

  const attestationId = generateAttestationId(
    input.agent,
    input.target,
    input.selector,
    input.riskScore,
    now,
  );

  // Sign for Gateway: (attestationId, agent, target, selector, riskScore, chainId, contractAddress)
  const gatewayMessageHash = keccak256(
    encodePacked(
      ["bytes32", "address", "address", "bytes4", "uint8", "uint256", "address"],
      [attestationId, input.agent, input.target, input.selector as `0x${string}`, input.riskScore, BigInt(chainId), contractAddress],
    ),
  );

  const signature = await account.signMessage({
    message: { raw: gatewayMessageHash },
  });

  return {
    attestationId,
    agent: input.agent,
    target: input.target,
    selector: input.selector,
    riskScore: input.riskScore,
    expiresAt,
    signature,
  };
}

/**
 * Sign an attestation specifically for the v4 hook's inline verification.
 * Hook expects: keccak256(abi.encodePacked(attestationId, agent, riskScore, expiresAt, chainId, hookAddress))
 *
 * Includes chain ID and hook address to prevent cross-chain replay attacks.
 */
export async function signHookAttestation(input: AttestationInput): Promise<SignedAttestation> {
  const privateKey = process.env.ATTESTER_PRIVATE_KEY || process.env.PRIVATE_KEY;
  if (!privateKey) {
    throw new Error(
      "No attester key configured. Set ATTESTER_PRIVATE_KEY or PRIVATE_KEY in .env",
    );
  }

  const account = privateKeyToAccount(privateKey as Hex);
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + 300;
  const chainId = input.chainId || 8453;
  const hookAddress = input.contractAddress || ("0x0000000000000000000000000000000000000000" as Address);

  const attestationId = generateAttestationId(
    input.agent,
    input.target,
    input.selector,
    input.riskScore,
    now,
  );

  // Sign for Hook: (attestationId, agent, riskScore, expiresAt, chainId, hookAddress)
  const hookMessageHash = keccak256(
    encodePacked(
      ["bytes32", "address", "uint8", "uint256", "uint256", "address"],
      [attestationId, input.agent, input.riskScore, BigInt(expiresAt), BigInt(chainId), hookAddress],
    ),
  );

  const signature = await account.signMessage({
    message: { raw: hookMessageHash },
  });

  return {
    attestationId,
    agent: input.agent,
    target: input.target,
    selector: input.selector,
    riskScore: input.riskScore,
    expiresAt,
    signature,
  };
}
