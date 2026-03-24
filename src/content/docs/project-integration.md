---
title: Project Integration
description: How to integrate Aegis into your product to protect users and AI agents.
---


How to integrate Aegis into your product to protect users and AI agents interacting with DeFi protocols.

## Overview

Aegis provides two integration paths:

1. **MCP Server** (off-chain) - Your AI agents connect via MCP to get risk assessments before executing transactions. Zero infrastructure required.

2. **Smart Contracts** (on-chain) - Deploy Aegis contracts to enforce safety checks at the protocol level. Two options:
   - **AegisGateway** - A standalone safety wrapper for any DeFi interaction
   - **AegisSafetyHook** - A Uniswap v4 hook that enforces safety attestations on every swap

---

## Path 1: MCP Server Integration

Best for: Products with AI agents that interact with DeFi protocols.

### Setup

```bash
npm install aegis-defi
```

### In your agent's configuration

```json
{
  "mcpServers": {
    "aegis": {
      "command": "npx",
      "args": ["aegis-defi"],
      "env": {
        "ETHERSCAN_API_KEY": "your_key",
        "ETH_RPC_URL": "https://your-rpc.com",
        "SOLODIT_API_KEY": "sk_your_key (optional, free at solodit.cyfrin.io)"
      }
    }
  }
}
```

### Programmatic usage (without MCP)

```typescript
import { scanContractSource, simulateTransaction, checkTokenSellability } from "aegis-defi";

// Scan a contract
const result = scanContractSource(contractSourceCode);
if (result.riskScore > 70) {
  console.log("BLOCKED:", result.summary);
}

// Simulate a transaction
const sim = await simulateTransaction({
  chainId: 1,
  from: "0x...",
  to: "0x...",
  data: "0x...",
  value: 0n,
});

// Check token safety
const tokenCheck = await checkTokenSellability(1, "0xTokenAddress", "0xHolderAddress");
```

---

## Path 2: AegisGateway (On-Chain)

Best for: Products that want protocol-level safety enforcement regardless of the agent framework.

### How it works

1. Agent calls Aegis MCP server to assess a transaction
2. If safe, Aegis server signs an attestation
3. Attestation is recorded on the AegisGateway contract
4. Agent calls `executeProtected()` which verifies the attestation and forwards the transaction
5. A small protocol fee (5 bps) is collected

### Deployed on Base Mainnet

- AegisGateway: [`0x62c64c063ddbcd438f924184c03d8dad45230fa3`](https://basescan.org/address/0x62c64c063ddbcd438f924184c03d8dad45230fa3#code)

Ownership transferred to Safe multisig. Source verified on Basescan.

To deploy your own instance:

```bash
npx tsx scripts/deploy-gateway.ts --network base --fee-recipient <your-safe-address>
```

### Contract interface

```solidity
// Record a safety attestation (called by Aegis server or relayer)
// Signature format: keccak256(abi.encodePacked(
//   attestationId, agent, target, selector, riskScore, chainId, contractAddress
// ))
// Signatures include chain ID + contract address to prevent cross-chain replay.
// ecrecover validates against address(0) to prevent forged attestations.
// EIP-2 s-value malleability check is enforced on all signature recovery.
function recordAttestation(
    bytes32 attestationId,
    address agent,
    address target,
    bytes4 selector,
    uint8 riskScore,
    bytes calldata signature
) external;

// Execute a protected transaction
function executeProtected(
    bytes32 attestationId,
    address target,
    bytes calldata data
) external payable;

// Check if a transaction would be allowed (view)
function wouldAllow(bytes32 attestationId) external view returns (
    bool allowed,
    uint8 riskScore,
    string memory reason
);

// Rescue ETH sent directly to the contract via receive()
function rescueStuckEth() external;
```

### Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `riskThreshold` | 70 | Block transactions with risk above this (0-100) |
| `feeBps` | 5 | Protocol fee in basis points (0.05%) |
| `minFee` | 0.0001 ETH | Minimum fee per transaction |

---

## Path 3: AegisSafetyHook (Uniswap v4)

Best for: Projects deploying Uniswap v4 pools that want built-in safety for AI agent swaps.

**Deployed on Base Mainnet:** [`0xaEE532d9707b056f4d0939b91D4031298F7340C0`](https://basescan.org/address/0xaEE532d9707b056f4d0939b91D4031298F7340C0#code)

### How it works

The hook runs `beforeSwap` on every trade in the pool. It:

1. Checks if either token is flagged as dangerous → blocks immediately
2. Looks for a valid safety attestation in `hookData`
3. Verifies the attestation was signed by the trusted Aegis attester
4. Checks the risk score is below the threshold
5. If all checks pass, the swap proceeds

### Deploying a pool with Aegis protection

```solidity
PoolKey memory key = PoolKey({
    currency0: Currency.wrap(token0),
    currency1: Currency.wrap(token1),
    fee: 3000,
    tickSpacing: 60,
    hooks: IHooks(aegisHookAddress)
});

poolManager.initialize(key, sqrtPriceX96);
```

### Swapping through a protected pool

```typescript
// 1. Get safety attestation from Aegis MCP server
// assess_risk now returns a signed attestation for ALLOW/WARN decisions
const attestation = await aegis.assessRisk({ ... });

// 2. Encode attestation for hookData
// Format: (attestationId, agent, riskScore, expiresAt, signature)
// Hook signature format: keccak256(abi.encodePacked(
//   attestationId, agent, riskScore, expiresAt, chainId, hookAddress
// ))
const hookData = ethers.AbiCoder.defaultAbiCoder().encode(
  ["bytes32", "address", "uint8", "uint256", "bytes"],
  [
    attestation.id,
    agentAddress,
    attestation.riskScore,
    attestation.expiresAt,
    attestation.signature  // includes chainId + hookAddress in signed message
  ]
);

// 3. Swap with hookData - the hook verifies the attestation signature
//    matches the data including chainId and hookAddress, preventing
//    cross-chain replay attacks
await router.swap(key, swapParams, hookData);
```

### Token flagging

The hook owner (immutable after deployment) or Aegis attester can flag tokens that are known to be malicious:

```solidity
// Flag a token - all swaps involving this token will be blocked
hook.flagToken(tokenAddress, 100, "Confirmed honeypot - 99% sell tax");

// Clear a flag
hook.clearToken(tokenAddress);
```

### Permissive mode

For pools that want monitoring without blocking:

```solidity
hook.setPermissiveMode(true);
// Swaps proceed even without attestations, but events are still emitted
```

---

## Security Model

Security practices follow Ethereum security best practices (informed by [ethskills](https://github.com/austintgriffith/ethskills)).

### Trust assumptions

- The **Aegis attester** is a trusted off-chain entity (the MCP server's signing key)
- Attestations expire after **5 minutes** to prevent stale approvals
- Each attestation can only be used **once** to prevent replay attacks
- **Gateway**: the attester can be rotated by the contract owner (zero-address validation enforced on `setAttester`). **Hook**: the attester is **immutable** after deployment.
- Signatures include **chain ID + contract address** to prevent cross-chain replay
- **ecrecover** validates against `address(0)` to prevent forged attestations
- **EIP-2 s-value malleability** check on all signature recovery
- **Gateway**: `withdrawFees` is protected by `nonReentrant`. `rescueStuckEth()` recovers ETH sent directly via `receive()`.
- **Hook**: owner is **immutable** after deployment. Emits events for all state changes: `RiskThresholdUpdated`, `PermissiveModeUpdated`, `AttestationRecorded`.

### What Aegis catches

| Threat | Detection Method |
|--------|-----------------|
| Honeypot tokens (can't sell) | Source pattern matching + simulation |
| High sell taxes | Source analysis |
| Fake ownership renounce | Pattern detection |
| Reentrancy vulnerabilities | Source + bytecode analysis |
| Flash loan attack vectors | Price oracle pattern detection |
| Blacklist mechanisms | Source analysis |
| Upgradeable proxy risks | Bytecode signature detection |
| Transaction reverts | Fork simulation |
| Gas griefing | Gas estimation + anomaly detection |

### What Aegis does NOT catch

- Novel zero-day exploits with no known pattern
- Social engineering attacks
- MEV/sandwich attacks (use private mempools for that)
- Governance attacks
- Oracle manipulation beyond simple patterns

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ETHERSCAN_API_KEY` | API key for fetching verified source code (Ethereum) | (none) |
| `BASESCAN_API_KEY` | API key for fetching verified source code (Base) | Falls back to `ETHERSCAN_API_KEY` |
| `SOLODIT_API_KEY` | Cross-references findings against 50K+ real audit results. Free key at solodit.cyfrin.io | (none, optional) |
| `ETH_RPC_URL` | Ethereum mainnet RPC endpoint | `https://eth.llamarpc.com` |
| `BASE_RPC` | Base mainnet RPC endpoint | `https://mainnet.base.org` |
| `BASE_SEPOLIA_RPC` | Base Sepolia RPC endpoint | `https://sepolia.base.org` |

---

## Example: Full Agent Flow

```
┌──────────┐      ┌──────────┐      ┌──────────────┐      ┌──────────┐
│  Agent   │─────►│  Aegis   │─────►│  Risk Engine  │      │  Chain   │
│          │      │  MCP     │      │  + Simulator   │      │          │
│  "swap   │      │  Server  │      │               │      │          │
│   WETH   │      │          │◄─────│  riskScore: 5 │      │          │
│   for    │      │          │      │  decision:    │      │          │
│   USDC"  │      │          │      │  ALLOW        │      │          │
│          │◄─────│ ✅ ALLOW │      └───────────────┘      │          │
│          │      └──────────┘                              │          │
│          │─────────────────────────────────────────────►  │          │
│          │              executeProtected(attestation)     │  ✅ Swap │
└──────────┘                                               └──────────┘
```

```
┌──────────┐      ┌──────────┐      ┌──────────────┐
│  Agent   │─────►│  Aegis   │─────►│  Risk Engine  │
│          │      │  MCP     │      │               │
│  "swap   │      │  Server  │◄─────│  riskScore:92 │
│   WETH   │      │          │      │  decision:    │
│   for    │◄─────│ ⛨ BLOCK │      │  BLOCK        │
│   SCAM"  │      └──────────┘      └───────────────┘
│          │
│  (does   │      Funds saved. Honeypot detected.
│   NOT    │
│   swap)  │
└──────────┘
```
