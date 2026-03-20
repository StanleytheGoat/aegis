---
name: aegis-contracts
description: Smart contract deployment and interaction skill for Aegis. Triggers on: deploy, gateway, hook, on-chain, contract, Solidity, Hardhat, Base mainnet, Basescan, CREATE2, Safe multisig, fee withdrawal.
---

# Aegis Contract Operations

## Deployment Checklist
1. Compile: npx hardhat compile
2. Fork test: FORK_URL=https://mainnet.base.org npx hardhat test
3. Deploy to mainnet
4. Verify on Basescan immediately
5. Transfer ownership to Safe multisig

## Key Addresses
- AegisGateway: 0x62c64c063ddbcd438f924184c03d8dad45230fa3
- AegisSafetyHook: 0xaEE532d9707b056f4d0939b91D4031298F7340C0
- Fee Recipient (Safe): 0x3cfFEcfdBC7cE87067990b2863dfBBfD1cfD5952
- Deployer: 0x52A0eff814729B98cF75E43d195840CB77ADD941
- Safe Singleton Factory: 0x13b0D85CcB8bf860b6b79AF3029fCA081AE9beF2

## Security Rules
- Fee recipient is IMMUTABLE (constructor arg, no setter)
- Always include chainId + contract address in signed messages
- Check ecrecover result != address(0)
- EIP-2 malleability: s-value <= secp256k1 half-order
- Use ReentrancyGuard on all ETH transfer functions
- Emit events for every state change

## CREATE2 Hook Deployment
Hook address must have correct permission bits in the last byte.
Use Safe Singleton Factory for deterministic deployment.
Salt must be mined to produce address with correct flag bits (0xC0 for beforeSwap + afterSwap).
