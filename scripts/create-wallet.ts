/**
 * Generate a new Ethereum wallet for Aegis deployment & testing.
 * Stores the private key in .env (which is .gitignored).
 */

import { Wallet } from "ethers";
import * as fs from "node:fs";
import * as path from "node:path";

const wallet = Wallet.createRandom();

console.log("=== Aegis Deployment Wallet ===");
console.log(`Address:     ${wallet.address}`);
console.log(`Private Key: ${wallet.privateKey}`);
console.log("");

// Write to .env
const envPath = path.join(import.meta.dirname, "../.env");
const envContent = `# Aegis Wallet — generated ${new Date().toISOString()}
# THIS FILE IS GITIGNORED. DO NOT SHARE OR COMMIT.
PRIVATE_KEY=${wallet.privateKey}
WALLET_ADDRESS=${wallet.address}

# RPC endpoints
ETH_RPC_URL=https://eth.llamarpc.com
BASE_RPC=https://mainnet.base.org
BASE_SEPOLIA_RPC=https://sepolia.base.org
`;

fs.writeFileSync(envPath, envContent);
console.log(`Private key saved to .env (gitignored)`);
console.log("");
console.log("Next: fund this address on Base Sepolia via a faucet.");
