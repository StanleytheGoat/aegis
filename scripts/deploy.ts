/**
 * Deploy AegisGateway and MockHoneypot to Base Sepolia.
 *
 * Usage: PRIVATE_KEY=0x... npx tsx scripts/deploy.ts
 * Or: source .env && npx tsx scripts/deploy.ts
 */

import { createWalletClient, createPublicClient, http, parseEther } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { baseSepolia } from "viem/chains";
import * as fs from "node:fs";
import * as path from "node:path";

// Load .env manually
const envPath = path.join(import.meta.dirname, "../.env");
if (fs.existsSync(envPath)) {
  const envContent = fs.readFileSync(envPath, "utf-8");
  for (const line of envContent.split("\n")) {
    const match = line.match(/^([A-Z_]+)=(.+)/);
    if (match) process.env[match[1]] = match[2];
  }
}

const PRIVATE_KEY = process.env.PRIVATE_KEY;
if (!PRIVATE_KEY) {
  console.error("Set PRIVATE_KEY in .env or environment");
  process.exit(1);
}

// We need the compiled contract artifacts from Hardhat
const ARTIFACTS_DIR = path.join(import.meta.dirname, "../artifacts/contracts/src");

function loadArtifact(name: string) {
  const artifactPath = path.join(ARTIFACTS_DIR, `${name}.sol`, `${name}.json`);
  if (!fs.existsSync(artifactPath)) {
    console.error(`Artifact not found: ${artifactPath}`);
    console.error("Run: npx hardhat compile");
    process.exit(1);
  }
  return JSON.parse(fs.readFileSync(artifactPath, "utf-8"));
}

async function main() {
  const account = privateKeyToAccount(PRIVATE_KEY as `0x${string}`);

  const publicClient = createPublicClient({
    chain: baseSepolia,
    transport: http(process.env.BASE_SEPOLIA_RPC || "https://sepolia.base.org"),
  });

  const walletClient = createWalletClient({
    account,
    chain: baseSepolia,
    transport: http(process.env.BASE_SEPOLIA_RPC || "https://sepolia.base.org"),
  });

  console.log("=== Aegis Deployment to Base Sepolia ===");
  console.log(`Deployer: ${account.address}`);

  const balance = await publicClient.getBalance({ address: account.address });
  const balanceEth = Number(balance) / 1e18;
  console.log(`Balance:  ${balanceEth} ETH\n`);

  if (balanceEth < 0.001) {
    console.error("Insufficient balance. Need at least 0.001 ETH for deployment.");
    console.error("Fund this address via a faucet first.");
    process.exit(1);
  }

  // --- Deploy AegisGateway ---
  console.log("Deploying AegisGateway...");
  const gatewayArtifact = loadArtifact("AegisGateway");

  const gatewayHash = await walletClient.deployContract({
    abi: gatewayArtifact.abi,
    bytecode: gatewayArtifact.bytecode as `0x${string}`,
    args: [account.address, account.address], // attester = deployer, feeRecipient = deployer (testnet)
  });

  console.log(`  TX: ${gatewayHash}`);
  const gatewayReceipt = await publicClient.waitForTransactionReceipt({ hash: gatewayHash });
  const gatewayAddress = gatewayReceipt.contractAddress!;
  console.log(`  ✓ AegisGateway deployed at: ${gatewayAddress}`);
  console.log(`  Block: ${gatewayReceipt.blockNumber}`);
  console.log(`  Gas used: ${gatewayReceipt.gasUsed}\n`);

  // --- Deploy MockHoneypot ---
  console.log("Deploying MockHoneypot...");
  const honeypotArtifact = loadArtifact("MockHoneypot");

  const honeypotHash = await walletClient.deployContract({
    abi: honeypotArtifact.abi,
    bytecode: honeypotArtifact.bytecode as `0x${string}`,
    args: [],
  });

  console.log(`  TX: ${honeypotHash}`);
  const honeypotReceipt = await publicClient.waitForTransactionReceipt({ hash: honeypotHash });
  const honeypotAddress = honeypotReceipt.contractAddress!;
  console.log(`  ✓ MockHoneypot deployed at: ${honeypotAddress}`);
  console.log(`  Block: ${honeypotReceipt.blockNumber}`);
  console.log(`  Gas used: ${honeypotReceipt.gasUsed}\n`);

  // --- Save deployment info ---
  const deployment = {
    network: "base-sepolia",
    chainId: 84532,
    deployer: account.address,
    deployedAt: new Date().toISOString(),
    contracts: {
      AegisGateway: {
        address: gatewayAddress,
        txHash: gatewayHash,
        blockNumber: Number(gatewayReceipt.blockNumber),
      },
      MockHoneypot: {
        address: honeypotAddress,
        txHash: honeypotHash,
        blockNumber: Number(honeypotReceipt.blockNumber),
      },
    },
    explorerBaseUrl: "https://sepolia.basescan.org",
  };

  const deploymentPath = path.join(import.meta.dirname, "../deployment.json");
  fs.writeFileSync(deploymentPath, JSON.stringify(deployment, null, 2));
  console.log(`Deployment info saved to deployment.json`);

  console.log("\n=== Deployment Complete ===");
  console.log(`AegisGateway:  ${deployment.explorerBaseUrl}/address/${gatewayAddress}`);
  console.log(`MockHoneypot:  ${deployment.explorerBaseUrl}/address/${honeypotAddress}`);
}

main().catch((e) => {
  console.error("Deployment failed:", e.message);
  process.exit(1);
});
