/**
 * Deploy AegisGateway to Base mainnet or Base Sepolia.
 *
 * Usage:
 *   npx tsx scripts/deploy-gateway.ts                    # Base Sepolia (default)
 *   npx tsx scripts/deploy-gateway.ts --network base     # Base mainnet
 *
 * The feeRecipient is set via FEE_RECIPIENT env var or --fee-recipient flag.
 * Use a Safe multisig address for production deployments to avoid
 * single-key risk on an immutable fee destination.
 */
import { createWalletClient, createPublicClient, http, type Chain } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base, baseSepolia } from "viem/chains";
import * as fs from "node:fs";
import * as path from "node:path";

// Load .env
const envPath = path.join(import.meta.dirname, "../.env");
if (fs.existsSync(envPath)) {
  for (const line of fs.readFileSync(envPath, "utf-8").split("\n")) {
    const m = line.match(/^([A-Z_]+)=(.+)/);
    if (m) process.env[m[1]] = m[2];
  }
}

// Parse CLI args
const args = process.argv.slice(2);
const networkFlag = args.includes("--network") ? args[args.indexOf("--network") + 1] : "baseSepolia";
const feeRecipientFlag = args.includes("--fee-recipient") ? args[args.indexOf("--fee-recipient") + 1] : undefined;

// Network config
const networks: Record<string, { chain: Chain; rpc: string; explorer: string }> = {
  baseSepolia: {
    chain: baseSepolia,
    rpc: process.env.BASE_SEPOLIA_RPC || "https://sepolia.base.org",
    explorer: "https://sepolia.basescan.org",
  },
  base: {
    chain: base,
    rpc: process.env.BASE_RPC || "https://mainnet.base.org",
    explorer: "https://basescan.org",
  },
};

const network = networks[networkFlag];
if (!network) {
  console.error(`Unknown network: ${networkFlag}. Use "baseSepolia" or "base".`);
  process.exit(1);
}

// Fee recipient - prefer flag > env > error
const feeRecipient = feeRecipientFlag || process.env.FEE_RECIPIENT;
if (!feeRecipient) {
  console.error("Error: No fee recipient specified.");
  console.error("Set FEE_RECIPIENT in .env or pass --fee-recipient <address>");
  console.error("");
  console.error("IMPORTANT: For production, use a Safe multisig (app.safe.global)");
  console.error("instead of a single EOA. The fee recipient is IMMUTABLE -");
  console.error("if you lose access to a single-key wallet, fees are lost forever.");
  process.exit(1);
}

const account = privateKeyToAccount(process.env.PRIVATE_KEY as `0x${string}`);
const publicClient = createPublicClient({ chain: network.chain, transport: http(network.rpc) });
const walletClient = createWalletClient({ account, chain: network.chain, transport: http(network.rpc) });

const artifact = JSON.parse(fs.readFileSync(
  path.join(import.meta.dirname, "../artifacts/contracts/src/AegisGateway.sol/AegisGateway.json"), "utf-8"
));

async function main() {
  const nonce = await publicClient.getTransactionCount({ address: account.address });
  const balance = await publicClient.getBalance({ address: account.address });

  console.log("=== AegisGateway Deployment ===\n");
  console.log(`Network:        ${networkFlag} (chainId: ${network.chain.id})`);
  console.log(`Deployer:       ${account.address}`);
  console.log(`Attester:       ${account.address} (same as deployer)`);
  console.log(`Fee Recipient:  ${feeRecipient}`);
  console.log(`Balance:        ${Number(balance) / 1e18} ETH`);
  console.log(`Nonce:          ${nonce}`);

  if (balance === 0n) {
    console.error("\nError: Deployer has no ETH. Send funds first.");
    process.exit(1);
  }

  // Warn if fee recipient looks like an EOA on mainnet
  if (networkFlag === "base") {
    const code = await publicClient.getCode({ address: feeRecipient as `0x${string}` });
    if (!code || code === "0x") {
      console.warn("\n⚠️  WARNING: Fee recipient appears to be an EOA (not a contract/multisig).");
      console.warn("   For production, consider using a Safe multisig to avoid single-key risk.");
      console.warn("   The fee recipient is IMMUTABLE and cannot be changed after deployment.\n");
    } else {
      console.log(`\n✅ Fee recipient is a contract (likely Safe multisig). Good.\n`);
    }
  }

  console.log("Deploying...");
  const hash = await walletClient.deployContract({
    abi: artifact.abi,
    bytecode: artifact.bytecode as `0x${string}`,
    args: [account.address, feeRecipient],
    nonce,
  });

  console.log(`TX: ${hash}`);
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  console.log(`\n✅ AegisGateway deployed at: ${receipt.contractAddress}`);
  console.log(`Status: ${receipt.status}`);
  console.log(`Gas used: ${receipt.gasUsed}`);

  // Save deployment info
  const deployment = {
    network: networkFlag,
    chainId: network.chain.id,
    deployer: account.address,
    deployedAt: new Date().toISOString(),
    contracts: {
      AegisGateway: {
        address: receipt.contractAddress,
        txHash: hash,
        blockNumber: Number(receipt.blockNumber),
        feeRecipient,
        attester: account.address,
      },
    },
    explorerBaseUrl: network.explorer,
  };

  const depPath = path.join(import.meta.dirname, "../deployment.json");
  fs.writeFileSync(depPath, JSON.stringify(deployment, null, 2));
  console.log("\ndeployment.json saved");
  console.log(`Explorer: ${network.explorer}/address/${receipt.contractAddress}`);

  // --- Step 2: Transfer ownership to Safe multisig ---
  if (feeRecipient !== account.address) {
    console.log(`\n--- Transferring ownership to Safe multisig: ${feeRecipient} ---`);
    const transferHash = await walletClient.writeContract({
      address: receipt.contractAddress!,
      abi: artifact.abi,
      functionName: "transferOwnership",
      args: [feeRecipient],
    });
    await publicClient.waitForTransactionReceipt({ hash: transferHash });
    console.log(`✅ Ownership transferred to ${feeRecipient}`);
    console.log(`   TX: ${transferHash}`);
  }

  // --- Step 3: Verify on Basescan ---
  console.log("\n--- Contract Verification ---");
  console.log("Run this command to verify on Basescan:");
  console.log(`\n  npx hardhat verify --network ${networkFlag} ${receipt.contractAddress} ${account.address} ${feeRecipient}\n`);
  console.log("Or with Foundry:");
  console.log(`  forge verify-contract ${receipt.contractAddress} AegisGateway --chain ${network.chain.id} --etherscan-api-key $BASESCAN_API_KEY --constructor-args $(cast abi-encode "constructor(address,address)" ${account.address} ${feeRecipient})`);
  console.log("\n⚠️  Deployment is NOT done until verification passes. Unverified contracts look like scams.");
}

main().catch(e => { console.error("Deploy failed:", e.message); process.exit(1); });
