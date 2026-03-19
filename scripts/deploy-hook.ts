/**
 * Deploy AegisSafetyHook to Base mainnet using CREATE2.
 * Uses the pre-mined salt from hook-deployment.json.
 *
 * The hook will be deployed at an address with the correct permission bits
 * (beforeSwap=bit7, afterSwap=bit6) set.
 */
import { createWalletClient, createPublicClient, http, concat, encodeAbiParameters, parseAbiParameters } from "viem";
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

// Parse args: --network base or --network baseSepolia
const network = process.argv.includes("--network")
  ? process.argv[process.argv.indexOf("--network") + 1]
  : "baseSepolia";

const isMainnet = network === "base";
const chain = isMainnet ? base : baseSepolia;
const rpcUrl = isMainnet
  ? (process.env.BASE_RPC || "https://mainnet.base.org")
  : (process.env.BASE_SEPOLIA_RPC || "https://sepolia.base.org");

// Arachnid's deterministic CREATE2 deployer (per Uniswap v4 docs)
const CREATE2_DEPLOYER = "0x4e59b44847b379578588920cA78FbF26c0B4956C" as `0x${string}`;

// Load hook deployment config
const hookConfigPath = path.join(import.meta.dirname, "../hook-deployment.json");
if (!fs.existsSync(hookConfigPath)) {
  console.error("Run mine-hook-salt.ts first");
  process.exit(1);
}
const hookConfig = JSON.parse(fs.readFileSync(hookConfigPath, "utf-8"));

const account = privateKeyToAccount(process.env.PRIVATE_KEY as `0x${string}`);
const publicClient = createPublicClient({ chain, transport: http(rpcUrl) });
const walletClient = createWalletClient({ account, chain, transport: http(rpcUrl) });

// Load artifact
const artifact = JSON.parse(fs.readFileSync(
  path.join(import.meta.dirname, "../artifacts/contracts/src/AegisSafetyHook.sol/AegisSafetyHook.json"), "utf-8"
));

async function main() {
  console.log(`=== Deploy AegisSafetyHook via CREATE2 ===`);
  console.log(`Network:    ${network} (${chain.id})`);
  console.log(`Deployer:   ${account.address}`);
  console.log(`CREATE2:    ${CREATE2_DEPLOYER}`);
  console.log(`Salt:       ${hookConfig.salt}`);
  console.log(`Expected:   ${hookConfig.hookAddress}\n`);

  const balance = await publicClient.getBalance({ address: account.address });
  console.log(`Balance:    ${Number(balance) / 1e18} ETH\n`);

  if (balance < 100000n) {
    console.error("Insufficient balance for deployment");
    process.exit(1);
  }

  // Check if already deployed
  const existingCode = await publicClient.getCode({ address: hookConfig.hookAddress as `0x${string}` });
  if (existingCode && existingCode !== "0x") {
    console.log("Hook already deployed at this address!");
    process.exit(0);
  }

  // Build creation code with constructor args
  const constructorArgs = encodeAbiParameters(
    parseAbiParameters("address, address"),
    [hookConfig.poolManager as `0x${string}`, hookConfig.attester as `0x${string}`]
  );
  const creationCode = concat([artifact.bytecode as `0x${string}`, constructorArgs]);

  // CREATE2 deployer expects: salt (32 bytes) + creationCode
  const deployData = concat([hookConfig.salt as `0x${string}`, creationCode]);

  console.log("Deploying via CREATE2...");
  const nonce = await publicClient.getTransactionCount({ address: account.address });
  const txHash = await walletClient.sendTransaction({
    to: CREATE2_DEPLOYER,
    data: deployData,
    nonce,
    gas: 5_000_000n,
  });

  console.log(`TX: ${txHash}`);
  const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
  console.log(`Status: ${receipt.status}`);
  console.log(`Gas used: ${receipt.gasUsed}`);

  // Verify deployment
  const deployedCode = await publicClient.getCode({ address: hookConfig.hookAddress as `0x${string}` });
  if (deployedCode && deployedCode !== "0x") {
    console.log(`\n✓ Hook deployed at: ${hookConfig.hookAddress}`);

    const explorerBase = isMainnet ? "https://basescan.org" : "https://sepolia.basescan.org";
    console.log(`Explorer: ${explorerBase}/address/${hookConfig.hookAddress}`);

    // Update hook-deployment.json
    hookConfig.deployed = true;
    hookConfig.deployTxHash = txHash;
    hookConfig.deployBlock = Number(receipt.blockNumber);
    fs.writeFileSync(hookConfigPath, JSON.stringify(hookConfig, null, 2));
  } else {
    console.error("\n✗ Deployment failed - no code at expected address");
    process.exit(1);
  }
}

main().catch(e => { console.error("Deploy failed:", e.message); process.exit(1); });
