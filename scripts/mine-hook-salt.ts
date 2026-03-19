/**
 * Mine a CREATE2 salt for deploying AegisSafetyHook on Base mainnet.
 *
 * The hook address must have bits 7 (beforeSwap) and 6 (afterSwap) set
 * in the last 14 bits. This script finds a salt that produces such an address.
 *
 * No gas needed - pure computation.
 */
import { keccak256, concat, getAddress, toBytes, encodeAbiParameters, parseAbiParameters } from "viem";
import * as fs from "node:fs";
import * as path from "node:path";

// Base mainnet CREATE2 deployer
const CREATE2_DEPLOYER = "0x13b0D85CcB8bf860b6b79AF3029fCA081AE9beF2";
// Base mainnet PoolManager
const POOL_MANAGER = "0x498581ff718922c3f8e6a244956af099b2652b2b";

// Permission flags (from Hooks.sol)
const BEFORE_SWAP_FLAG = 1n << 7n;  // 0x80
const AFTER_SWAP_FLAG = 1n << 6n;   // 0x40
const FLAG_MASK = 0x3FFFn;          // Bottom 14 bits

const REQUIRED_FLAGS = BEFORE_SWAP_FLAG | AFTER_SWAP_FLAG; // 0xC0

// Vanity prefix: "ae" - short enough to find quickly with correct flag bits
// Full "ae615" would take ~17 billion iterations in JS; "ae" takes ~4M
const VANITY_PREFIX = "ae";

// Load the hook artifact for bytecode
const artifactPath = path.join(import.meta.dirname, "../artifacts/contracts/src/AegisSafetyHook.sol/AegisSafetyHook.json");

async function main() {
  if (!fs.existsSync(artifactPath)) {
    console.error("Compile first: npx hardhat compile");
    process.exit(1);
  }

  // Load .env for attester address
  const envPath = path.join(import.meta.dirname, "../.env");
  if (fs.existsSync(envPath)) {
    for (const line of fs.readFileSync(envPath, "utf-8").split("\n")) {
      const m = line.match(/^([A-Z_]+)=(.+)/);
      if (m) process.env[m[1]] = m[2];
    }
  }

  const attester = process.env.WALLET_ADDRESS || "0x52A0eff814729B98cF75E43d195840CB77ADD941";

  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf-8"));
  const bytecode = artifact.bytecode as `0x${string}`;

  // Encode constructor args: (IPoolManager _poolManager, address _attester)
  const constructorArgs = encodeAbiParameters(
    parseAbiParameters("address, address"),
    [POOL_MANAGER as `0x${string}`, attester as `0x${string}`]
  );

  // Creation code = bytecode + constructor args
  const creationCode = concat([bytecode, constructorArgs]);
  const creationCodeHash = keccak256(creationCode);

  console.log("=== Aegis Hook Salt Mining ===\n");
  console.log(`CREATE2 Deployer: ${CREATE2_DEPLOYER}`);
  console.log(`PoolManager:      ${POOL_MANAGER}`);
  console.log(`Attester:         ${attester}`);
  console.log(`Required flags:   0x${REQUIRED_FLAGS.toString(16)} (beforeSwap | afterSwap)`);
  console.log(`Creation code hash: ${creationCodeHash}`);
  console.log(`\nMining salt (this may take a moment)...\n`);

  const MAX_ITERATIONS = 50_000_000;
  const deployerBytes = toBytes(CREATE2_DEPLOYER as `0x${string}`);

  let fallbackSalt: string | undefined;
  let fallbackAddr: string | undefined;

  for (let i = 0; i < MAX_ITERATIONS; i++) {
    // Convert i to a bytes32 salt
    const saltHex = `0x${i.toString(16).padStart(64, "0")}` as `0x${string}`;
    const saltBytes = toBytes(saltHex);

    // CREATE2 address = keccak256(0xff ++ deployer ++ salt ++ keccak256(creationCode))[12:]
    const data = concat([
      toBytes("0xff"),
      deployerBytes,
      saltBytes,
      toBytes(creationCodeHash),
    ]);

    const hash = keccak256(data);
    // Address is last 20 bytes
    const addr = getAddress(`0x${hash.slice(26)}`);

    // Check if bottom 14 bits match our required flags
    const addrNum = BigInt(addr);
    const addrFlags = addrNum & FLAG_MASK;

    // Check permission bits AND vanity prefix
    const addrLower = addr.toLowerCase();
    const hasCorrectFlags = (addrFlags & REQUIRED_FLAGS) === REQUIRED_FLAGS && (addrFlags & ~REQUIRED_FLAGS) === 0n;
    const hasVanityPrefix = addrLower.startsWith(`0x${VANITY_PREFIX}`);

    if (hasCorrectFlags && hasVanityPrefix) {
      console.log(`Found vanity salt after ${i + 1} iterations!`);
      console.log(`Salt:    ${saltHex}`);
      console.log(`Address: ${addr}`);
      console.log(`Flags:   0x${addrFlags.toString(16)}`);

      // Save to file
      const result = {
        salt: saltHex,
        hookAddress: addr,
        flags: `0x${addrFlags.toString(16)}`,
        deployer: CREATE2_DEPLOYER,
        poolManager: POOL_MANAGER,
        attester,
        network: "base-mainnet",
        chainId: 8453,
      };

      const outPath = path.join(import.meta.dirname, "../hook-deployment.json");
      fs.writeFileSync(outPath, JSON.stringify(result, null, 2));
      console.log(`\nSaved to hook-deployment.json`);
      return;
    }

    // Also save any non-vanity match as fallback
    if (hasCorrectFlags && !hasVanityPrefix && i < 100) {
      // Save first valid non-vanity as fallback
      if (!fallbackSalt) {
        fallbackSalt = saltHex;
        fallbackAddr = addr;
        console.log(`  (fallback found: ${addr})`);
      }
    }

    if (i > 0 && i % 500_000 === 0) {
      console.log(`  ...checked ${i.toLocaleString()} salts`);
    }
  }

  if (fallbackSalt && fallbackAddr) {
    console.log(`\nVanity prefix "${VANITY_PREFIX}" not found in ${MAX_ITERATIONS.toLocaleString()} iterations.`);
    console.log(`Using fallback address instead:\n`);
    console.log(`Salt:    ${fallbackSalt}`);
    console.log(`Address: ${fallbackAddr}`);

    const result = {
      salt: fallbackSalt,
      hookAddress: fallbackAddr,
      flags: "0xc0",
      deployer: CREATE2_DEPLOYER,
      poolManager: POOL_MANAGER,
      attester,
      network: "base-mainnet",
      chainId: 8453,
    };
    const outPath = path.join(import.meta.dirname, "../hook-deployment.json");
    fs.writeFileSync(outPath, JSON.stringify(result, null, 2));
    console.log(`Saved to hook-deployment.json`);
    return;
  }

  console.error(`\nFailed to find valid salt in ${MAX_ITERATIONS.toLocaleString()} iterations.`);
  process.exit(1);
}

main().catch(e => { console.error("Mining failed:", e.message); process.exit(1); });
