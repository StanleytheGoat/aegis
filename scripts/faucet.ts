/**
 * Try multiple Base Sepolia faucets programmatically.
 * Falls back through several options until one works.
 */

import * as fs from "node:fs";
import * as path from "node:path";

const WALLET_ADDRESS = process.env.WALLET_ADDRESS || (() => {
  const envFile = fs.readFileSync(path.join(import.meta.dirname, "../.env"), "utf-8");
  const match = envFile.match(/WALLET_ADDRESS=(.+)/);
  return match?.[1] || "";
})();

console.log(`Requesting testnet ETH for: ${WALLET_ADDRESS}\n`);

interface FaucetResult {
  name: string;
  success: boolean;
  txHash?: string;
  error?: string;
}

async function tryFaucet(
  name: string,
  fn: () => Promise<{ txHash?: string }>
): Promise<FaucetResult> {
  try {
    console.log(`Trying ${name}...`);
    const result = await fn();
    console.log(`  ✓ ${name}: Success! TX: ${result.txHash || "pending"}`);
    return { name, success: true, txHash: result.txHash };
  } catch (e: any) {
    const error = e.message?.slice(0, 200) || "Unknown error";
    console.log(`  ✗ ${name}: ${error}`);
    return { name, success: false, error };
  }
}

// Faucet 1: Ethereum Sepolia PoW faucet (no auth)
async function sepoliaPoWFaucet() {
  const res = await fetch("https://sepolia-faucet.pk910.de/api/getFaucetStatus");
  const data = await res.json();
  // This is a PoW faucet — we'd need to mine, skip for now
  throw new Error("PoW faucet requires mining, skipping");
}

// Faucet 2: Try the Superchain faucet API
async function superchainFaucet() {
  const res = await fetch("https://app.optimism.io/faucet/api/drip", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chainId: 84532,
      address: WALLET_ADDRESS,
    }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`);
  }
  const data = await res.json();
  return { txHash: data.txHash || data.hash };
}

// Faucet 3: Try Bware Labs faucet
async function bwareFaucet() {
  const res = await fetch("https://bwarelabs.com/api/faucet", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chain: "base",
      network: "sepolia",
      address: WALLET_ADDRESS,
    }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`);
  }
  const data = await res.json();
  return { txHash: data.txHash || data.hash };
}

// Faucet 4: Try thirdweb faucet
async function thirdwebFaucet() {
  const res = await fetch("https://thirdweb.com/api/testnet-faucet/claim", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chainId: 84532,
      toAddress: WALLET_ADDRESS,
    }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`);
  }
  const data = await res.json();
  return { txHash: data.transactionHash || data.txHash };
}

// Faucet 5: Try LearnWeb3 faucet
async function learnweb3Faucet() {
  const res = await fetch("https://learnweb3.io/api/faucets/base_sepolia", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      walletAddress: WALLET_ADDRESS,
    }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`);
  }
  const data = await res.json();
  return { txHash: data.txHash || data.ok };
}

async function checkBalance() {
  const res = await fetch("https://sepolia.base.org", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      method: "eth_getBalance",
      params: [WALLET_ADDRESS, "latest"],
      id: 1,
    }),
  });
  const data = await res.json();
  const balanceWei = BigInt(data.result || "0x0");
  const balanceEth = Number(balanceWei) / 1e18;
  return balanceEth;
}

async function main() {
  // Check starting balance
  const startBalance = await checkBalance();
  console.log(`Current Base Sepolia balance: ${startBalance} ETH\n`);

  if (startBalance > 0.001) {
    console.log("Already funded! Skipping faucets.");
    return;
  }

  const faucets = [
    { name: "Superchain Faucet", fn: superchainFaucet },
    { name: "Thirdweb Faucet", fn: thirdwebFaucet },
    { name: "Bware Labs Faucet", fn: bwareFaucet },
    { name: "LearnWeb3 Faucet", fn: learnweb3Faucet },
  ];

  for (const { name, fn } of faucets) {
    const result = await tryFaucet(name, fn);
    if (result.success) {
      // Wait a bit and check balance
      console.log("\nWaiting 10s for transaction to confirm...");
      await new Promise((r) => setTimeout(r, 10000));
      const balance = await checkBalance();
      console.log(`New balance: ${balance} ETH`);
      if (balance > 0) {
        console.log("\n✓ Successfully funded! Ready for deployment.");
        return;
      }
    }
  }

  console.log("\n---");
  console.log("No automated faucet worked. Manual options:");
  console.log(`1. Visit https://www.alchemy.com/faucets/base-sepolia`);
  console.log(`2. Visit https://faucets.chain.link/base-sepolia`);
  console.log(`3. Visit https://faucet.quicknode.com/base/sepolia`);
  console.log(`\nPaste this address: ${WALLET_ADDRESS}`);
}

main().catch(console.error);
