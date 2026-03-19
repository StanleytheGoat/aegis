/**
 * On-chain integration test for Aegis on Base Sepolia.
 *
 * Tests the full flow:
 * 1. Record a safety attestation on AegisGateway
 * 2. Verify it with wouldAllow()
 * 3. Scan the MockHoneypot contract with the risk engine
 * 4. Verify the risk engine would block the honeypot
 *
 * Usage: npx tsx scripts/onchain-test.ts
 */

import { createWalletClient, createPublicClient, http, keccak256, toBytes, encodePacked } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { baseSepolia } from "viem/chains";
import * as fs from "node:fs";
import * as path from "node:path";
import { scanContractSource } from "../src/risk-engine/scanner.js";

// Load .env
const envPath = path.join(import.meta.dirname, "../.env");
if (fs.existsSync(envPath)) {
  const envContent = fs.readFileSync(envPath, "utf-8");
  for (const line of envContent.split("\n")) {
    const match = line.match(/^([A-Z_]+)=(.+)/);
    if (match) process.env[match[1]] = match[2];
  }
}

// Load deployment info
const deploymentPath = path.join(import.meta.dirname, "../deployment.json");
if (!fs.existsSync(deploymentPath)) {
  console.error("No deployment.json found. Run: npx tsx scripts/deploy.ts first");
  process.exit(1);
}
const deployment = JSON.parse(fs.readFileSync(deploymentPath, "utf-8"));

// Load contract ABIs
function loadAbi(name: string) {
  const artifactPath = path.join(import.meta.dirname, `../artifacts/contracts/src/${name}.sol/${name}.json`);
  return JSON.parse(fs.readFileSync(artifactPath, "utf-8")).abi;
}

const PRIVATE_KEY = process.env.PRIVATE_KEY as `0x${string}`;
const account = privateKeyToAccount(PRIVATE_KEY);

const publicClient = createPublicClient({
  chain: baseSepolia,
  transport: http(process.env.BASE_SEPOLIA_RPC || "https://sepolia.base.org"),
});

const walletClient = createWalletClient({
  account,
  chain: baseSepolia,
  transport: http(process.env.BASE_SEPOLIA_RPC || "https://sepolia.base.org"),
});

const gatewayAbi = loadAbi("AegisGateway");
const honeypotAbi = loadAbi("MockHoneypot");
const gatewayAddress = deployment.contracts.AegisGateway.address as `0x${string}`;
const honeypotAddress = deployment.contracts.MockHoneypot.address as `0x${string}`;

async function test(name: string, fn: () => Promise<void>) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
  } catch (e: any) {
    console.log(`  ✗ ${name}: ${e.message}`);
  }
}

async function main() {
  console.log("=== Aegis On-Chain Integration Tests (Base Sepolia) ===\n");
  console.log(`Gateway:   ${gatewayAddress}`);
  console.log(`Honeypot:  ${honeypotAddress}`);
  console.log(`Tester:    ${account.address}\n`);

  const balance = await publicClient.getBalance({ address: account.address });
  console.log(`Balance:   ${Number(balance) / 1e18} ETH\n`);

  // --- Test 1: Read gateway state ---
  console.log("Gateway State:");
  await test("Read attester", async () => {
    const attester = await publicClient.readContract({
      address: gatewayAddress,
      abi: gatewayAbi,
      functionName: "attester",
    });
    console.log(`    Attester: ${attester}`);
    if (attester !== account.address) throw new Error("Unexpected attester");
  });

  await test("Read risk threshold", async () => {
    const threshold = await publicClient.readContract({
      address: gatewayAddress,
      abi: gatewayAbi,
      functionName: "riskThreshold",
    });
    console.log(`    Threshold: ${threshold}`);
    if (threshold !== 70) throw new Error(`Expected 70, got ${threshold}`);
  });

  await test("Read fee", async () => {
    const fee = await publicClient.readContract({
      address: gatewayAddress,
      abi: gatewayAbi,
      functionName: "feeBps",
    });
    console.log(`    Fee: ${fee} bps`);
    if (fee !== 5n) throw new Error(`Expected 5, got ${fee}`);
  });

  // --- Test 2: Record a safety attestation ---
  console.log("\nAttestation Flow:");

  const attestationId = keccak256(toBytes(`aegis-test-${Date.now()}`));
  const riskScore = 15; // Low risk
  const selector = "0xa9059cbb" as `0x${string}`; // transfer selector
  console.log(`  Attestation ID: ${attestationId}`);

  await test("Sign attestation", async () => {
    // Create the message hash matching the contract's logic
    const messageHash = keccak256(
      encodePacked(
        ["bytes32", "address", "address", "bytes4", "uint8"],
        [attestationId, account.address, honeypotAddress, selector, riskScore]
      )
    );

    // Sign using viem's account
    const signature = await account.signMessage({
      message: { raw: toBytes(messageHash) },
    });

    // Record on-chain
    const txHash = await walletClient.writeContract({
      address: gatewayAddress,
      abi: gatewayAbi,
      functionName: "recordAttestation",
      args: [attestationId, account.address, honeypotAddress, selector, riskScore, signature],
    });

    const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
    console.log(`    TX: ${txHash}`);
    console.log(`    Status: ${receipt.status}`);
    console.log(`    Gas: ${receipt.gasUsed}`);
    if (receipt.status === "reverted") throw new Error("Transaction reverted");
  });

  // Wait for state to propagate on public RPC
  await new Promise((r) => setTimeout(r, 3000));

  await test("Read attestation directly from mapping", async () => {
    console.log(`    Looking up ID: ${attestationId}`);
    const att = await publicClient.readContract({
      address: gatewayAddress,
      abi: gatewayAbi,
      functionName: "attestations",
      args: [attestationId],
    }) as any;
    console.log(`    Agent: ${att[0]}`);
    console.log(`    Target: ${att[1]}`);
    console.log(`    Selector: ${att[2]}`);
    console.log(`    RiskScore: ${att[3]}`);
    console.log(`    Timestamp: ${att[4]}`);
    console.log(`    Used: ${att[5]}`);
  });

  await test("Verify attestation with wouldAllow()", async () => {
    const [allowed, score, reason] = await publicClient.readContract({
      address: gatewayAddress,
      abi: gatewayAbi,
      functionName: "wouldAllow",
      args: [attestationId],
    }) as [boolean, number, string];

    console.log(`    Allowed: ${allowed}, Score: ${score}, Reason: "${reason}"`);
    if (!allowed) throw new Error(`Expected allowed, got: ${reason}`);
  });

  // --- Test 3: Read honeypot state ---
  console.log("\nHoneypot Contract:");

  await test("Read fake owner (should be address(0))", async () => {
    const owner = await publicClient.readContract({
      address: honeypotAddress,
      abi: honeypotAbi,
      functionName: "owner",
    });
    console.log(`    owner(): ${owner}`);
    if (owner !== "0x0000000000000000000000000000000000000000") {
      throw new Error("Expected address(0)");
    }
  });

  await test("Read sell tax (should be 99%)", async () => {
    const sellTax = await publicClient.readContract({
      address: honeypotAddress,
      abi: honeypotAbi,
      functionName: "sellTaxBps",
    });
    console.log(`    sellTaxBps: ${sellTax} (${Number(sellTax) / 100}%)`);
    if (sellTax !== 9900n) throw new Error(`Expected 9900, got ${sellTax}`);
  });

  await test("Read token name", async () => {
    const name = await publicClient.readContract({
      address: honeypotAddress,
      abi: honeypotAbi,
      functionName: "name",
    });
    console.log(`    name: "${name}"`);
  });

  // --- Test 4: Risk engine scan on honeypot source ---
  console.log("\nRisk Engine vs Honeypot:");

  await test("Scan MockHoneypot source code", async () => {
    const source = fs.readFileSync(
      path.join(import.meta.dirname, "../contracts/src/MockHoneypot.sol"),
      "utf-8",
    );
    const result = scanContractSource(source);

    console.log(`    Risk Score: ${result.riskScore}/100`);
    console.log(`    Risk Level: ${result.riskLevel}`);
    console.log(`    Findings: ${result.findings.length}`);
    console.log(`    Recommendation: ${result.recommendation}`);

    if (result.riskScore < 80) throw new Error(`Expected high risk, got ${result.riskScore}`);
    if (result.recommendation !== "avoid") throw new Error("Expected AVOID recommendation");
  });

  // --- Test 5: High-risk attestation should be blocked ---
  console.log("\nHigh-Risk Blocking:");

  const highRiskId = keccak256(toBytes(`aegis-highrisk-${Date.now()}`));
  const highRiskScore = 85;

  await test("Record high-risk attestation (score=85)", async () => {
    const messageHash = keccak256(
      encodePacked(
        ["bytes32", "address", "address", "bytes4", "uint8"],
        [highRiskId, account.address, honeypotAddress, selector, highRiskScore]
      )
    );

    const signature = await account.signMessage({
      message: { raw: toBytes(messageHash) },
    });

    const txHash = await walletClient.writeContract({
      address: gatewayAddress,
      abi: gatewayAbi,
      functionName: "recordAttestation",
      args: [highRiskId, account.address, honeypotAddress, selector, highRiskScore, signature],
    });

    await publicClient.waitForTransactionReceipt({ hash: txHash });
    console.log(`    TX: ${txHash}`);
  });

  await test("wouldAllow() should return false for high-risk", async () => {
    const [allowed, score, reason] = await publicClient.readContract({
      address: gatewayAddress,
      abi: gatewayAbi,
      functionName: "wouldAllow",
      args: [highRiskId],
    }) as [boolean, number, string];

    console.log(`    Allowed: ${allowed}, Score: ${score}, Reason: "${reason}"`);
    if (allowed) throw new Error("Should NOT be allowed — risk too high");
  });

  console.log("\n=== All Tests Complete ===");
  console.log(`Explorer: https://sepolia.basescan.org/address/${gatewayAddress}`);
}

main().catch((e) => {
  console.error("\nTest suite failed:", e.message);
  process.exit(1);
});
