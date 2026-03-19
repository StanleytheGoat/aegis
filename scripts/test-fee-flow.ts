/**
 * Full fee flow test - using Hardhat-compiled EthReceiver.
 */
import { createWalletClient, createPublicClient, http, parseEther, keccak256, toBytes, encodePacked } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { baseSepolia } from "viem/chains";
import * as fs from "node:fs";
import * as path from "node:path";

const envPath = path.join(import.meta.dirname, "../.env");
if (fs.existsSync(envPath)) {
  for (const line of fs.readFileSync(envPath, "utf-8").split("\n")) {
    const m = line.match(/^([A-Z_]+)=(.+)/);
    if (m) process.env[m[1]] = m[2];
  }
}

const COLD_WALLET = "0x364cD2d592281b6eDE0Ef0A7a863892a04805206" as `0x${string}`;
const account = privateKeyToAccount(process.env.PRIVATE_KEY as `0x${string}`);
const pub = createPublicClient({ chain: baseSepolia, transport: http("https://sepolia.base.org") });
const wallet = createWalletClient({ account, chain: baseSepolia, transport: http("https://sepolia.base.org") });

const deployment = JSON.parse(fs.readFileSync(path.join(import.meta.dirname, "../deployment.json"), "utf-8"));
const gw = deployment.contracts.AegisGateway.address as `0x${string}`;
const gwAbi = JSON.parse(fs.readFileSync(
  path.join(import.meta.dirname, "../artifacts/contracts/src/AegisGateway.sol/AegisGateway.json"), "utf-8"
)).abi;
const receiverArtifact = JSON.parse(fs.readFileSync(
  path.join(import.meta.dirname, "../artifacts/contracts/src/EthReceiver.sol/EthReceiver.json"), "utf-8"
));

async function sendAndWait(fn: (nonce: number) => Promise<`0x${string}`>) {
  const nonce = await pub.getTransactionCount({ address: account.address });
  const hash = await fn(nonce);
  const receipt = await pub.waitForTransactionReceipt({ hash });
  // Wait for nonce propagation
  await new Promise(r => setTimeout(r, 2000));
  return receipt;
}

async function main() {
  console.log("=== Full Fee Flow Test ===\n");

  const coldBefore = await pub.getBalance({ address: COLD_WALLET });
  console.log(`Cold wallet before: ${Number(coldBefore) / 1e18} ETH`);

  // 1. Deploy EthReceiver
  console.log("\n1. Deploying EthReceiver...");
  const r1 = await sendAndWait(nonce => wallet.deployContract({
    abi: receiverArtifact.abi,
    bytecode: receiverArtifact.bytecode as `0x${string}`,
    nonce,
  }));
  const receiver = r1.contractAddress! as `0x${string}`;
  console.log(`   ✓ EthReceiver: ${receiver}`);

  // Verify it accepts ETH
  const testSend = await sendAndWait(nonce => wallet.sendTransaction({
    to: receiver, value: parseEther("0.001"), nonce,
  }));
  console.log(`   ✓ Test ETH send: ${testSend.status}`);

  // 2. Record attestation
  console.log("\n2. Recording attestation...");
  const attId = keccak256(toBytes(`fee-v3-${Date.now()}`));
  // Use fallback selector - the EthReceiver has fallback() payable
  const sel = "0xdeadbeef" as `0x${string}`; // arbitrary selector → hits fallback
  const msgHash = keccak256(encodePacked(
    ["bytes32", "address", "address", "bytes4", "uint8"],
    [attId, account.address, receiver, sel, 5]
  ));
  const sig = await account.signMessage({ message: { raw: toBytes(msgHash) } });

  await sendAndWait(nonce => wallet.writeContract({
    address: gw, abi: gwAbi,
    functionName: "recordAttestation",
    args: [attId, account.address, receiver, sel, 5, sig],
    nonce,
  }));
  console.log(`   ✓ Attestation recorded`);

  // 3. executeProtected with 0.01 ETH
  console.log("\n3. Executing protected tx (0.01 ETH)...");
  // calldata starts with our selector 0xdeadbeef
  const calldata = "0xdeadbeef" as `0x${string}`;
  const r3 = await sendAndWait(nonce => wallet.writeContract({
    address: gw, abi: gwAbi,
    functionName: "executeProtected",
    args: [attId, receiver, calldata],
    value: parseEther("0.01"),
    nonce,
  }));
  console.log(`   ✓ executeProtected: ${r3.status}`);

  const accFees = await pub.readContract({ address: gw, abi: gwAbi, functionName: "accumulatedFees" }) as bigint;
  console.log(`   accumulatedFees: ${Number(accFees) / 1e18} ETH`);

  if (accFees === 0n) {
    console.log("   ✗ No fees. Aborting.");
    return;
  }

  // 4. Withdraw fees
  console.log("\n4. Withdrawing fees to cold wallet...");
  await sendAndWait(nonce => wallet.writeContract({
    address: gw, abi: gwAbi, functionName: "withdrawFees", nonce,
  }));

  // 5. Verify
  const coldAfter = await pub.getBalance({ address: COLD_WALLET });
  const increase = coldAfter - coldBefore;
  console.log(`\n=== Results ===`);
  console.log(`Cold wallet before: ${Number(coldBefore) / 1e18} ETH`);
  console.log(`Cold wallet after:  ${Number(coldAfter) / 1e18} ETH`);
  console.log(`Fee collected:      ${Number(increase) / 1e18} ETH`);

  if (increase > 0n) {
    console.log(`\n✓✓✓ SUCCESS: Fees landed in cold wallet ✓✓✓`);
  } else {
    console.log(`\n✗ Fees did not reach cold wallet`);
  }
  console.log(`\nVerify: https://sepolia.basescan.org/address/${COLD_WALLET}`);
}

main().catch(e => { console.error("Failed:", e.message); process.exit(1); });
