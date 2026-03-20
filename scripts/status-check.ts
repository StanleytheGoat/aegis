/**
 * Aegis Status Check - run with: npx tsx scripts/status-check.ts
 *
 * Verifies all deployments, distributions, and docs are in sync.
 * Outputs a single dashboard view.
 */

import { createPublicClient, http, formatEther } from "viem";
import { base } from "viem/chains";
import * as fs from "fs";
import * as path from "path";

const BOLD = "\x1b[1m";
const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const DIM = "\x1b[2m";
const RESET = "\x1b[0m";

const GATEWAY = "0x62c64c063ddbcd438f924184c03d8dad45230fa3";
const HOOK = "0xaEE532d9707b056f4d0939b91D4031298F7340C0";
const SAFE = "0x3cfFEcfdBC7cE87067990b2863dfBBfD1cfD5952";
const DEPLOYER = "0x52A0eff814729B98cF75E43d195840CB77ADD941";

interface Check {
  name: string;
  status: "ok" | "warn" | "fail";
  detail: string;
}

const results: Check[] = [];

function ok(name: string, detail: string) { results.push({ name, status: "ok", detail }); }
function warn(name: string, detail: string) { results.push({ name, status: "warn", detail }); }
function fail(name: string, detail: string) { results.push({ name, status: "fail", detail }); }

async function checkOnChain() {
  const client = createPublicClient({ chain: base, transport: http("https://mainnet.base.org") });

  // Gateway
  const gwCode = await client.getCode({ address: GATEWAY as `0x${string}` });
  if (gwCode && gwCode !== "0x") ok("Gateway", `Live on Base (${GATEWAY.slice(0, 10)}...)`);
  else fail("Gateway", "No code at address");

  // Hook
  const hookCode = await client.getCode({ address: HOOK as `0x${string}` });
  if (hookCode && hookCode !== "0x") ok("Hook", `Live on Base (${HOOK.slice(0, 10)}...)`);
  else fail("Hook", "No code at address");

  // Safe balance
  const safeBal = await client.getBalance({ address: SAFE as `0x${string}` });
  ok("Safe Balance", `${formatEther(safeBal)} ETH`);

  // Deployer balance
  const deployBal = await client.getBalance({ address: DEPLOYER as `0x${string}` });
  ok("Deployer Balance", `${formatEther(deployBal)} ETH`);
}

async function checkNpm() {
  try {
    const res = await fetch("https://registry.npmjs.org/aegis-defi");
    const data = await res.json();
    const latest = data["dist-tags"]?.latest;
    ok("npm", `aegis-defi@${latest}`);
  } catch {
    fail("npm", "Could not reach registry");
  }
}

async function checkGitHub() {
  try {
    const res = await fetch("https://api.github.com/repos/StanleytheGoat/aegis");
    const data = await res.json();
    if (data.private) warn("GitHub", "Repo is PRIVATE");
    else ok("GitHub", `Public - ${data.stargazers_count} stars`);
  } catch {
    fail("GitHub", "Could not reach API");
  }
}

async function checkSite() {
  try {
    const res = await fetch("https://aegis-defi.netlify.app");
    if (res.ok) ok("Website", "aegis-defi.netlify.app is live");
    else fail("Website", `HTTP ${res.status}`);
  } catch {
    fail("Website", "Could not reach site");
  }
}

async function checkPRs() {
  const prs = [
    { name: "ethskills PR", url: "https://api.github.com/repos/austintgriffith/ethskills/pulls/128" },
    { name: "awesome-mcp PR", url: "https://api.github.com/repos/punkpeye/awesome-mcp-servers/pulls/3526" },
  ];
  for (const pr of prs) {
    try {
      const res = await fetch(pr.url);
      const data = await res.json();
      if (data.merged_at) ok(pr.name, "Merged");
      else if (data.state === "open") warn(pr.name, "Open - awaiting merge");
      else fail(pr.name, `Closed (not merged)`);
    } catch {
      warn(pr.name, "Could not check");
    }
  }
}

async function checkLocalSync() {
  const root = path.resolve(import.meta.dirname, "..");
  const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf-8"));
  ok("Local Version", pkg.version);

  // Check pattern count consistency
  const patterns = fs.readFileSync(path.join(root, "src/risk-engine/patterns.ts"), "utf-8");
  const patternCount = (patterns.match(/name:\s*"/g) || []).length;

  const filesToCheck = [
    "site/index.html",
    "site/llms.txt",
    "README.md",
    "docs/agent-integration.md",
  ];

  for (const f of filesToCheck) {
    const content = fs.readFileSync(path.join(root, f), "utf-8");
    if (content.includes(`${patternCount} exploit`)) {
      ok(f, `References ${patternCount} patterns`);
    } else if (content.includes("12 exploit")) {
      fail(f, `Still says 12 patterns (should be ${patternCount})`);
    } else {
      warn(f, `Pattern count not found`);
    }
  }

  // Check for secrets in tracked files
  const cp = await import("child_process");
  const gitFiles = cp.execSync("git ls-files", { cwd: root }).toString().split("\n");
  let leaks = 0;
  for (const f of gitFiles) {
    if (!f || f.includes("node_modules")) continue;
    try {
      const content = fs.readFileSync(path.join(root, f), "utf-8");
      if (/ghp_[a-zA-Z0-9]{36}/.test(content) || /npm_[a-zA-Z0-9]{30}/.test(content) || /sk-synth-[a-f0-9]{40}/.test(content)) {
        fail("SECRET LEAK", `${f} contains a token/key!`);
        leaks++;
      }
    } catch {}
  }
  if (leaks === 0) ok("Security", "No secrets in tracked files");
}

async function run() {
  console.log(`\n${BOLD}AEGIS STATUS CHECK${RESET}  ${DIM}${new Date().toISOString()}${RESET}\n`);

  await Promise.all([checkOnChain(), checkNpm(), checkGitHub(), checkSite(), checkPRs()]);
  checkLocalSync();

  // Print results
  let oks = 0, warns = 0, fails = 0;
  for (const r of results) {
    const icon = r.status === "ok" ? `${GREEN}OK${RESET}` : r.status === "warn" ? `${YELLOW}!!${RESET}` : `${RED}FAIL${RESET}`;
    console.log(`  ${icon}  ${BOLD}${r.name.padEnd(20)}${RESET} ${r.detail}`);
    if (r.status === "ok") oks++;
    else if (r.status === "warn") warns++;
    else fails++;
  }

  console.log(`\n  ${GREEN}${oks} ok${RESET}  ${warns > 0 ? YELLOW : DIM}${warns} warn${RESET}  ${fails > 0 ? RED : DIM}${fails} fail${RESET}\n`);

  // Write machine-readable status for Desktop
  const status = {
    timestamp: new Date().toISOString(),
    summary: fails > 0 ? "ISSUES" : warns > 0 ? "WARNINGS" : "ALL GOOD",
    checks: results,
    counts: { ok: oks, warn: warns, fail: fails },
  };
  const statusRoot = path.resolve(import.meta.dirname, "..");
  fs.writeFileSync(path.join(statusRoot, ".aegis-status.json"), JSON.stringify(status, null, 2));
}

run().catch(console.error);
