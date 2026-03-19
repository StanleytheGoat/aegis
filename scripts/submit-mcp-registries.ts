/**
 * Submit Aegis to awesome-mcp-servers lists via GitHub PRs.
 */
const TOKEN = process.env.GITHUB_TOKEN || "";

const headers: Record<string, string> = {
  "Authorization": `token ${TOKEN}`,
  "Accept": "application/vnd.github.v3+json",
  "Content-Type": "application/json",
};

const ENTRY = "- [aegis-defi](https://github.com/StanleytheGoat/aegis) - Safety layer for autonomous DeFi agents. Scans contracts for exploit patterns, simulates transactions, blocks honeypots. `npx aegis-defi`";

async function submitPR(owner: string, repo: string) {
  console.log(`\n--- ${owner}/${repo} ---`);

  // 1. Fork
  const forkRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/forks`, {
    method: "POST",
    headers,
  });
  const fork = await forkRes.json();
  console.log("Forked:", fork.full_name || fork.message);

  // Wait for fork to be ready
  await new Promise(r => setTimeout(r, 3000));

  // 2. Get default branch
  const repoRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`, { headers });
  const repoData = await repoRes.json();
  const defaultBranch = repoData.default_branch || "main";

  // 3. Get README from fork
  const readmeRes = await fetch(
    `https://api.github.com/repos/StanleytheGoat/${repo}/contents/README.md?ref=${defaultBranch}`,
    { headers }
  );
  const readme = await readmeRes.json();

  if (!readme.content) {
    console.log("Could not read README:", readme.message);
    return;
  }

  const content = Buffer.from(readme.content, "base64").toString("utf-8");

  // 4. Find insertion point
  let newContent = content;
  if (content.includes("### Security")) {
    newContent = content.replace(/(### Security[^\n]*\n)/, "$1\n" + ENTRY + "\n");
  } else if (content.includes("## Security")) {
    newContent = content.replace(/(## Security[^\n]*\n)/, "$1\n" + ENTRY + "\n");
  } else if (content.includes("### Blockchain")) {
    newContent = content.replace(/(### Blockchain[^\n]*\n)/, "$1\n" + ENTRY + "\n");
  } else if (content.includes("### Finance")) {
    newContent = content.replace(/(### Finance[^\n]*\n)/, "$1\n" + ENTRY + "\n");
  } else {
    newContent = content.trimEnd() + "\n\n" + ENTRY + "\n";
  }

  if (newContent === content) {
    console.log("Could not find insertion point, appending");
    newContent = content.trimEnd() + "\n\n" + ENTRY + "\n";
  }

  // 5. Create branch
  const refRes = await fetch(
    `https://api.github.com/repos/StanleytheGoat/${repo}/git/ref/heads/${defaultBranch}`,
    { headers }
  );
  const ref = await refRes.json();

  const branchName = `add-aegis-${Date.now()}`;
  await fetch(`https://api.github.com/repos/StanleytheGoat/${repo}/git/refs`, {
    method: "POST",
    headers,
    body: JSON.stringify({ ref: `refs/heads/${branchName}`, sha: ref.object.sha }),
  });

  // 6. Update README on branch
  const updateRes = await fetch(
    `https://api.github.com/repos/StanleytheGoat/${repo}/contents/README.md`,
    {
      method: "PUT",
      headers,
      body: JSON.stringify({
        message: "Add aegis-defi MCP server",
        content: Buffer.from(newContent).toString("base64"),
        sha: readme.sha,
        branch: branchName,
      }),
    }
  );
  const update = await updateRes.json();
  console.log("File updated:", update.content?.path || update.message);

  // 7. Create PR
  const prRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/pulls`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      title: "Add aegis-defi - DeFi safety MCP server",
      head: `StanleytheGoat:${branchName}`,
      base: defaultBranch,
      body: [
        "Adds [aegis-defi](https://github.com/StanleytheGoat/aegis), an MCP server that protects AI agents from DeFi exploits.",
        "",
        "Scans contracts for 12 exploit patterns (honeypots, rug pulls, reentrancy), simulates transactions on forked chains, and enforces safety on-chain via verified smart contracts on Base.",
        "",
        "- **npm**: `npx aegis-defi`",
        "- **GitHub**: https://github.com/StanleytheGoat/aegis",
        "- **Website**: https://aegis-defi.netlify.app",
        "- **Contracts**: Deployed and verified on Base mainnet",
      ].join("\n"),
    }),
  });
  const pr = await prRes.json();
  console.log("PR:", pr.html_url || pr.message);
}

async function main() {
  await submitPR("punkpeye", "awesome-mcp-servers");
  await submitPR("wong2", "awesome-mcp-servers");
}

main().catch(e => console.error(e));
