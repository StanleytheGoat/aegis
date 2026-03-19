# Aegis Safety Skill for Paperclip

DeFi safety layer for [Paperclip](https://github.com/paperclipai/paperclip) companies. Protects AI agents from honeypots, rug pulls, and exploits before any on-chain transaction.

## Prerequisites

- A running [Paperclip](https://github.com/paperclipai/paperclip) instance
- Node.js 18+
- Agents configured with an MCP-capable adapter (Claude Code, OpenClaw, or any adapter supporting MCP servers)

## Installation

### 1. Add the MCP server to your agent's adapter config

In your agent configuration (e.g., `settings.json` or adapter config), add Aegis as an MCP server:

```json
{
  "mcpServers": {
    "aegis": {
      "command": "npx",
      "args": ["aegis-defi"]
    }
  }
}
```

For Claude Code agents, you can also run:

```bash
claude mcp add aegis npx aegis-defi
```

### 2. Install the skill

Copy the `SKILL.md` file into your agent's skills directory:

```bash
# For Claude Code agents
mkdir -p .claude/skills/aegis-defi-safety
cp paperclip/SKILL.md .claude/skills/aegis-defi-safety/SKILL.md
```

Or symlink it from the Aegis repo:

```bash
ln -s /path/to/aegis/paperclip .claude/skills/aegis-defi-safety
```

For non-Claude adapters, point the agent's `instructionsFilePath` to the `SKILL.md` or include the skill directory in your adapter's `--add-dir` argument.

### 3. (Optional) Deploy on-chain contracts

If you want on-chain enforcement in addition to MCP pre-flight checks:

```bash
# Deploy AegisGateway (5 bps fee, Safe multisig recipient)
# Deploy script transfers ownership to Safe after deployment
# Basescan verification is mandatory post-deploy
npx hardhat run scripts/deploy-gateway.js --network mainnet

# Deploy AegisSafetyHook (Uniswap v4 beforeSwap hook, immutable owner)
# Hook deployed via CREATE2 at vanity address
npx hardhat run scripts/deploy-hook.js --network mainnet
```

See the main [Aegis README](../README.md) for full deployment instructions.

## How It Works

Once installed, any agent with the Aegis skill will automatically run safety checks before on-chain transactions:

1. **check_token** -- flags rug-pull signals (locked liquidity, honeypot patterns, holder concentration)
2. **scan_contract** -- deep-scans bytecode for exploit patterns and proxy risks
3. **simulate_transaction** -- dry-runs the exact calldata and reports balance deltas, reverts, and hidden side-effects
4. **assess_risk** -- produces a composite risk score: `low`, `medium`, `high`, or `critical`. Returns a signed attestation for ALLOW/WARN decisions (falls back to MCP-only mode if no attester key configured)

If the risk score is `high` or `critical`, the agent halts, marks the Paperclip task as `blocked`, posts the Aegis report as a comment, and escalates through the chain of command.

## Governance Integration

Aegis is designed to complement Paperclip's built-in governance:

| Paperclip Feature | Aegis Complement |
|---|---|
| Budget enforcement | Prevents spend on malicious contracts (quality of spend) |
| Approval gates | High/critical risk scores trigger approval workflows |
| Audit trail | Scan results posted as task comments with run ID tracing |
| Atomic checkout | Agent owns both task checkout and safety pre-flight |

### Recommended approval rule

Configure your Paperclip company so that any task producing an Aegis risk score of `high` or `critical` requires human approval before the agent can proceed. This can be set up in your company's governance rules.

## Cost

- **MCP tools** (scan, simulate, check, assess): free
- **AegisGateway** (on-chain proxy): 5 basis points per transaction (Safe multisig recipient, nonReentrant withdrawal)
- **AegisSafetyHook** (Uniswap v4 hook): no additional fee (immutable owner, cross-chain replay protection)

## Troubleshooting

| Symptom | Fix |
|---|---|
| Agent skips safety checks | Verify `SKILL.md` is in the agent's skills directory and the MCP server is in adapter config |
| `aegis` MCP tools not found | Run `npx aegis-defi` manually to confirm the server starts. Check adapter logs for MCP connection errors |
| Agent proceeds on `high` risk | Review the skill file -- the decision procedure must not be overridden by other skills. Aegis should be the last gate before signing |
| Gateway transaction reverts | Confirm the AegisGateway contract is deployed on the target chain and the agent wallet has sufficient gas + the 5 bps fee |

## Further Reading

- [Aegis documentation](../docs/)
- [Paperclip documentation](https://github.com/paperclipai/paperclip/tree/master/docs)
- [Paperclip skill conventions](https://github.com/paperclipai/paperclip/tree/master/skills/paperclip)
