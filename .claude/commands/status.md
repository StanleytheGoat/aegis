# /status - Aegis Status Dashboard

Run the Aegis status checker and display a dashboard view of all systems.

## Steps

1. Run the status checker:
```bash
cd /Users/agent/Desktop/crazy/aegis && npx tsx scripts/status-check.ts
```

2. Read the generated status file:
```bash
cat /Users/agent/Desktop/crazy/aegis/.aegis-status.json
```

3. Present a clean dashboard:

```
AEGIS STATUS DASHBOARD
<timestamp>

On-Chain:
  Gateway:    <status> (<address>)
  Hook:       <status> (<address>)
  Safe:       <balance> ETH
  Deployer:   <balance> ETH

Distribution:
  npm:        <version>
  GitHub:     <public/private> - <stars> stars
  Website:    <status>

PRs:
  ethskills:  <status>
  awesome-mcp: <status>

Local:
  Version:    <version>
  Patterns:   <count>
  Security:   <leak status>

Summary: <ok count> ok | <warn count> warn | <fail count> fail
```

4. If any checks FAIL, highlight them and suggest fixes
