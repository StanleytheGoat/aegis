---
name: aegis-monitoring
description: Protocol monitoring and incident response skill for Aegis. Triggers on: monitor, alert, incident, exploit, hack, vulnerability report, security alert, fee balance, revenue, status check.
---

# Aegis Monitoring Operations

## Status Check
Checks: on-chain contracts, npm version, GitHub visibility, website, PR status, pattern count consistency, secret leak scanning.

## Incident Response Procedure
1. DETECT - Monitor catches anomaly via pattern matching or simulation
2. CLASSIFY - Which pattern? What severity? Known or novel?
3. RESPOND - Block via attestation refusal, alert team
4. REPORT - Document as case study with: what happened, how Aegis catches it, pattern reference
5. IMPROVE - Add new pattern if novel exploit type

## Fee Monitoring
- Check Gateway balance periodically
- withdrawFees() sends accumulated fees to Safe multisig
- Fee rate: 5 bps (0.05%) per transaction

## Distribution Channels to Monitor
- npm: aegis-defi (check for version currency)
- GitHub: StanleytheGoat/aegis (check visibility, stars)
- Website: aegis-defi.netlify.app (check uptime)
- PRs: ethskills #128, awesome-mcp-servers #3526
