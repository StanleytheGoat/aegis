# /scan - Full Safety Scan

Run a complete Aegis safety analysis on a contract or token address.

## Usage
/scan <address>

## Steps

1. Use the `scan_contract` MCP tool to analyze the bytecode and source code for exploit patterns
2. Use the `check_token` MCP tool to evaluate token-specific risks (honeypot, hidden fees, transfer traps)
3. Use the `assess_risk` MCP tool for a comprehensive risk assessment combining all signals
4. Present results in this format:

```
AEGIS SAFETY SCAN
Target: <address>
Chain: Base (8453)

Risk Score: <score>/100
Decision: ALLOW | WARN | BLOCK

Patterns Matched:
- <pattern name>: <description>

Token Analysis:
- <token findings>

Recommendation:
<clear action recommendation>
```

5. If risk score >= 50, explicitly warn that this contract should NOT be interacted with
6. If risk score < 25, confirm it appears safe but note that no scan is 100% comprehensive
