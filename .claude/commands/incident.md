# /incident - Create Incident Report

Document a DeFi security incident and analyze how Aegis would have prevented it.

## Usage
/incident <description or URL>

## Steps

1. Research the incident thoroughly:
   - What happened? (attack vector, amount lost, affected protocol)
   - When did it happen?
   - How was it exploited? (specific vulnerability)
   - What was the root cause?

2. Map to Aegis patterns:
   - Which of our 22 exploit patterns would have caught this?
   - Would scan_contract detect the vulnerability?
   - Would simulate_transaction flag the malicious transaction?
   - Would the Hook have blocked it?

3. Generate incident report:

```
AEGIS INCIDENT REPORT
Date: <incident date>
Protocol: <name>
Amount Lost: <amount>
Chain: <chain>

ATTACK VECTOR:
<description>

AEGIS DETECTION:
- Pattern Match: <pattern name and number>
- Scan Result: <what scan_contract would return>
- Simulation: <what simulate_transaction would show>

PREVENTION:
<How Aegis would have prevented this>

ACTION ITEMS:
- [ ] Add/update pattern if needed
- [ ] Update case studies
- [ ] Create outreach for affected protocol
```

4. Save to /Users/agent/Desktop/crazy/aegis/incidents/<date>-<protocol>.md
5. If a new pattern is needed, flag it for addition to patterns.ts
