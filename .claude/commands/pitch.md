# /pitch - Generate Outreach Pitch

Research a target company and generate a tailored pitch for Aegis integration.

## Usage
/pitch <company name or URL>

## Steps

1. Research the target company:
   - What protocols/products do they run?
   - Do they use Uniswap v4 hooks?
   - Have they had any security incidents?
   - What is their TVL / volume?
   - Who are the key people to contact?

2. Identify how Aegis helps them specifically:
   - Which of our 165 exploit patterns are relevant to their protocol type?
   - Would they benefit more from the MCP server (agent safety) or the Hook (pool safety)?
   - What case studies are relevant? (Aave $50M, Cork $11M, Moonwell $1.78M)
   - Mention Solodit integration: findings are cross-referenced against 50K+ real audit results from top security firms

3. Generate a pitch in this format:

```
AEGIS PITCH: <Company Name>
Generated: <date>

WHY THEY NEED AEGIS:
<2-3 sentences about their specific risk exposure>

RELEVANT CASE STUDY:
<Most relevant incident that Aegis would have prevented>

INTEGRATION PATH:
<Specific technical steps for their stack>

REVENUE IMPACT:
<Estimate based on their volume and our 5 bps fee>

CONTACT APPROACH:
<Suggested outreach channel and message>
```

4. Save the pitch to /Users/agent/Desktop/crazy/aegis/outreach/<company-name>.md

## Priority Targets (Ranked)
1. Flaunch - 3000+ v4 pools, AI agent, open SDK
2. Virtuals Protocol - 2200+ AI agents, Base native
3. Coinbase Agentic Wallets - default agent infra
4. Bunni DEX - 59% of v4 hook volume, had $2.3M exploit
5. Olas/Autonolas - 700K+ agent txns/month
6. Doppler - 90% of Base token launches
