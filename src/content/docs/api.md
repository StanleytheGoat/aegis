---
title: API Reference
description: HTTP API endpoints for the Aegis DeFi safety layer. No MCP required.
---

The Aegis API exposes the risk engine over HTTP. No MCP client needed - any HTTP client works.

**Base URL:** `https://aegis-defi.netlify.app`

All endpoints accept `POST` with a JSON body and return JSON responses.

## Rate Limiting

- 20 requests per minute per IP
- Returns `429` with `Retry-After` header when exceeded

## POST /api/scan

Scan a smart contract for exploit patterns.

### Request

```json
{
  "contractAddress": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
  "chainId": 1
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `contractAddress` | string | No* | Contract address (fetches source automatically) |
| `source` | string | No* | Solidity source code |
| `bytecode` | string | No* | Contract bytecode (hex) |
| `chainId` | number | No | Chain ID. Default: 1. Supported: 1, 8453, 84532 |

*At least one of `contractAddress`, `source`, or `bytecode` required.

### Response

```json
{
  "contractAddress": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
  "chainId": 1,
  "riskScore": 15,
  "classification": "safe",
  "findings": [],
  "recommendation": "No significant risks detected."
}
```

## POST /api/check-token

Check if a token is safe to trade (anti-honeypot).

### Request

```json
{
  "tokenAddress": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
  "chainId": 1
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tokenAddress` | string | Yes | Token contract address |
| `chainId` | number | No | Chain ID. Default: 1 |
| `holderAddress` | string | No | Address to check balance for |

### Response

```json
{
  "tokenAddress": "0x...",
  "chainId": 1,
  "sellability": {
    "canSell": true
  },
  "contractScan": {
    "riskScore": 15,
    "findings": []
  },
  "overallAssessment": "LIKELY_SAFE"
}
```

## POST /api/simulate

Simulate a transaction on a forked chain.

### Request

```json
{
  "chainId": 1,
  "from": "0xYourWallet",
  "to": "0xTargetContract",
  "data": "0xcalldata",
  "value": "0"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `chainId` | number | No | Chain ID. Default: 1 |
| `from` | string | Yes | Sender address |
| `to` | string | Yes | Target contract address |
| `data` | string | Yes | Transaction calldata (hex) |
| `value` | string | No | ETH value in wei. Default: "0" |

### Response

```json
{
  "chainId": 1,
  "from": "0x...",
  "to": "0x...",
  "success": true,
  "gasUsed": "21000",
  "revertReason": null
}
```

## Error Responses

All errors return JSON:

```json
{
  "error": "Invalid contractAddress. Must be a 0x-prefixed 40-character hex string.",
  "details": "..."
}
```

| Status | Meaning |
|--------|---------|
| 400 | Bad request (missing/invalid parameters) |
| 405 | Method not allowed (use POST) |
| 422 | Could not process (e.g., source not available) |
| 429 | Rate limited |
| 500 | Internal server error |
