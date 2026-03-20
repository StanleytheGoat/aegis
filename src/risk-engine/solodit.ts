/**
 * Aegis Risk Engine - Solodit Integration
 *
 * Cross-references Aegis scan findings against Solodit's database of 50K+
 * real-world audit findings from Cyfrin, Sherlock, Code4rena, Trail of Bits,
 * OpenZeppelin, and others.
 *
 * API: POST https://solodit.cyfrin.io/api/v1/solodit/findings
 * Auth: X-Cyfrin-API-Key header
 * Rate limit: 20 requests per 60-second window
 */

import type { ScanFinding } from "./scanner.js";

export interface SoloditFinding {
  title: string;
  severity: string;
  tags: string[];
  protocolCategory: string;
  qualityScore: number;
  slug: string;
  url: string;
}

export interface SoloditEnrichment {
  query: string;
  totalResults: number;
  findings: SoloditFinding[];
  cached: boolean;
}

export interface EnrichedScanResult {
  aegisFindings: ScanFinding[];
  soloditMatches: SoloditEnrichment[];
  crossReferenceCount: number;
}

// Map Aegis pattern categories to Solodit search keywords
const CATEGORY_KEYWORD_MAP: Record<string, string[]> = {
  // Token scam patterns
  "honeypot": ["honeypot", "sell restriction", "transfer lock"],
  "sell-tax": ["sell tax", "transfer fee manipulation"],
  "sell-pause": ["pause", "transfer pause", "blacklist"],
  "fake-renounce": ["fake renounce", "hidden owner"],
  "hidden-mint": ["hidden mint", "unauthorized minting"],
  "balance-manipulation": ["balance manipulation", "reflection token"],
  "max-tx": ["max transaction", "anti-whale"],
  "approval-theft": ["approval", "allowance theft"],
  "burn-price": ["burn manipulation", "price manipulation burn"],

  // Reentrancy
  "reentrancy": ["reentrancy", "re-entrancy", "cross-function reentrancy"],
  "read-only-reentrancy": ["read-only reentrancy"],
  "cross-contract-reentrancy": ["cross-contract reentrancy"],

  // Access control
  "access-control": ["access control", "unauthorized access", "missing access control"],
  "tx-origin": ["tx.origin", "phishing"],
  "unprotected-selfdestruct": ["selfdestruct", "self-destruct"],

  // Oracle
  "oracle": ["oracle manipulation", "price oracle", "TWAP manipulation"],
  "spot-price": ["spot price", "flash loan oracle"],

  // Proxy
  "proxy": ["proxy", "upgrade", "implementation slot", "storage collision"],
  "delegatecall": ["delegatecall", "delegate call vulnerability"],
  "storage-collision": ["storage collision", "storage layout"],

  // Flash loan
  "flash-loan": ["flash loan", "flash loan attack"],

  // MEV
  "mev": ["MEV", "front-running", "sandwich attack", "frontrun"],
  "sandwich": ["sandwich attack", "sandwich"],

  // Governance
  "governance": ["governance attack", "flash loan governance", "vote manipulation"],

  // Cross-chain
  "cross-chain": ["cross-chain", "bridge vulnerability", "bridge exploit"],

  // NFT
  "nft": ["NFT", "ERC721", "unsafe mint"],

  // Staking/vault
  "vault": ["vault", "share inflation", "first depositor"],
  "staking": ["staking", "reward manipulation"],

  // Lending
  "lending": ["lending", "liquidation", "borrow"],

  // Signature
  "signature": ["signature replay", "signature malleability", "ecrecover"],
  "permit": ["permit", "EIP-2612"],

  // EVM
  "overflow": ["overflow", "underflow", "integer overflow"],
  "unchecked": ["unchecked return", "low-level call"],
  "dos": ["denial of service", "DoS", "unbounded loop"],
  "rounding": ["rounding", "precision loss", "rounding error"],
};

// Simple in-memory cache with TTL
const cache = new Map<string, { data: SoloditEnrichment; expiresAt: number }>();
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

// Rate limiter
let requestTimestamps: number[] = [];
const RATE_LIMIT = 20;
const RATE_WINDOW_MS = 60_000;

function getApiKey(): string | null {
  return process.env.SOLODIT_API_KEY || process.env.CYFRIN_API_KEY || null;
}

async function waitForRateLimit(): Promise<void> {
  const now = Date.now();
  requestTimestamps = requestTimestamps.filter((t) => now - t < RATE_WINDOW_MS);
  if (requestTimestamps.length >= RATE_LIMIT) {
    const oldest = requestTimestamps[0];
    const waitMs = RATE_WINDOW_MS - (now - oldest) + 100;
    await new Promise((r) => setTimeout(r, waitMs));
    requestTimestamps = requestTimestamps.filter((t) => Date.now() - t < RATE_WINDOW_MS);
  }
  requestTimestamps.push(Date.now());
}

export async function searchSolodit(
  keywords: string,
  impact: string[] = ["HIGH", "MEDIUM"],
  pageSize: number = 5,
): Promise<SoloditEnrichment> {
  const cacheKey = `${keywords}:${impact.join(",")}:${pageSize}`;
  const cached = cache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) {
    return { ...cached.data, cached: true };
  }

  const apiKey = getApiKey();
  if (!apiKey) {
    return { query: keywords, totalResults: 0, findings: [], cached: false };
  }

  await waitForRateLimit();

  const response = await fetch("https://solodit.cyfrin.io/api/v1/solodit/findings", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Cyfrin-API-Key": apiKey,
    },
    body: JSON.stringify({
      page: 1,
      pageSize,
      filters: {
        keywords,
        impact,
        sortField: "Quality",
        sortDirection: "Desc",
      },
    }),
  });

  if (!response.ok) {
    const errorText = await response.text().catch(() => "");
    if (response.status === 429) {
      // Rate limited -- return empty, don't crash
      return { query: keywords, totalResults: 0, findings: [], cached: false };
    }
    throw new Error(`Solodit API error ${response.status}: ${errorText}`);
  }

  const data = await response.json() as any;

  const findings: SoloditFinding[] = (data.data || data.findings || data.results || []).map(
    (f: any) => ({
      title: f.title || f.name || "",
      severity: f.severity || f.impact || "",
      tags: f.tags || [],
      protocolCategory: f.protocol_category || f.protocolCategory || "",
      qualityScore: f.quality_score || f.qualityScore || 0,
      slug: f.slug || "",
      url: f.slug ? `https://solodit.cyfrin.io/issues/${f.slug}` : "",
    }),
  );

  const result: SoloditEnrichment = {
    query: keywords,
    totalResults: data.total || data.totalCount || findings.length,
    findings,
    cached: false,
  };

  cache.set(cacheKey, { data: result, expiresAt: Date.now() + CACHE_TTL_MS });
  return result;
}

/**
 * Given Aegis scan findings, query Solodit for real-world audit findings
 * that match the same vulnerability categories. Returns enriched results
 * with cross-references.
 */
export async function enrichWithSolodit(
  aegisFindings: ScanFinding[],
): Promise<EnrichedScanResult> {
  if (!getApiKey()) {
    return { aegisFindings, soloditMatches: [], crossReferenceCount: 0 };
  }

  // Deduplicate keywords based on pattern categories
  const keywordSets = new Set<string>();
  for (const finding of aegisFindings) {
    const id = finding.patternId;
    // Match against category map keys
    for (const [category, keywords] of Object.entries(CATEGORY_KEYWORD_MAP)) {
      if (id.includes(category)) {
        // Use the first keyword as primary search
        keywordSets.add(keywords[0]);
        break;
      }
    }
  }

  // Cap at 5 queries to stay within rate limits
  const queries = Array.from(keywordSets).slice(0, 5);
  const soloditMatches: SoloditEnrichment[] = [];

  for (const query of queries) {
    try {
      const result = await searchSolodit(query, ["HIGH", "MEDIUM"], 3);
      if (result.totalResults > 0) {
        soloditMatches.push(result);
      }
    } catch {
      // Non-fatal: Solodit enrichment is best-effort
    }
  }

  const crossReferenceCount = soloditMatches.reduce(
    (sum, m) => sum + m.findings.length,
    0,
  );

  return { aegisFindings, soloditMatches, crossReferenceCount };
}

/**
 * Direct search -- used by the MCP tool for manual queries
 */
export async function querySolodit(
  keywords: string,
  options?: {
    impact?: string[];
    pageSize?: number;
    page?: number;
  },
): Promise<SoloditEnrichment> {
  return searchSolodit(
    keywords,
    options?.impact || ["HIGH", "MEDIUM", "LOW"],
    options?.pageSize || 10,
  );
}
