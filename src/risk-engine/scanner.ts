/**
 * Aegis Risk Engine — Contract Scanner
 *
 * Analyzes smart contract source code and bytecode for known exploit patterns,
 * honeypot mechanics, and other security risks. Returns a risk assessment with
 * detailed findings.
 */

import { EXPLOIT_PATTERNS, type ExploitPattern } from "./patterns.js";

export interface ScanFinding {
  patternId: string;
  patternName: string;
  severity: ExploitPattern["severity"];
  description: string;
  riskWeight: number;
  matchedSnippet?: string;
}

export interface ScanResult {
  /** Overall risk score 0-100 (0 = safe, 100 = definitely malicious) */
  riskScore: number;
  /** Risk classification */
  riskLevel: "safe" | "low" | "medium" | "high" | "critical";
  /** Individual findings */
  findings: ScanFinding[];
  /** Summary for agents */
  summary: string;
  /** Recommendation */
  recommendation: "proceed" | "caution" | "avoid";
  /** Timestamp */
  scannedAt: string;
}

export function scanContractSource(source: string): ScanResult {
  const findings: ScanFinding[] = [];

  for (const pattern of EXPLOIT_PATTERNS) {
    if (!pattern.sourcePatterns) continue;

    for (const regex of pattern.sourcePatterns) {
      const match = source.match(regex);
      if (match) {
        // Avoid duplicate findings for the same pattern
        if (findings.some((f) => f.patternId === pattern.id)) continue;

        findings.push({
          patternId: pattern.id,
          patternName: pattern.name,
          severity: pattern.severity,
          description: pattern.description,
          riskWeight: pattern.riskWeight,
          matchedSnippet: match[0].slice(0, 100),
        });
        break; // One match per pattern is enough
      }
    }
  }

  return buildResult(findings);
}

export function scanBytecode(bytecode: string): ScanResult {
  const findings: ScanFinding[] = [];
  const hex = bytecode.toLowerCase().replace(/^0x/, "");

  for (const pattern of EXPLOIT_PATTERNS) {
    if (!pattern.bytecodePatterns) continue;

    for (const bytePattern of pattern.bytecodePatterns) {
      if (hex.includes(bytePattern.toLowerCase())) {
        if (findings.some((f) => f.patternId === pattern.id)) continue;

        findings.push({
          patternId: pattern.id,
          patternName: pattern.name,
          severity: pattern.severity,
          description: pattern.description,
          riskWeight: pattern.riskWeight,
        });
        break;
      }
    }
  }

  return buildResult(findings);
}

function buildResult(findings: ScanFinding[]): ScanResult {
  // Calculate composite risk score
  // Use a weighted approach: highest finding dominates, others add diminishing contributions
  const sorted = [...findings].sort((a, b) => b.riskWeight - a.riskWeight);

  let riskScore = 0;
  for (let i = 0; i < sorted.length; i++) {
    // Each subsequent finding contributes less (diminishing returns)
    const contribution = sorted[i].riskWeight * Math.pow(0.5, i);
    riskScore += contribution;
  }
  riskScore = Math.min(100, Math.round(riskScore));

  const riskLevel = classifyRisk(riskScore);
  const recommendation = riskScore >= 70 ? "avoid" : riskScore >= 40 ? "caution" : "proceed";

  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const highCount = findings.filter((f) => f.severity === "high").length;

  let summary: string;
  if (findings.length === 0) {
    summary = "No known exploit patterns detected. Contract appears safe based on static analysis.";
  } else {
    const parts = [`Found ${findings.length} potential issue(s).`];
    if (criticalCount > 0) parts.push(`${criticalCount} critical.`);
    if (highCount > 0) parts.push(`${highCount} high severity.`);
    parts.push(`Risk score: ${riskScore}/100.`);
    parts.push(`Recommendation: ${recommendation.toUpperCase()}.`);
    summary = parts.join(" ");
  }

  return {
    riskScore,
    riskLevel,
    findings,
    summary,
    recommendation,
    scannedAt: new Date().toISOString(),
  };
}

function classifyRisk(score: number): ScanResult["riskLevel"] {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  if (score >= 20) return "low";
  return "safe";
}
