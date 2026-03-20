import { type Action } from "@elizaos/core";
import { querySolodit } from "aegis-defi";

/**
 * Search the Solodit audit findings database for known vulnerabilities
 * matching a set of keywords. Useful for researching whether a particular
 * pattern or protocol has been exploited before.
 */
export const searchAuditFindingsAction: Action = {
  name: "AEGIS_SEARCH_AUDIT_FINDINGS",
  similes: [
    "SEARCH_SOLODIT",
    "FIND_VULNERABILITIES",
    "AUDIT_SEARCH",
    "KNOWN_EXPLOITS",
    "SEARCH_AUDIT",
  ],
  description:
    "Search the Solodit database of real-world audit findings. " +
    "Provide keywords like a vulnerability type, protocol name, or " +
    "pattern to find relevant past findings and exploits.",

  validate: async (_runtime, message) => {
    const text = message.content?.text ?? "";
    // Needs at least a few characters of search input
    return text.trim().length >= 3;
  },

  handler: async (_runtime, message, _state, _options, callback) => {
    const text = message.content?.text ?? "";

    // Extract keywords - strip out common filler words and the action trigger
    const keywords = extractKeywords(text);
    if (keywords.length === 0) {
      await callback?.({ text: "Please provide keywords to search for (e.g., 'reentrancy', 'flash loan', 'price oracle')." });
      return { success: false, text: "No search keywords found." };
    }

    // Check for impact filter
    const impactLevel = extractImpact(text);

    await callback?.({
      text: `Searching Solodit for: "${keywords.join(" ")}"${impactLevel ? ` (impact: ${impactLevel})` : ""}...`,
    });

    try {
      const findings = await querySolodit(keywords.join(" "), impactLevel, 10);

      if (!findings || findings.length === 0) {
        const msg = "No audit findings matched your search. Try different keywords.";
        await callback?.({ text: msg });
        return { success: true, text: msg };
      }

      const summary = formatFindings(findings, keywords);
      await callback?.({ text: summary });
      return { success: true, text: summary };
    } catch (err) {
      const msg = `Solodit search failed: ${String(err)}`;
      await callback?.({ text: msg });
      return { success: false, text: msg };
    }
  },

  examples: [
    [
      {
        user: "user",
        content: { text: "Search for reentrancy audit findings" },
      },
      {
        user: "agent",
        content: { text: 'Searching Solodit for: "reentrancy"...' },
      },
    ],
    [
      {
        user: "user",
        content: { text: "Find high impact flash loan exploits in audits" },
      },
      {
        user: "agent",
        content: { text: 'Searching Solodit for: "flash loan exploits" (impact: high)...' },
      },
    ],
  ],
};

const FILLER_WORDS = new Set([
  "search", "find", "look", "for", "audit", "findings", "solodit",
  "about", "related", "to", "the", "a", "an", "in", "on", "any",
  "show", "me", "get", "please", "can", "you", "aegis", "check",
]);

function extractKeywords(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, " ")
    .split(/\s+/)
    .filter((w) => w.length > 1 && !FILLER_WORDS.has(w));
}

function extractImpact(text: string): string | undefined {
  const lower = text.toLowerCase();
  if (lower.includes("critical")) return "critical";
  if (lower.includes("high")) return "high";
  if (lower.includes("medium")) return "medium";
  if (lower.includes("low")) return "low";
  return undefined;
}

interface Finding {
  title?: string;
  severity?: string;
  impact?: string;
  description?: string;
  protocol?: string;
  url?: string;
}

function formatFindings(findings: Finding[], keywords: string[]): string {
  const lines: string[] = [];
  lines.push(`**Solodit Audit Findings** for "${keywords.join(" ")}" (${findings.length} results)`);
  lines.push("");

  for (const f of findings) {
    const severity = f.severity || f.impact || "unknown";
    const title = f.title || "Untitled";
    const protocol = f.protocol ? ` (${f.protocol})` : "";
    lines.push(`- [${severity.toUpperCase()}] **${title}**${protocol}`);
    if (f.description) {
      // Truncate long descriptions
      const desc = f.description.length > 200 ? f.description.slice(0, 200) + "..." : f.description;
      lines.push(`  ${desc}`);
    }
    if (f.url) {
      lines.push(`  Link: ${f.url}`);
    }
  }

  return lines.join("\n");
}
