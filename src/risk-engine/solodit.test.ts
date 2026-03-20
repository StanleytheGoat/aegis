import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { searchSolodit, enrichWithSolodit, querySolodit } from "./solodit.js";
import type { ScanFinding } from "./scanner.js";

// Mock fetch globally
const fetchMock = vi.fn();
vi.stubGlobal("fetch", fetchMock);

describe("Solodit Integration", () => {
  beforeEach(() => {
    vi.stubEnv("SOLODIT_API_KEY", "sk_test_key_123");
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  describe("searchSolodit", () => {
    it("sends correct request to Solodit API", async () => {
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          data: [
            {
              title: "Reentrancy in withdraw",
              severity: "HIGH",
              tags: ["Reentrancy"],
              protocol_category: "Lending",
              quality_score: 85,
              slug: "test-finding-1",
            },
          ],
          total: 1,
        }),
      });

      const result = await searchSolodit("reentrancy", ["HIGH"], 5);

      expect(fetchMock).toHaveBeenCalledWith(
        "https://solodit.cyfrin.io/api/v1/solodit/findings",
        expect.objectContaining({
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Cyfrin-API-Key": "sk_test_key_123",
          },
        }),
      );

      const body = JSON.parse(fetchMock.mock.calls[0][1].body);
      expect(body.filters.keywords).toBe("reentrancy");
      expect(body.filters.impact).toEqual(["HIGH"]);
      expect(body.pageSize).toBe(5);
    });

    it("parses findings correctly", async () => {
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          data: [
            {
              title: "Flash loan price manipulation",
              severity: "HIGH",
              tags: ["Flash Loan", "Oracle"],
              protocol_category: "DeFi",
              quality_score: 90,
              slug: "flash-loan-finding",
            },
          ],
          total: 42,
        }),
      });

      const result = await searchSolodit("flash loan");
      expect(result.totalResults).toBe(42);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].title).toBe("Flash loan price manipulation");
      expect(result.findings[0].severity).toBe("HIGH");
      expect(result.findings[0].url).toBe("https://solodit.cyfrin.io/issues/flash-loan-finding");
      expect(result.cached).toBe(false);
    });

    it("returns empty when no API key is set", async () => {
      vi.stubEnv("SOLODIT_API_KEY", "");
      delete process.env.SOLODIT_API_KEY;
      delete process.env.CYFRIN_API_KEY;

      // Re-import to pick up env change
      const result = await searchSolodit("reentrancy");
      expect(result.findings).toHaveLength(0);
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it("handles rate limit (429) gracefully", async () => {
      fetchMock.mockResolvedValueOnce({
        ok: false,
        status: 429,
        text: async () => "Rate limited",
      });

      const result = await searchSolodit("test query");
      expect(result.findings).toHaveLength(0);
      expect(result.totalResults).toBe(0);
    });

    it("throws on non-429 API errors", async () => {
      fetchMock.mockResolvedValueOnce({
        ok: false,
        status: 500,
        text: async () => "Internal server error",
      });

      await expect(searchSolodit("test")).rejects.toThrow("Solodit API error 500");
    });
  });

  describe("enrichWithSolodit", () => {
    it("maps Aegis findings to Solodit queries", async () => {
      const aegisFindings: ScanFinding[] = [
        {
          patternId: "reentrancy-basic",
          patternName: "Basic Reentrancy",
          severity: "critical",
          description: "Reentrancy vulnerability detected",
          riskWeight: 90,
        },
        {
          patternId: "flash-loan-attack",
          patternName: "Flash Loan Attack",
          severity: "high",
          description: "Flash loan attack pattern",
          riskWeight: 80,
        },
      ];

      // Two queries expected: reentrancy and flash loan
      fetchMock
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            data: [{ title: "Reentrancy in pool", severity: "HIGH", tags: [], slug: "r1" }],
            total: 15,
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            data: [{ title: "Flash loan exploit", severity: "HIGH", tags: [], slug: "f1" }],
            total: 8,
          }),
        });

      const result = await enrichWithSolodit(aegisFindings);
      expect(result.aegisFindings).toBe(aegisFindings);
      expect(result.soloditMatches.length).toBeGreaterThanOrEqual(1);
      expect(result.crossReferenceCount).toBeGreaterThanOrEqual(1);
    });

    it("returns empty when no API key", async () => {
      delete process.env.SOLODIT_API_KEY;
      delete process.env.CYFRIN_API_KEY;

      const result = await enrichWithSolodit([
        {
          patternId: "honeypot-sell-tax",
          patternName: "Sell Tax",
          severity: "critical",
          description: "test",
          riskWeight: 90,
        },
      ]);

      expect(result.soloditMatches).toHaveLength(0);
      expect(result.crossReferenceCount).toBe(0);
    });

    it("handles empty aegis findings", async () => {
      const result = await enrichWithSolodit([]);
      expect(result.soloditMatches).toHaveLength(0);
      expect(fetchMock).not.toHaveBeenCalled();
    });
  });

  describe("querySolodit", () => {
    it("passes options through correctly", async () => {
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ data: [], total: 0 }),
      });

      await querySolodit("oracle manipulation", {
        impact: ["HIGH", "MEDIUM", "LOW"],
        pageSize: 15,
      });

      const body = JSON.parse(fetchMock.mock.calls[0][1].body);
      expect(body.filters.keywords).toBe("oracle manipulation");
      expect(body.filters.impact).toEqual(["HIGH", "MEDIUM", "LOW"]);
      expect(body.pageSize).toBe(15);
    });
  });
});
