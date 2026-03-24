/**
 * Shared utilities for Aegis API functions.
 * Provides rate limiting, error handling, CORS, and input validation.
 */

// --- In-memory rate limiter (resets per cold start) ---

const REQUEST_WINDOW_MS = 60_000;
const MAX_REQUESTS_PER_WINDOW = 20;

const requestCounts = new Map<string, { count: number; resetAt: number }>();

export function checkRateLimit(ip: string): { allowed: boolean; retryAfterMs: number } {
  const now = Date.now();
  const entry = requestCounts.get(ip);

  if (!entry || now > entry.resetAt) {
    requestCounts.set(ip, { count: 1, resetAt: now + REQUEST_WINDOW_MS });
    return { allowed: true, retryAfterMs: 0 };
  }

  if (entry.count >= MAX_REQUESTS_PER_WINDOW) {
    return { allowed: false, retryAfterMs: entry.resetAt - now };
  }

  entry.count++;
  return { allowed: true, retryAfterMs: 0 };
}

// --- CORS headers ---

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Max-Age": "86400",
};

// --- Response helpers ---

export function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}

export function errorResponse(message: string, status: number, details?: string): Response {
  return jsonResponse({ error: message, ...(details ? { details } : {}) }, status);
}

export function corsPreflightResponse(): Response {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}

// --- Address validation ---

const EVM_ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/;

export function isValidAddress(value: unknown): value is string {
  return typeof value === "string" && EVM_ADDRESS_RE.test(value);
}

export function isValidHex(value: unknown): value is string {
  return typeof value === "string" && /^0x[a-fA-F0-9]*$/.test(value);
}

// --- Supported chains ---

const SUPPORTED_CHAINS = new Set([1, 8453, 84532]);

export function isValidChainId(value: unknown): value is number {
  return typeof value === "number" && SUPPORTED_CHAINS.has(value);
}

// --- Request handler wrapper ---

type HandlerFn = (body: Record<string, unknown>) => Promise<Response>;

export function apiHandler(fn: HandlerFn) {
  return async (request: Request): Promise<Response> => {
    // CORS preflight
    if (request.method === "OPTIONS") {
      return corsPreflightResponse();
    }

    // Only POST
    if (request.method !== "POST") {
      return errorResponse("Method not allowed. Use POST.", 405);
    }

    // Rate limit
    const ip = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
      || request.headers.get("x-nf-client-connection-ip")
      || "unknown";
    const rateCheck = checkRateLimit(ip);
    if (!rateCheck.allowed) {
      const retryAfter = Math.ceil(rateCheck.retryAfterMs / 1000);
      return new Response(
        JSON.stringify({
          error: "Rate limit exceeded. Too many requests.",
          retryAfterSeconds: retryAfter,
        }),
        {
          status: 429,
          headers: {
            "Content-Type": "application/json",
            "Retry-After": String(retryAfter),
            ...CORS_HEADERS,
          },
        },
      );
    }

    // Parse body
    let body: Record<string, unknown>;
    try {
      const text = await request.text();
      if (!text) {
        return errorResponse("Request body is required. Send JSON.", 400);
      }
      body = JSON.parse(text);
      if (typeof body !== "object" || body === null || Array.isArray(body)) {
        return errorResponse("Request body must be a JSON object.", 400);
      }
    } catch {
      return errorResponse("Invalid JSON in request body.", 400);
    }

    // Run handler
    try {
      return await fn(body);
    } catch (err: unknown) {
      console.error("[aegis-api]", err);
      const message = err instanceof Error ? err.message : "Unknown error";
      return errorResponse("Internal server error.", 500, message);
    }
  };
}
