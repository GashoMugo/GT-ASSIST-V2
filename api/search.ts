/**
 * Server-side search proxy (Vercel serverless function).
 *
 * SECURITY CONTRACT: Tavily / Brave API keys NEVER reach the browser. Search
 * calls go through this route and the credential is injected here from
 * server-side environment variables (TAVILY_API_KEY / BRAVE_API_KEY, with a
 * transitional fallback to the legacy VITE_ variants).
 *
 * - POST { provider: 'tavily' | 'brave', query, maxResults?, searchDepth?, userKey? }
 *   -> runs the search upstream and returns its JSON verbatim.
 * - GET -> capability probe: { tavily: boolean, brave: boolean } (whether a
 *   platform key exists for each provider; never exposes key material).
 * - userKey is an optional BYOK key; when absent the platform key is used.
 * - Guards: Clerk session auth (POST) + browser-Origin allowlist + per-IP
 *   rate limiting (all inlined in this file).
 * - Every locally generated error response carries `X-Proxy-Error: 1` so the
 *   client knows it is the proxy speaking (no point retrying) rather than a
 *   retryable upstream failure.
 *
 * HANDLER SIGNATURE: Vercel requires named method exports (`export function
 * GET/POST(request: Request)`) — a plain default-exported function is never
 * invoked and the function 504s. Verified against
 * https://vercel.com/docs/functions/runtimes/node-js
 */

import { verifyToken } from '@clerk/backend';

export const config = { maxDuration: 30, supportsResponseStreaming: true };

// ---- Request guards (INLINED on purpose: Vercel does not bundle relative
// cross-directory imports for /api functions — a shared module fails at
// runtime with ERR_MODULE_NOT_FOUND. Keep in sync with api/chutes.ts.) ----

const ALLOWED_ORIGINS = new Set([
  'https://create.gashotech.com',
  'https://gashotech.com',
  'http://localhost:3000',
  'http://localhost:5173',
]);

/**
 * This project's own Vercel preview hosts only (never blanket *.vercel.app —
 * any Vercel customer can host there). Kept as a second layer behind the
 * Clerk session check.
 */
const isProjectPreviewHost = (hostname: string): boolean =>
  /^gashochat-[a-z0-9-]+-gashotoxics-projects\.vercel\.app$/.test(hostname) ||
  /^gashochat-git-[a-z0-9-]+\.vercel\.app$/.test(hostname);

/** 403 when a browser Origin is present and not ours; null when allowed. */
const guardOrigin = (request: Request): Response | null => {
  const origin = request.headers.get('origin');
  if (!origin) return null;
  if (ALLOWED_ORIGINS.has(origin)) return null;
  try {
    if (isProjectPreviewHost(new URL(origin).hostname)) return null;
  } catch {
    // fall through to reject
  }
  return json({ error: 'Origin not allowed' }, 403);
};

const WINDOW_MS = 60_000;
const rateBuckets = new Map<string, number[]>();

/** Per-IP sliding window (per instance) — defence-in-depth, not auth. */
const guardRateLimit = (request: Request, bucket: string, maxPerMinute = 60): Response | null => {
  const fwd = request.headers.get('x-forwarded-for');
  const ip = (fwd ? fwd.split(',')[0].trim() : '') || 'unknown';
  const key = `${bucket}:${ip}`;
  const now = Date.now();
  if (rateBuckets.size > 2000) {
    for (const [k, hits] of rateBuckets) {
      if (hits.length === 0 || now - hits[hits.length - 1] > 2 * WINDOW_MS) rateBuckets.delete(k);
    }
  }
  const hits = (rateBuckets.get(key) || []).filter((t) => now - t < WINDOW_MS);
  if (hits.length >= maxPerMinute) {
    rateBuckets.set(key, hits);
    return new Response(JSON.stringify({ error: 'Rate limit exceeded, retry shortly' }), {
      status: 429,
      headers: { 'Content-Type': 'application/json', 'Retry-After': '60' },
    });
  }
  hits.push(now);
  rateBuckets.set(key, hits);
  return null;
};
// ---- End request guards ----

/** Error responses are marked so clients never retry the proxy itself. */
const PROXY_ERROR_HEADERS = { 'X-Proxy-Error': '1' };

const json = (data: unknown, status = 200, headers: Record<string, string> = {}): Response =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...PROXY_ERROR_HEADERS, ...headers },
  });

// ---- Client session auth (Clerk) (INLINED on purpose — same rule as the
// request guards; keep this block byte-identical across both proxy handlers.
// scripts/api_smoke.mjs asserts the two copies match.) ----

/**
 * Verify a Clerk session JWT server-side. Returns null when authenticated, or
 * the 401/503 Response to send instead. Runs BEFORE any body parsing or
 * upstream call: an anonymous request can never spend platform credits.
 */
const requireSession = async (request: Request): Promise<Response | null> => {
  const secretKey = process.env.CLERK_SECRET_KEY;
  const jwtKey = process.env.CLERK_JWT_KEY;
  if (!secretKey && !jwtKey) {
    // Fail closed, but loudly distinguishable from a bad token.
    return json({ error: 'Auth not configured on the server' }, 503);
  }
  const header = request.headers.get('authorization') || '';
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  if (!match) return json({ error: 'Authentication required' }, 401);
  try {
    await verifyToken(match[1].trim(), { secretKey, jwtKey });
    return null;
  } catch (error) {
    const reason = (error as { reason?: string })?.reason;
    return json({ error: reason === 'token-expired' ? 'Session token expired' : 'Invalid session token' }, 401);
  }
};
// ---- End client session auth ----

const resolveKey = (provider: 'tavily' | 'brave', userKey: unknown): string | undefined => {
  if (typeof userKey === 'string' && userKey.trim().length > 0) return userKey.trim();
  // Transitional fallback: same secret, legacy env name. Migrate to
  // TAVILY_API_KEY / BRAVE_API_KEY in Vercel and delete the VITE_ variants.
  if (provider === 'tavily') return process.env.TAVILY_API_KEY || process.env.VITE_TAVILY_API_KEY || undefined;
  return process.env.BRAVE_API_KEY || process.env.VITE_BRAVE_API_KEY || undefined;
};

const runTavily = async (
  key: string,
  query: string,
  maxResults: number,
  searchDepth: string
): Promise<Response> => {
  const upstream = await fetch('https://api.tavily.com/search', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      api_key: key,
      query,
      search_depth: searchDepth,
      include_answer: true,
      include_raw_content: false,
      max_results: maxResults,
      include_domains: [],
      exclude_domains: [],
    }),
    redirect: 'manual',
  });
  return new Response(upstream.body, {
    status: upstream.status,
    headers: { 'Content-Type': upstream.headers.get('content-type') || 'application/json' },
  });
};

const runBrave = async (key: string, query: string, maxResults: number): Promise<Response> => {
  const target = new URL('https://api.search.brave.com/res/v1/web/search');
  target.searchParams.set('q', query);
  target.searchParams.set('count', String(maxResults));

  const upstream = await fetch(target, {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
      'X-Subscription-Token': key,
    },
    redirect: 'manual',
  });
  return new Response(upstream.body, {
    status: upstream.status,
    headers: { 'Content-Type': upstream.headers.get('content-type') || 'application/json' },
  });
};

export function GET(request: Request): Response {
  const blocked = guardOrigin(request) ?? guardRateLimit(request, 'search', 120);
  if (blocked) return blocked;
  return json({
    tavily: Boolean(resolveKey('tavily', undefined)),
    brave: Boolean(resolveKey('brave', undefined)),
  });
}

export function PUT(): Response {
  return json({ error: 'Method not allowed' }, 405);
}

export async function POST(request: Request): Promise<Response> {
  const blocked = guardOrigin(request) ?? guardRateLimit(request, 'search', 60);
  if (blocked) return blocked;
  const unauthed = await requireSession(request);
  if (unauthed) return unauthed;

  let payload: {
    provider?: unknown;
    query?: unknown;
    maxResults?: unknown;
    searchDepth?: unknown;
    userKey?: unknown;
  };
  try {
    payload = await request.json();
  } catch {
    return json({ error: 'Invalid JSON body' }, 400);
  }

  const provider = payload.provider === 'tavily' || payload.provider === 'brave' ? payload.provider : null;
  if (!provider) {
    return json({ error: 'Unknown search provider' }, 400);
  }
  if (typeof payload.query !== 'string' || payload.query.trim().length === 0) {
    return json({ error: 'Missing query' }, 400);
  }

  const key = resolveKey(provider, payload.userKey);
  if (!key) {
    return json({ error: `No ${provider} API key configured on the server` }, 503);
  }

  const maxResults = typeof payload.maxResults === 'number' && payload.maxResults > 0
    ? Math.min(Math.floor(payload.maxResults), 20)
    : 5;
  const searchDepth = payload.searchDepth === 'advanced' ? 'advanced' : 'basic';

  try {
    return provider === 'tavily'
      ? await runTavily(key, payload.query, maxResults, searchDepth)
      : await runBrave(key, payload.query, maxResults);
  } catch (error) {
    if ((error as Error).name === 'AbortError') {
      return json({ error: 'Client aborted' }, 499);
    }
    return json({ error: 'Search request failed' }, 502);
  }
}
