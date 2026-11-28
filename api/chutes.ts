/**
 * Server-side Chutes proxy (Vercel serverless function).
 *
 * SECURITY CONTRACT: the Chutes API key NEVER reaches the browser. All Chutes
 * calls from the client go through this route; the Authorization header is
 * injected here from the server-side environment variable CHUTES_API_KEY (the
 * public VITE_ variant was removed in the 2026-10-07 key-leak sweep — Vite
 * inlines VITE_* into the client bundle; never reintroduce a VITE_ secret).
 *
 * - POST { targetUrl, body, userKey? } -> forwards a JSON POST to targetUrl.
 * - targetUrl must be https on port 443 at chutes.ai / *.chutes.ai (allowlist =
 *   SSRF guard) and upstream redirects are not followed (keeps the injected
 *   Authorization on-allowlist).
 * - userKey is an optional BYOK key; when absent the platform key is used.
 * - The upstream response (status, content-type, body incl. SSE streams and
 *   binary blobs) is passed straight through.
 * - Guards: Clerk session auth + browser-Origin allowlist + per-IP rate
 *   limiting + request-body size cap (all inlined in this file).
 * - Every locally generated error response carries `X-Proxy-Error: 1` so the
 *   client knows it is the proxy speaking (no point retrying) rather than a
 *   retryable upstream failure.
 *
 * HANDLER SIGNATURE: Vercel requires named method exports (`export function
 * POST(request: Request)`) or `export default { fetch() {} }` for the web
 * standard — a plain default-exported function is never invoked and the
 * function 504s. Verified against https://vercel.com/docs/functions/runtimes/node-js
 */

import { verifyToken } from '@clerk/backend';

// 60s is deploy-safe on every Vercel plan (Hobby cap). Raise to 300 on Pro if
// long media generations need more headroom.
export const config = { maxDuration: 60, supportsResponseStreaming: true };

// Vercel's platform request-body cap is ~4.5MB
// (vercel.com/docs/functions/limitations). Fail fast with a clear 413 instead
// of letting the platform truncate the body mid-relay (base64 media inputs —
// lip-sync video/audio — are the risk here).
const MAX_REQUEST_BODY_BYTES = 4_500_000;

// ---- Request guards (INLINED on purpose: Vercel does not bundle relative
// cross-directory imports for /api functions — a shared module fails at
// runtime with ERR_MODULE_NOT_FOUND. Keep in sync with api/search.ts.) ----

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

const PLATFORM_HOST = 'chutes.ai';

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

const isAllowedTarget = (raw: unknown): raw is string => {
  if (typeof raw !== 'string' || raw.length === 0) return false;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.protocol !== 'https:') return false;
  if (url.port !== '' && url.port !== '443') return false;
  const host = url.hostname.toLowerCase();
  return host === PLATFORM_HOST || host.endsWith(`.${PLATFORM_HOST}`);
};

const resolveApiKey = (userKey: unknown): string | undefined => {
  if (typeof userKey === 'string' && userKey.trim().length > 0) return userKey.trim();
  // Server-side only. The public VITE_ variant was removed after the 2026-10-07
  // key-leak sweep (Vite inlines VITE_* vars into the public client bundle).
  // Set CHUTES_API_KEY in Vercel env (server scope). Never reintroduce a VITE_ secret.
  return process.env.CHUTES_API_KEY || undefined;
};

export async function POST(request: Request): Promise<Response> {
  const blocked = guardOrigin(request) ?? guardRateLimit(request, 'chutes', 60);
  if (blocked) return blocked;
  const unauthed = await requireSession(request);
  if (unauthed) return unauthed;

  const contentLength = Number(request.headers.get('content-length') || '0');
  if (Number.isFinite(contentLength) && contentLength > MAX_REQUEST_BODY_BYTES) {
    return json({ error: `Request body too large (max ${MAX_REQUEST_BODY_BYTES} bytes) — pass media inputs as URLs` }, 413);
  }

  let raw: string;
  try {
    raw = await request.text();
  } catch {
    return json({ error: 'Invalid JSON body' }, 400);
  }
  // content-length is not always present (chunked bodies), so enforce the cap
  // on the measured body too, before JSON.parse allocates any structure.
  if (raw.length > MAX_REQUEST_BODY_BYTES) {
    return json({ error: `Request body too large (max ${MAX_REQUEST_BODY_BYTES} bytes) — pass media inputs as URLs` }, 413);
  }

  let payload: { targetUrl?: unknown; body?: unknown; userKey?: unknown };
  try {
    payload = JSON.parse(raw);
  } catch {
    return json({ error: 'Invalid JSON body' }, 400);
  }

  if (!isAllowedTarget(payload.targetUrl)) {
    return json({ error: 'Target URL not allowed' }, 400);
  }

  const apiKey = resolveApiKey(payload.userKey);
  if (!apiKey) {
    return json({ error: 'Chutes API key not configured on the server' }, 503);
  }

  let upstream: Response;
  try {
    upstream = await fetch(payload.targetUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload.body ?? {}),
      signal: request.signal,
      redirect: 'manual',
    });
  } catch (error) {
    if ((error as Error).name === 'AbortError') {
      return json({ error: 'Client aborted' }, 499);
    }
    return json({ error: 'Upstream request failed' }, 502);
  }

  const headers = new Headers();
  const contentType = upstream.headers.get('content-type');
  if (contentType) headers.set('Content-Type', contentType);

  return new Response(upstream.body, { status: upstream.status, headers });
}

export function GET(): Response {
  return json({ error: 'Method not allowed' }, 405);
}
