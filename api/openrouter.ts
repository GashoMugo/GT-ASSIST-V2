/**
 * Server-side OpenRouter proxy (Vercel serverless function).
 *
 * Modes (chat text only — media/TTS/STT stay on the Chutes proxy):
 * - Server-key mode: OPENROUTER_API_KEY from server env, restricted to the
 *   live FREE text-model allowlist fetched from https://openrouter.ai/api/v1/models
 *   and cached in memory for ~1h. A client can never spend this key on a paid
 *   model. No env key -> 503 (never a silent fallback to Chutes).
 * - BYO mode: the user's key arrives per request in the `X-OpenRouter-Key`
 *   header, is used for that one upstream call, and is never logged, stored or
 *   echoed (no key in any response body/header, no console output, no model
 *   call log). Any model id is allowed; OpenRouter bills the user's account.
 *
 * - POST { body: {...chat completion body...} } -> streams the upstream SSE
 *   response straight through.
 * - GET ?action=models -> model list for the picker (free list in server mode,
 *   all text models in BYO mode; Free/pricing flags included).
 * - GET ?action=test-key -> validates the BYO key via /api/v1/key and returns
 *   remaining credit. Never echoes the key.
 * - Guards: Clerk session auth + browser-Origin allowlist + per-IP rate
 *   limiting + request-body size cap (inlined; Vercel does not bundle relative
 *   cross-directory imports for /api functions).
 *
 * HANDLER SIGNATURE: Vercel requires named method exports (`export function
 * POST(request: Request)`), a plain default-exported function 504s.
 */

import { verifyToken } from '@clerk/backend';

// 60s is deploy-safe on every Vercel plan (Hobby cap).
export const config = { maxDuration: 60, supportsResponseStreaming: true };

// Vercel's platform request-body cap is ~4.5MB.
const MAX_REQUEST_BODY_BYTES = 4_500_000;

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

const UPSTREAM_CHAT = 'https://openrouter.ai/api/v1/chat/completions';

/** Fields the route relays upstream; anything else (plugins, provider) is dropped. */
const ALLOWED_CHAT_FIELDS = [
  'model', 'messages', 'stream', 'max_tokens', 'temperature', 'top_p', 'stop',
  'seed', 'presence_penalty', 'frequency_penalty', 'tools', 'tool_choice', 'response_format',
] as const;
const UPSTREAM_MODELS = 'https://openrouter.ai/api/v1/models';
const UPSTREAM_KEY = 'https://openrouter.ai/api/v1/key';

// Attribution headers OpenRouter uses for app ranking/limits.
const ATTRIBUTION_HEADERS = {
  'HTTP-Referer': 'https://create.gashotech.com',
  'X-Title': 'GashoTech Create',
};

type UpstreamModel = {
  id?: unknown;
  name?: unknown;
  pricing?: { prompt?: unknown; completion?: unknown };
  architecture?: { output_modalities?: unknown };
};

type ModelInfo = { id: string; name: string; free: boolean; promptPrice: string; completionPrice: string };

const MODELS_TTL_MS = 60 * 60 * 1000;
let modelsCache: { at: number; models: UpstreamModel[] } | null = null;

const fetchUpstreamModels = async (): Promise<UpstreamModel[]> => {
  if (modelsCache && Date.now() - modelsCache.at < MODELS_TTL_MS) return modelsCache.models;
  const res = await fetch(UPSTREAM_MODELS, { headers: { Accept: 'application/json' } });
  if (!res.ok) throw new Error(`models HTTP ${res.status}`);
  const payload = (await res.json()) as { data?: unknown };
  const models = Array.isArray(payload.data) ? (payload.data as UpstreamModel[]) : [];
  modelsCache = { at: Date.now(), models };
  return models;
};

/** Text-output models only (older entries without modality data are kept). */
const isTextModel = (m: UpstreamModel): boolean =>
  !Array.isArray(m.architecture?.output_modalities) ||
  (m.architecture?.output_modalities as unknown[]).includes('text');

/** Free = id ends `:free` OR both prompt and completion price are 0. */
const isFreeModel = (m: UpstreamModel): boolean =>
  typeof m.id === 'string' &&
  (m.id.endsWith(':free') ||
    (Number(m.pricing?.prompt) === 0 && Number(m.pricing?.completion) === 0));

const toModelInfo = (m: UpstreamModel): ModelInfo => ({
  id: String(m.id),
  name: typeof m.name === 'string' ? m.name : String(m.id),
  free: isFreeModel(m),
  promptPrice: String(m.pricing?.prompt ?? '0'),
  completionPrice: String(m.pricing?.completion ?? '0'),
});

const textModels = async (): Promise<ModelInfo[]> =>
  (await fetchUpstreamModels()).filter((m) => typeof m.id === 'string' && isTextModel(m)).map(toModelInfo);

/** BYO key from the request header. Rejects anything that is not a plain token. */
const readUserKey = (request: Request): string | null => {
  const raw = request.headers.get('x-openrouter-key');
  if (raw === null) return null;
  const key = raw.trim();
  if (!/^[\x21-\x7e]{10,512}$/.test(key)) return 'invalid';
  return key;
};

export async function POST(request: Request): Promise<Response> {
  const blocked = guardOrigin(request) ?? guardRateLimit(request, 'openrouter', 60);
  if (blocked) return blocked;
  const unauthed = await requireSession(request);
  if (unauthed) return unauthed;

  const contentLength = Number(request.headers.get('content-length') || '0');
  if (Number.isFinite(contentLength) && contentLength > MAX_REQUEST_BODY_BYTES) {
    return json({ error: `Request body too large (max ${MAX_REQUEST_BODY_BYTES} bytes)` }, 413);
  }

  let raw: string;
  try {
    raw = await request.text();
  } catch {
    return json({ error: 'Invalid JSON body' }, 400);
  }
  if (raw.length > MAX_REQUEST_BODY_BYTES) {
    return json({ error: `Request body too large (max ${MAX_REQUEST_BODY_BYTES} bytes)` }, 413);
  }

  let payload: { body?: unknown };
  try {
    payload = JSON.parse(raw);
  } catch {
    return json({ error: 'Invalid JSON body' }, 400);
  }
  const chatBody = payload?.body;
  if (!chatBody || typeof chatBody !== 'object' || Array.isArray(chatBody)) {
    return json({ error: 'Missing chat body' }, 400);
  }
  const model = (chatBody as { model?: unknown }).model;
  if (typeof model !== 'string' || model.length === 0) {
    return json({ error: 'Missing model' }, 400);
  }

  const userKey = readUserKey(request);
  if (userKey === 'invalid') return json({ error: 'Invalid key header' }, 400);

  let apiKey: string;
  if (userKey) {
    apiKey = userKey;
  } else {
    const serverKey = process.env.OPENROUTER_API_KEY;
    if (!serverKey) {
      // Never fall back silently to Chutes (spec: free mode is a distinct mode).
      return json({ error: 'OpenRouter free mode not configured' }, 503);
    }
    apiKey = serverKey;
    const allowed = new Set((await textModels().catch(() => [])).filter((m) => m.free).map((m) => m.id));
    if (allowed.size === 0) {
      return json({ error: 'OpenRouter model list unavailable' }, 502);
    }
    if (!allowed.has(model)) {
      // A paid/non-text model may never run on the platform key.
      return json({ error: 'Model not available in free mode' }, 400);
    }
  }

  // Relay chat fields only: OpenRouter `plugins`/`provider` extras can spend the
  // key on paid features the app never asked for (AEGIS H-1).
  const relayBody: Record<string, unknown> = {};
  for (const field of ALLOWED_CHAT_FIELDS) {
    const value = (chatBody as Record<string, unknown>)[field];
    if (value !== undefined) relayBody[field] = value;
  }
  relayBody.stream = (chatBody as { stream?: unknown }).stream !== false;

  let upstream: Response;
  try {
    upstream = await fetch(UPSTREAM_CHAT, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        ...ATTRIBUTION_HEADERS,
      },
      body: JSON.stringify(relayBody),
      signal: request.signal,
    });
  } catch (error) {
    if ((error as Error).name === 'AbortError') {
      return json({ error: 'Client aborted' }, 499);
    }
    return json({ error: 'Upstream request failed' }, 502);
  }

  if (upstream.status === 429) {
    return json(
      {
        error: userKey
          ? 'OpenRouter rate limit reached — try again later'
          : 'Free daily limit reached — add your own OpenRouter key in Settings or try later',
      },
      429
    );
  }
  if (upstream.status === 401 || upstream.status === 403) {
    // Never relay the upstream auth body (defence against any key echo).
    return json({ error: 'Key rejected' }, 401);
  }
  if (!upstream.ok) {
    return json({ error: `OpenRouter error (HTTP ${upstream.status})` }, upstream.status);
  }

  const headers = new Headers();
  const contentType = upstream.headers.get('content-type');
  if (contentType) headers.set('Content-Type', contentType);
  return new Response(upstream.body, { status: upstream.status, headers });
}

export async function GET(request: Request): Promise<Response> {
  const blocked = guardOrigin(request) ?? guardRateLimit(request, 'openrouter', 60);
  if (blocked) return blocked;
  const unauthed = await requireSession(request);
  if (unauthed) return unauthed;

  const action = new URL(request.url).searchParams.get('action');

  if (action === 'models') {
    const userKey = readUserKey(request);
    if (userKey === 'invalid') return json({ error: 'Invalid key header' }, 400);
    let models: ModelInfo[];
    try {
      models = await textModels();
    } catch {
      return json({ error: 'OpenRouter model list unavailable' }, 502);
    }
    if (!userKey) models = models.filter((m) => m.free);
    if (userKey) models.sort((a, b) => Number(b.free) - Number(a.free));
    return json({ mode: userKey ? 'byok' : 'server', models });
  }

  if (action === 'test-key') {
    const userKey = readUserKey(request);
    if (!userKey || userKey === 'invalid') return json({ valid: false, error: 'No key supplied' }, 400);
    let upstream: Response;
    try {
      upstream = await fetch(UPSTREAM_KEY, {
        headers: { 'Authorization': `Bearer ${userKey}`, 'Content-Type': 'application/json', ...ATTRIBUTION_HEADERS },
      });
    } catch {
      return json({ valid: false, error: 'OpenRouter unreachable' });
    }
    if (upstream.status === 401 || upstream.status === 403) return json({ valid: false, error: 'Key rejected' });
    if (!upstream.ok) return json({ valid: false, error: `OpenRouter error (HTTP ${upstream.status})` });
    const payload = (await upstream.json().catch(() => ({}))) as { data?: Record<string, unknown> };
    const data = payload?.data ?? {};
    return json({
      valid: true,
      label: data.label ?? null,
      is_free_tier: data.is_free_tier ?? null,
      limit: data.limit ?? null,
      limit_remaining: data.limit_remaining ?? null,
      usage: data.usage ?? null,
    });
  }

  return json({ error: 'Unknown action' }, 400);
}

export function PUT(): Response {
  return json({ error: 'Method not allowed' }, 405);
}
