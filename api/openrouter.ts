/**
 * Server-side OpenRouter proxy (Vercel serverless function).
 *
 * Modes (chat text only — media/TTS/STT stay on the Chutes proxy):
 * - Server-key mode: OPENROUTER_API_KEY from server env, restricted to the
 *   live free/stealth text-model allowlist fetched from
 *   https://openrouter.ai/api/v1/models and cached in memory for 30min (last
 *   good list survives a failed refresh). No env key -> 503 (never a silent
 *   fallback to Chutes). No list at all -> 503, never open.
 * - BYO mode: the user's key arrives per request in the `X-OpenRouter-Key`
 *   header, is used for that one upstream call, and is never logged, stored or
 *   echoed (no key in any response body/header, no console output, no model
 *   call log). Same free/stealth allowlist: the BYO key buys the user's own
 *   rate limit, never a paid model (owner decision 2026-11-27).
 * - Every upstream call also carries provider.max_price = 0 on all cost fields
 *   (OpenRouter refuses to route to anything billable) and usage.include; a
 *   non-zero reported cost denylists the model for the life of the instance.
 *
 * - POST { body: {...chat completion body...} } -> streams the upstream SSE
 *   response straight through.
 * - GET ?action=models -> allowlisted model list for the picker (Free or
 *   Stealth flags included) in both modes.
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

/**
 * Fields the route relays upstream. Anything else the client sends — `models`
 * (fallback arrays), `route`, `provider`, `plugins`, `transforms`,
 * `web_search_options`, `presence_penalty`/`frequency_penalty` — is dropped
 * before the call: those extras can spend the key on paid routing/features
 * (AEGIS H-1).
 */
const ALLOWED_CHAT_FIELDS = [
  'model', 'messages', 'stream', 'max_tokens', 'temperature', 'top_p', 'stop',
  'seed', 'tools', 'tool_choice', 'response_format',
] as const;
// Paid variants of an allowlisted id (`:online` runs web search, `:nitro`
// picks the fastest paid host, `:floor` the cheapest paid). Never forwarded.
const PAID_VARIANT_SUFFIX = /:(online|nitro|floor)$/i;
const MAX_TOKENS_CAP = 8192;
const UPSTREAM_MODELS = 'https://openrouter.ai/api/v1/models';
const UPSTREAM_KEY = 'https://openrouter.ai/api/v1/key';

/** OpenRouter's own router can pick a paid model — never allowlisted. */
const AUTO_ROUTER = /^openrouter\/auto(?:$|[-/:])/i;

// Attribution headers OpenRouter uses for app ranking/limits.
const ATTRIBUTION_HEADERS = {
  'HTTP-Referer': 'https://create.gashotech.com',
  'X-Title': 'GashoTech Create',
};

type UpstreamModel = {
  id?: unknown;
  name?: unknown;
  pricing?: unknown;
  architecture?: { output_modalities?: unknown };
};

type ModelInfo = {
  id: string;
  name: string;
  free: boolean;
  /** Free without `:free`: a cloaked/stealth id — usually logs prompts for training. */
  stealth: boolean;
  promptPrice: string;
  completionPrice: string;
};

const MODELS_TTL_MS = 30 * 60 * 1000;
let modelsCache: { at: number; models: UpstreamModel[] } | null = null;
/** Models that reported a non-zero cost. Instance-local, fail-closed. */
const paidModels = new Set<string>();

const fetchUpstreamModels = async (): Promise<UpstreamModel[]> => {
  if (modelsCache && Date.now() - modelsCache.at < MODELS_TTL_MS) return modelsCache.models;
  try {
    const res = await fetch(UPSTREAM_MODELS, { headers: { Accept: 'application/json' } });
    if (!res.ok) throw new Error(`models HTTP ${res.status}`);
    const payload = (await res.json()) as { data?: unknown };
    const models = Array.isArray(payload.data) ? (payload.data as UpstreamModel[]) : [];
    if (models.length === 0) throw new Error('models list empty');
    modelsCache = { at: Date.now(), models };
    return models;
  } catch (error) {
    // A failed refresh keeps serving the last good list; with no list at all
    // the caller fails closed (503).
    if (modelsCache) return modelsCache.models;
    throw error;
  }
};

/** Text-output models only: absent modality data is kept, anything that can
 *  emit audio/image/video is not a chat model and is dropped. */
const isTextModel = (m: UpstreamModel): boolean => {
  const out = m.architecture?.output_modalities;
  if (!Array.isArray(out) || out.length === 0) return true;
  return out.every((modality) => modality === 'text');
};

/**
 * Free/stealth = EVERY pricing field is zero or absent: prompt, completion,
 * request, image, web_search, internal_reasoning, input_cache_read,
 * input_cache_write, audio — and any field OpenRouter adds later (the loop
 * checks them all, so a new cost field fails closed).
 */
const hasZeroPricing = (m: UpstreamModel): boolean => {
  const pricing = m.pricing;
  if (pricing === undefined || pricing === null) return true;
  if (typeof pricing !== 'object') return false;
  return Object.values(pricing as Record<string, unknown>).every(
    (value) => value === undefined || value === null || value === '' || Number(value) === 0
  );
};

const isAllowlisted = (m: UpstreamModel): boolean =>
  typeof m.id === 'string' &&
  isTextModel(m) &&
  hasZeroPricing(m) &&
  !AUTO_ROUTER.test(m.id) &&
  !PAID_VARIANT_SUFFIX.test(m.id) &&
  !paidModels.has(m.id);

const toModelInfo = (m: UpstreamModel): ModelInfo => {
  const id = String(m.id);
  return {
    id,
    name: typeof m.name === 'string' ? m.name : id,
    free: true,
    // `openrouter/*` ids are OpenRouter's own free routes, not cloaked models.
    stealth: !id.endsWith(':free') && !id.startsWith('openrouter/'),
    promptPrice: String((m.pricing as { prompt?: unknown } | undefined)?.prompt ?? '0'),
    completionPrice: String((m.pricing as { completion?: unknown } | undefined)?.completion ?? '0'),
  };
};

/** The one allowlist both modes share. Throws only when there is no list at all. */
const allowlistedModels = async (): Promise<ModelInfo[]> =>
  (await fetchUpstreamModels()).filter(isAllowlisted).map(toModelInfo);

/**
 * A free model that reports a cost was billed anyway: WARN (model id only,
 * never the key) and denylist it. Reads the stream tail, where OpenRouter puts
 * the final usage chunk.
 * shortcut: only cost inside a flat `usage` object is detected, compact JSON.
 */
const noteUsageCost = (model: string, text: string): void => {
  const match = /"usage"\s*:\s*\{[^{}]*?"cost"\s*:\s*([0-9.eE+-]+)/.exec(text);
  if (match && Number(match[1]) > 0) {
    paidModels.add(model);
    console.warn(`[openrouter] non-zero cost reported for ${model} — denylisted`);
  }
};

/** Passes the upstream stream through untouched while watching its tail. */
const guardStream = (body: ReadableStream<Uint8Array>, model: string): ReadableStream<Uint8Array> => {
  const decoder = new TextDecoder();
  let tail = '';
  return body.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        controller.enqueue(chunk);
        tail = (tail + decoder.decode(chunk, { stream: true })).slice(-4096);
      },
      flush() {
        noteUsageCost(model, tail + decoder.decode());
      },
    })
  );
};

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

  const apiKey = userKey || process.env.OPENROUTER_API_KEY;
  if (!apiKey) {
    // Never fall back silently to Chutes (spec: free mode is a distinct mode).
    return json({ error: 'OpenRouter free mode not configured' }, 503);
  }

  // Free/stealth allowlist in BOTH modes: a BYO key buys the user's own rate
  // limit, never a paid model (owner decision 2026-11-27).
  let allowed: Set<string>;
  try {
    allowed = new Set((await allowlistedModels()).map((m) => m.id));
  } catch {
    // No list at all -> fail closed.
    return json({ error: 'OpenRouter model list unavailable' }, 503);
  }
  if (allowed.size === 0) {
    return json({ error: 'OpenRouter model list unavailable' }, 503);
  }
  if (PAID_VARIANT_SUFFIX.test(model) || !allowed.has(model)) {
    return json({ error: 'Model not available — free or stealth models only' }, 400);
  }

  // Relay chat fields only: OpenRouter `plugins`/`provider` extras can spend the
  // key on paid features the app never asked for (AEGIS H-1).
  const relayBody: Record<string, unknown> = {};
  for (const field of ALLOWED_CHAT_FIELDS) {
    const value = (chatBody as Record<string, unknown>)[field];
    if (value !== undefined) relayBody[field] = value;
  }
  relayBody.stream = (chatBody as { stream?: unknown }).stream !== false;
  if (typeof relayBody.max_tokens === 'number' && Number.isFinite(relayBody.max_tokens)) {
    relayBody.max_tokens = Math.min(Math.max(1, Math.floor(relayBody.max_tokens)), MAX_TOKENS_CAP);
  } else {
    delete relayBody.max_tokens;
  }
  // Hard upstream budget guard: OpenRouter refuses to route to anything that
  // costs money, whatever the model id says (D2d).
  relayBody.provider = { max_price: { prompt: 0, completion: 0, request: 0, image: 0 } };
  relayBody.usage = { include: true };

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
  if (relayBody.stream === false || !upstream.body) {
    const text = await upstream.text();
    noteUsageCost(model, text);
    return new Response(text, { status: upstream.status, headers });
  }
  return new Response(guardStream(upstream.body, model), { status: upstream.status, headers });
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
      models = await allowlistedModels();
    } catch {
      return json({ error: 'OpenRouter model list unavailable' }, 503);
    }
    // `:free` ids first: they are the ones with a published free pool.
    models.sort((a, b) => Number(a.stealth) - Number(b.stealth));
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
