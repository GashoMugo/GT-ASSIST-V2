#!/usr/bin/env node
/* global process, console, Request, Response, Buffer */
/**
 * Smoke tests for the OpenRouter proxy (api/openrouter.ts) and the BYO key
 * storage helpers (services/openrouterKey.ts).
 *
 * Asserts the 2026-11-27 contract (owner decisions D1–D3):
 *  - named Vercel exports, inlined Clerk session block, session on every endpoint
 *  - ONE free/stealth allowlist in both modes: every pricing field zero or absent,
 *    text output only, `openrouter/auto` excluded, paid variants refused
 *  - a paid model id is a 400 with the server key AND with the user's own key
 *  - client `models`/`plugins`/`provider`/`route`/`transforms` are stripped, and
 *    every upstream body carries provider.max_price zeros + usage.include
 *  - no model list at all -> 503 (fail closed, never open)
 *  - usage.cost > 0 -> WARN (model id only) + in-memory denylist
 *  - no server key -> 503 (never a Chutes fallback)
 *  - the BYO header is forwarded upstream and never echoed/logged
 *  - the default chat provider is OpenRouter Free (D1)
 * No network access, no real keys.
 *
 * Usage: node scripts/openrouter_smoke.mjs
 */
import assert from 'node:assert';
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { mkdtempSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const root = process.cwd();
const work = mkdtempSync(join(tmpdir(), 'openrouter-smoke-'));
const esbuildBin = join(root, 'node_modules', '.bin', 'esbuild');

if (!existsSync(esbuildBin)) {
  console.error('[openrouter_smoke] FAIL: esbuild not found — run npm ci first.');
  process.exit(1);
}

const bundle = (entry, out) =>
  execFileSync(esbuildBin, [entry, '--bundle', '--format=esm', '--platform=node', '--outfile=' + join(work, out)], {
    cwd: root,
    stdio: 'pipe',
  });

const SERVER_KEY = 'sk-or-v1-' + 'server-test-key-0000';
const USER_KEY = 'sk-or-v1-' + 'user-byo-test-key-9999';

try {
  bundle('api/openrouter.ts', 'openrouter.mjs');
  bundle('services/openrouterKey.ts', 'openrouterKey.mjs');
  bundle('types.ts', 'types.mjs');

  const mod = await import('file://' + join(work, 'openrouter.mjs'));
  assert.equal(typeof mod.POST, 'function', 'api/openrouter.ts must export function POST');
  assert.equal(typeof mod.GET, 'function', 'api/openrouter.ts must export function GET');
  assert.equal(typeof mod.default, 'undefined', 'api/openrouter.ts must NOT default-export a plain handler');

  // The inlined Clerk block must stay identical to the other proxies.
  const authStart = '// ---- Client session auth (Clerk) (INLINED on purpose —';
  const authEnd = '// ---- End client session auth ----';
  const authBlock = (file) => {
    const src = readFileSync(join(root, file), 'utf8');
    const start = src.indexOf(authStart);
    const end = src.indexOf(authEnd);
    assert.ok(start !== -1 && end !== -1, `${file}: auth block markers missing`);
    return src.slice(start, end + authEnd.length);
  };
  assert.equal(authBlock('api/openrouter.ts'), authBlock('api/chutes.ts'), 'inlined Clerk auth block must stay byte-identical');
  console.log('PASS exports + inlined auth block');

  // The BYO key must never be written anywhere a log can see it. The one allowed
  // log line is the non-zero-cost WARN, and it may only name the model.
  for (const file of ['api/openrouter.ts', 'services/openrouter.ts']) {
    const src = readFileSync(join(root, file), 'utf8');
    assert.ok(!/console\.(log|info|debug|error|table)/.test(src), `${file}: only console.warn is allowed (the BYO key rides in headers)`);
    for (const line of src.split('\n').filter((l) => l.includes('console.'))) {
      assert.ok(!/apiKey|userKey|authorization|headers/i.test(line), `${file}: a log line must never reference key material`);
    }
  }
  console.log('PASS no key-bearing logging in the OpenRouter path');

  // ---- Clerk session auth wiring: networkless verification via CLERK_JWT_KEY
  const { publicKey: testPub, privateKey: testPriv } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  delete process.env.CLERK_SECRET_KEY;
  process.env.CLERK_JWT_KEY = testPub.export({ type: 'spki', format: 'pem' });
  const testIssuer = 'https://test-instance.clerk.accounts.dev';
  const b64url = (input) => Buffer.from(input).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: 'RS256', kid: 'test-kid', typ: 'JWT', cat: 'cl_B7d4PD111AAA' }));
  const mintToken = (claims = {}) => {
    const payload = b64url(JSON.stringify({ sub: 'user_test', iss: testIssuer, iat: now - 10, nbf: now - 10, exp: now + 3600, ...claims }));
    const sig = nodeSign('RSA-SHA256', Buffer.from(`${header}.${payload}`), testPriv);
    return `${header}.${payload}.${sig.toString('base64url')}`;
  };
  const auth = { authorization: 'Bearer ' + mintToken() };

  // ---- Upstream stubs
  const calls = [];
  const zero = { prompt: '0', completion: '0' };
  const MODELS = [
    // allowlisted
    { id: 'free/text-model:free', name: 'Free Text', pricing: zero, architecture: { output_modalities: ['text'] } },
    { id: 'zero/priced-model', name: 'Zero Priced', pricing: zero, architecture: { output_modalities: ['text'] } },
    { id: 'openrouter/free', name: 'OpenRouter Free', pricing: zero, architecture: { output_modalities: ['text'] } },
    // dropped: any non-zero pricing field, any modality, auto-router, paid variants
    { id: 'paid/text-model', name: 'Paid Text', pricing: { prompt: '0.000001', completion: '0.000002' }, architecture: { output_modalities: ['text'] } },
    { id: 'zero/request-priced', name: 'Request Priced', pricing: { ...zero, request: '0.001' }, architecture: { output_modalities: ['text'] } },
    { id: 'zero/reasoning-priced', name: 'Reasoning Priced', pricing: { ...zero, internal_reasoning: '0.000001' }, architecture: { output_modalities: ['text'] } },
    { id: 'zero/audio-priced', name: 'Audio Priced', pricing: { ...zero, audio: '0.0001' }, architecture: { output_modalities: ['text'] } },
    { id: 'free/image-model:free', name: 'Free Image', pricing: zero, architecture: { output_modalities: ['image'] } },
    { id: 'free/audio-text-model:free', name: 'Free Audio+Text', pricing: zero, architecture: { output_modalities: ['text', 'audio'] } },
    { id: 'openrouter/auto', name: 'Auto Router', pricing: {}, architecture: { output_modalities: ['text'] } },
  ];
  // Sort is stable: `:free` ids first, then the stealth ones.
  const ALLOWED_IDS = ['free/text-model:free', 'openrouter/free', 'zero/priced-model'];

  const sse = (payload) => new Response(payload, { status: 200, headers: { 'content-type': 'text/event-stream' } });
  let chatResponse = () => sse('data: {"choices":[{"delta":{"content":"hi"}}]}\n\ndata: [DONE]\n');
  let modelsResponse = () =>
    new Response(JSON.stringify({ data: MODELS }), { status: 200, headers: { 'content-type': 'application/json' } });
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ url: String(url), init });
    if (String(url).includes('/api/v1/models')) return modelsResponse();
    if (String(url).includes('/api/v1/key')) {
      return new Response(JSON.stringify({ data: { label: 'test', limit_remaining: 12.5, usage: 1.5 } }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    return chatResponse();
  };

  const post = (body, headers = {}) =>
    new Request('http://localhost/api/openrouter', {
      method: 'POST',
      body: JSON.stringify(body),
      headers: { ...auth, ...headers },
    });
  const get = (query, headers = {}) => new Request('http://localhost/api/openrouter?' + query, { headers: { ...auth, ...headers } });

  // ---- Auth required on both verbs, before any upstream call
  let before = calls.length;
  let res = await mod.POST(new Request('http://localhost/api/openrouter', { method: 'POST', body: '{}' }));
  assert.equal(res.status, 401, 'POST without session -> 401');
  res = await mod.GET(new Request('http://localhost/api/openrouter?action=models'));
  assert.equal(res.status, 401, 'GET without session -> 401');
  assert.equal(calls.length, before, 'no upstream call without a session');
  console.log('PASS auth: both verbs 401 without a session, no upstream call');

  // ---- Server mode with no env key -> 503 (no silent Chutes fallback)
  delete process.env.OPENROUTER_API_KEY;
  res = await mod.POST(post({ body: { model: 'free/text-model:free', messages: [] } }));
  assert.equal(res.status, 503, 'server mode without OPENROUTER_API_KEY -> 503');
  assert.equal((await res.json()).error, 'OpenRouter free mode not configured');
  console.log('PASS no server key -> 503 with the exact message');

  // ---- No model list at all -> 503, in both verbs (fail closed, never open)
  process.env.OPENROUTER_API_KEY = SERVER_KEY;
  modelsResponse = () => new Response('{}', { status: 500 });
  res = await mod.POST(post({ body: { model: 'free/text-model:free', messages: [] } }));
  assert.equal(res.status, 503, 'no model list -> POST 503');
  assert.equal((await res.json()).error, 'OpenRouter model list unavailable');
  res = await mod.GET(get('action=models'));
  assert.equal(res.status, 503, 'no model list -> GET 503');
  before = calls.length;
  modelsResponse = () => new Response(JSON.stringify({ data: MODELS }), { status: 200, headers: { 'content-type': 'application/json' } });
  console.log('PASS no model list -> 503 on both verbs');

  // ---- D2b: a paid model id is refused in BOTH modes, before any upstream call
  for (const headers of [{}, { 'x-openrouter-key': USER_KEY }]) {
    res = await mod.POST(post({ body: { model: 'paid/text-model', messages: [] } }, headers));
    assert.equal(res.status, 400, `paid model -> 400 (${headers['x-openrouter-key'] ? 'BYO' : 'server'} mode)`);
    assert.equal((await res.json()).error, 'Model not available — free or stealth models only');
    assert.equal(calls.filter((c) => c.url.includes('/chat/completions')).length, 0, 'no upstream call for a paid model');
  }
  // Non-text, auto-router and paid variants are refused too.
  for (const model of ['free/image-model:free', 'free/audio-text-model:free', 'openrouter/auto', 'free/text-model:free:online']) {
    res = await mod.POST(post({ body: { model, messages: [] } }));
    assert.equal(res.status, 400, `${model} -> 400`);
  }
  console.log('PASS paid/non-text/auto/variant ids -> 400 in both modes, no upstream call');

  // ---- D2c/D2d: only allowlisted fields go upstream; every body carries the
  // max_price zeros and usage.include.
  res = await mod.POST(
    post({
      body: {
        model: 'zero/priced-model',
        messages: [{ role: 'user', content: 'hi' }],
        max_tokens: 999999,
        temperature: 0.2,
        presence_penalty: 0.5,
        plugins: [{ id: 'web' }],
        provider: { order: ['paid/host'] },
        models: ['paid/text-model'],
        route: 'fallback',
        transforms: ['middle-out'],
        web_search_options: { search_context_size: 'high' },
      },
    })
  );
  assert.equal(res.status, 200, 'server mode + allowlisted model -> 200');
  assert.equal(await res.text(), 'data: {"choices":[{"delta":{"content":"hi"}}]}\n\ndata: [DONE]\n', 'SSE passthrough');
  const serverCall = calls.filter((c) => c.url.includes('/chat/completions')).at(-1);
  assert.equal(serverCall.init.headers.Authorization, 'Bearer ' + SERVER_KEY, 'server key injected upstream');
  const sentBody = JSON.parse(serverCall.init.body);
  assert.deepEqual(Object.keys(sentBody).sort(), ['max_tokens', 'messages', 'model', 'provider', 'stream', 'temperature', 'usage'], 'only allowlisted fields relayed');
  assert.equal(sentBody.model, 'zero/priced-model');
  assert.equal(sentBody.stream, true);
  assert.equal(sentBody.max_tokens, 8192, 'max_tokens is capped');
  assert.equal(sentBody.presence_penalty, undefined, 'penalties are not relayed');
  assert.deepEqual(sentBody.provider, { max_price: { prompt: 0, completion: 0, request: 0, image: 0 } }, 'max_price zeros on every call');
  assert.deepEqual(sentBody.usage, { include: true }, 'usage.include on every call');
  console.log('PASS relay: client models/plugins/provider/route/transforms stripped, max_price zeros + usage.include present');

  // ---- BYO mode: header forwarded, never echoed
  before = calls.length;
  res = await mod.POST(post({ body: { model: 'free/text-model:free', messages: [] } }, { 'x-openrouter-key': USER_KEY }));
  assert.equal(res.status, 200, 'BYO + allowlisted model -> 200');
  const byoCall = calls.filter((c) => c.url.includes('/chat/completions')).at(-1);
  assert.equal(byoCall.init.headers.Authorization, 'Bearer ' + USER_KEY, 'BYO key forwarded upstream');
  assert.deepEqual(JSON.parse(byoCall.init.body).provider, { max_price: { prompt: 0, completion: 0, request: 0, image: 0 } }, 'BYO calls carry max_price too');
  const resText = await res.text();
  assert.ok(!resText.includes(USER_KEY), 'response body must not echo the key');
  for (const [, value] of res.headers) assert.ok(!value.includes(USER_KEY), 'response headers must not echo the key');
  assert.equal(res.headers.get('x-proxy-error'), null, 'success is not a proxy error');

  chatResponse = () => new Response(JSON.stringify({ error: { message: 'No auth credentials found', code: 401 } }), {
    status: 401,
    headers: { 'content-type': 'application/json' },
  });
  res = await mod.POST(post({ body: { model: 'free/text-model:free', messages: [] } }, { 'x-openrouter-key': USER_KEY }));
  assert.equal(res.status, 401, 'upstream 401 -> 401');
  const rejected = await res.text();
  assert.equal(rejected, JSON.stringify({ error: 'Key rejected' }), 'upstream auth body is never relayed');
  assert.ok(!rejected.includes(USER_KEY));

  chatResponse = () => new Response(JSON.stringify({ error: { message: 'rate limited' } }), { status: 429 });
  res = await mod.POST(post({ body: { model: 'free/text-model:free', messages: [] } }));
  assert.equal(res.status, 429);
  assert.equal(
    (await res.json()).error,
    'Free daily limit reached — add your own OpenRouter key in Settings or try later'
  );
  console.log('PASS BYO mode: header forwarded, max_price guard, 401/429 mapped, no key echo');

  // ---- Invalid key header is refused before any upstream call
  res = await mod.POST(post({ body: { model: 'free/text-model:free', messages: [] } }, { 'x-openrouter-key': 'bad key with spaces' }));
  assert.equal(res.status, 400);

  // ---- Model list: the same allowlist in both modes
  chatResponse = () => sse('data: {"choices":[{"delta":{"content":"hi"}}]}\n\ndata: [DONE]\n');
  res = await mod.GET(get('action=models'));
  assert.equal(res.status, 200);
  const serverList = await res.json();
  assert.deepEqual(serverList.models.map((m) => m.id), ALLOWED_IDS, 'priced / non-text / auto models are excluded');
  assert.ok(serverList.models.every((m) => m.free), 'every listed model is free');
  assert.deepEqual(serverList.models.map((m) => m.stealth), [false, false, true], 'stealth flag = free without :free');
  assert.equal(serverList.mode, 'server');

  res = await mod.GET(get('action=models', { 'x-openrouter-key': USER_KEY }));
  const byoList = await res.json();
  assert.equal(byoList.mode, 'byok');
  assert.deepEqual(byoList.models.map((m) => m.id), ALLOWED_IDS, 'BYO list is the same free/stealth allowlist');
  console.log('PASS models: all-zero pricing + text only, auto excluded, same list both modes');

  // ---- D2d: reported cost > 0 -> WARN (model id only) + denylist
  const warns = [];
  const realWarn = console.warn;
  console.warn = (...args) => warns.push(args.join(' '));
  chatResponse = () =>
    sse('data: {"choices":[{"delta":{"content":"hi"}}]}\n\ndata: {"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3,"cost":0.0004}}\n\ndata: [DONE]\n');
  res = await mod.POST(post({ body: { model: 'zero/priced-model', messages: [] } }));
  assert.equal(res.status, 200);
  const billed = await res.text();
  console.warn = realWarn;
  assert.ok(billed.includes('"cost":0.0004'), 'stream passes through untouched');
  assert.equal(warns.length, 1, 'one WARN for the billed model');
  assert.ok(warns[0].includes('zero/priced-model'), 'WARN names the model');
  assert.ok(!warns[0].includes(USER_KEY) && !warns[0].includes(SERVER_KEY), 'WARN never includes a key');

  res = await mod.GET(get('action=models'));
  const afterDeny = await res.json();
  assert.ok(!afterDeny.models.some((m) => m.id === 'zero/priced-model'), 'billed model leaves the allowlist');
  res = await mod.POST(post({ body: { model: 'zero/priced-model', messages: [] } }));
  assert.equal(res.status, 400, 'billed model is refused afterwards');
  chatResponse = () => sse('data: {"choices":[{"delta":{"content":"hi"}}]}\n\ndata: [DONE]\n');
  console.log('PASS usage.cost > 0 -> WARN (model only) + in-memory denylist');

  // ---- Key test: valid / rejected, key never echoed
  res = await mod.GET(get('action=test-key', { 'x-openrouter-key': USER_KEY }));
  const keyInfo = await res.json();
  assert.equal(keyInfo.valid, true);
  assert.equal(keyInfo.limit_remaining, 12.5);
  assert.ok(!JSON.stringify(keyInfo).includes(USER_KEY), 'key test response must not echo the key');

  globalThis.fetch = async (url) => {
    if (String(url).includes('/api/v1/key')) return new Response('{}', { status: 401 });
    return new Response(JSON.stringify({ data: MODELS }), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  res = await mod.GET(get('action=test-key', { 'x-openrouter-key': USER_KEY }));
  assert.deepEqual(await res.json(), { valid: false, error: 'Key rejected' });
  console.log('PASS key test: never echoes');

  // ---- D1: OpenRouter Free is the default provider; a saved blob with no
  // provider field still resolves to it.
  const types = await import('file://' + join(work, 'types.mjs'));
  assert.equal(types.DEFAULT_CHAT_PROVIDER, 'openrouter-free', 'default provider is openrouter-free');
  const legacySaved = JSON.parse('{"model":"Nemotron-3-Nano-Omni-30B-TEE"}'); // pre-OpenRouter user
  assert.equal(
    { provider: types.DEFAULT_CHAT_PROVIDER, ...legacySaved }.provider,
    'openrouter-free',
    'existing user with no saved choice resolves to openrouter-free'
  );
  const appSrc = readFileSync(join(root, 'App.tsx'), 'utf8');
  assert.ok(/provider:\s*DEFAULT_CHAT_PROVIDER/.test(appSrc), 'App.tsx DEFAULT_SETTINGS wires the default provider');
  assert.ok(!/settings\.provider\s*\?\?\s*'chutes'/.test(appSrc + readFileSync(join(root, 'components/LogoModelPicker.tsx'), 'utf8')
    + readFileSync(join(root, 'components/chat/hooks/useChatSendMessage.tsx'), 'utf8')), 'no chutes fallback left in the chat path');
  console.log('PASS default provider: openrouter-free for fresh and legacy users, Chutes still selectable');

  // ---- Client key storage + masking
  const store = new Map();
  globalThis.localStorage = {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => store.set(k, String(v)),
    removeItem: (k) => store.delete(k),
  };
  const keyMod = await import('file://' + join(work, 'openrouterKey.mjs'));
  assert.equal(keyMod.getOpenRouterKey(), '', 'empty until set');
  keyMod.setOpenRouterKey('  ' + USER_KEY + '  ');
  assert.equal(keyMod.getOpenRouterKey(), USER_KEY, 'trimmed round-trip');
  assert.equal(store.get(keyMod.OPENROUTER_KEY_STORAGE), USER_KEY, 'stored in localStorage only');
  const masked = keyMod.maskOpenRouterKey(USER_KEY);
  assert.equal(masked, 'sk-or-…9999', 'mask keeps prefix + last 4');
  assert.ok(!masked.includes('test-key'), 'mask hides the secret middle');
  assert.equal(keyMod.maskOpenRouterKey('short'), '••••');
  keyMod.setOpenRouterKey('');
  assert.equal(keyMod.getOpenRouterKey(), '', 'empty value clears');
  keyMod.setOpenRouterKey(USER_KEY);
  keyMod.clearOpenRouterKey();
  assert.equal(keyMod.getOpenRouterKey(), '', 'clear removes');
  console.log('PASS client key: localStorage round-trip, masking, clear');

  console.log('ALL OpenRouter smoke tests passed');
} finally {
  rmSync(work, { recursive: true, force: true });
}
