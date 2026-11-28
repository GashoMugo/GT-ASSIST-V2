#!/usr/bin/env node
/* global process, console, Request, Response, Buffer */
/**
 * Smoke tests for the OpenRouter proxy (api/openrouter.ts) and the BYO key
 * storage helpers (services/openrouterKey.ts).
 *
 * Asserts the 2026-11-27 contract: named Vercel exports, same inlined Clerk
 * session block as api/chutes.ts, session required on every endpoint, the
 * server key can never reach a paid or non-text model, a missing server key is
 * a 503 (never a Chutes fallback), the BYO header is forwarded upstream and
 * never echoed/logged, the free filter excludes priced/non-text models, and
 * the client key mask/storage behave. No network access, no real keys.
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

  // The BYO key must never be written anywhere a log can see it.
  for (const file of ['api/openrouter.ts', 'services/openrouter.ts']) {
    const src = readFileSync(join(root, file), 'utf8');
    assert.ok(!/console\.(log|info|warn|error|debug)/.test(src), `${file}: must not log (the BYO key rides in headers)`);
  }
  console.log('PASS no logging in the OpenRouter path');

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
  const validToken = mintToken();
  const auth = { authorization: 'Bearer ' + validToken };

  // ---- Upstream stubs
  const calls = [];
  const MODELS = [
    { id: 'free/text-model:free', name: 'Free Text', pricing: { prompt: '0', completion: '0' }, architecture: { output_modalities: ['text'] } },
    { id: 'paid/text-model', name: 'Paid Text', pricing: { prompt: '0.000001', completion: '0.000002' }, architecture: { output_modalities: ['text'] } },
    { id: 'zero/priced-model', name: 'Zero Priced', pricing: { prompt: '0', completion: '0' }, architecture: { output_modalities: ['text'] } },
    { id: 'free/image-model:free', name: 'Free Image', pricing: { prompt: '0', completion: '0' }, architecture: { output_modalities: ['image'] } },
  ];
  let chatResponse = () => new Response('data: {"choices":[{"delta":{"content":"hi"}}]}\n\ndata: [DONE]\n', {
    status: 200,
    headers: { 'content-type': 'text/event-stream' },
  });
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ url: String(url), init });
    if (String(url).includes('/api/v1/models')) {
      return new Response(JSON.stringify({ data: MODELS }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
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

  // ---- Server mode: paid model is refused, free model runs on the server key
  process.env.OPENROUTER_API_KEY = SERVER_KEY;
  res = await mod.POST(post({ body: { model: 'paid/text-model', messages: [] } }));
  assert.equal(res.status, 400, 'server mode + paid model -> 400');
  assert.equal((await res.json()).error, 'Model not available in free mode');
  // A non-text (image) model must also be refused even though it is free.
  res = await mod.POST(post({ body: { model: 'free/image-model:free', messages: [] } }));
  assert.equal(res.status, 400, 'server mode + non-text model -> 400');

  before = calls.length;
  res = await mod.POST(post({ body: { model: 'zero/priced-model', messages: [{ role: 'user', content: 'hi' }], max_tokens: 10, plugins: [{ id: 'web' }] } }));
  assert.equal(res.status, 200, 'server mode + free model -> 200');
  assert.equal(await res.text(), 'data: {"choices":[{"delta":{"content":"hi"}}]}\n\ndata: [DONE]\n', 'SSE passthrough');
  const serverCall = calls[before];
  assert.equal(serverCall.init.headers.Authorization, 'Bearer ' + SERVER_KEY, 'server key injected upstream');
  const sentBody = JSON.parse(serverCall.init.body);
  assert.equal(sentBody.model, 'zero/priced-model');
  assert.equal(sentBody.stream, true);
  assert.equal(sentBody.max_tokens, 10, 'chat fields are relayed');
  assert.equal(sentBody.plugins, undefined, 'non-chat fields (plugins) are dropped');
  assert.ok(!JSON.stringify(serverCall).includes(USER_KEY), 'user key never used in server mode');
  console.log('PASS server mode: free-only allowlist, server key injected, SSE passthrough');

  // ---- BYO mode: header forwarded, never echoed
  before = calls.length;
  res = await mod.POST(post({ body: { model: 'paid/text-model', messages: [] } }, { 'x-openrouter-key': USER_KEY }));
  assert.equal(res.status, 200, 'BYO + paid model -> 200');
  assert.equal(calls[before].init.headers.Authorization, 'Bearer ' + USER_KEY, 'BYO key forwarded upstream');
  const resText = await res.text();
  assert.ok(!resText.includes(USER_KEY), 'response body must not echo the key');
  for (const [, value] of res.headers) assert.ok(!value.includes(USER_KEY), 'response headers must not echo the key');
  assert.equal(res.headers.get('x-proxy-error'), null, 'success is not a proxy error');

  chatResponse = () => new Response(JSON.stringify({ error: { message: 'No auth credentials found', code: 401 } }), {
    status: 401,
    headers: { 'content-type': 'application/json' },
  });
  res = await mod.POST(post({ body: { model: 'paid/text-model', messages: [] } }, { 'x-openrouter-key': USER_KEY }));
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
  console.log('PASS BYO mode: header forwarded, 401/429 mapped, no key echo');

  // ---- Invalid key header is refused before any upstream call
  res = await mod.POST(post({ body: { model: 'paid/text-model', messages: [] } }, { 'x-openrouter-key': 'bad key with spaces' }));
  assert.equal(res.status, 400);

  // ---- Model list: free + text only in server mode; all text models in BYO
  res = await mod.GET(get('action=models'));
  assert.equal(res.status, 200);
  const serverList = await res.json();
  assert.deepEqual(serverList.models.map((m) => m.id), ['free/text-model:free', 'zero/priced-model']);
  assert.ok(serverList.models.every((m) => m.free), 'server list is free-only');
  assert.ok(!serverList.models.some((m) => m.id === 'free/image-model:free'), 'non-text models are excluded');

  res = await mod.GET(get('action=models', { 'x-openrouter-key': USER_KEY }));
  const byoList = await res.json();
  assert.equal(byoList.mode, 'byok');
  assert.ok(byoList.models.some((m) => m.id === 'paid/text-model'), 'BYO list includes paid models');
  assert.ok(!byoList.models.some((m) => m.id === 'free/image-model:free'), 'BYO list excludes non-text models');
  assert.equal(byoList.models[0].free, true, 'free models sort first in BYO mode');

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
  console.log('PASS models/actions: free+text filter, BYO full list, key test never echoes');

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
