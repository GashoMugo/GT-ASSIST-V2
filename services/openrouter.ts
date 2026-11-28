/**
 * OpenRouter chat client (spec 2026-11-27).
 *
 * Lives beside services/chutes.ts and reuses its whole streaming path: this
 * class only swaps the proxy endpoint and auth shape, so the chat UI, cache,
 * tool loop and model-call logging stay identical for both providers.
 *
 * - Server-key mode (`openrouter-free`): no key on the client; /api/openrouter
 *   injects OPENROUTER_API_KEY and restricts the model to the free allowlist.
 * - BYO mode (`openrouter-byok`): the key is read from localStorage and sent
 *   ONLY as the `X-OpenRouter-Key` header on that request.
 */

import { AppSettings } from '../types';
import { ChutesService } from './chutes';
import { authHeaders } from './authToken';
import { getOpenRouterKey } from './openrouterKey';
import type { ModelCallMode } from './modelCallLog';

const PROXY_URL = '/api/openrouter';
const MODELS_TTL_MS = 60 * 60 * 1000;

export type OpenRouterModel = {
  id: string;
  name: string;
  free: boolean;
  promptPrice: string;
  completionPrice: string;
};

type ModelCallInfo = { mode: ModelCallMode; model: string; prompt: string };

const modelsCache = new Map<string, { at: number; models: OpenRouterModel[] }>();

/** Model list for the picker (cached ~1h per mode). */
export const fetchOpenRouterModels = async (userKey = ''): Promise<OpenRouterModel[]> => {
  const cacheKey = userKey ? 'byok' : 'server';
  const hit = modelsCache.get(cacheKey);
  if (hit && Date.now() - hit.at < MODELS_TTL_MS) return hit.models;

  const headers: Record<string, string> = { ...(await authHeaders()) };
  if (userKey) headers['X-OpenRouter-Key'] = userKey;

  const res = await fetch(`${PROXY_URL}?action=models`, { headers });
  if (!res.ok) {
    throw new Error(res.status === 503 ? 'OpenRouter free mode not configured' : `Model list unavailable (HTTP ${res.status})`);
  }
  const data = (await res.json()) as { models?: OpenRouterModel[] };
  const models = Array.isArray(data.models) ? data.models : [];
  modelsCache.set(cacheKey, { at: Date.now(), models });
  return models;
};

/** Validate a BYO key server-side (/api/v1/key) without ever storing it. */
export const testOpenRouterKey = async (key: string): Promise<{ valid: boolean; message: string }> => {
  const headers: Record<string, string> = { ...(await authHeaders()), 'X-OpenRouter-Key': key.trim() };
  let data: { valid?: boolean; error?: string; label?: unknown; limit_remaining?: unknown };
  try {
    const res = await fetch(`${PROXY_URL}?action=test-key`, { headers });
    data = (await res.json()) as typeof data;
  } catch {
    return { valid: false, message: 'Could not reach the server' };
  }
  if (!data.valid) return { valid: false, message: data.error || 'Key rejected' };
  const remaining = typeof data.limit_remaining === 'number' ? ` — ${data.limit_remaining} credits remaining` : '';
  return { valid: true, message: `Valid${remaining}` };
};

/** Turn raw proxy errors into the exact user-facing hints in the spec. */
export const describeOpenRouterError = (error: unknown): string => {
  const raw = error instanceof Error ? error.message : String(error);
  const status = /LLM Error: (\d{3})/.exec(raw)?.[1];
  if (status === '429') return 'Free daily limit reached — add your own OpenRouter key in Settings or try later';
  if (status === '401' || status === '403') return 'Key rejected — check your OpenRouter key in Settings';
  if (status === '503') return 'OpenRouter free mode is not configured yet — add your own OpenRouter key in Settings or try later';
  return raw;
};

export class OpenRouterService extends ChutesService {
  private readonly byoKey: string;

  constructor(key = '') {
    // The platform key never exists on the client; the proxy owns it.
    super('internal');
    this.byoKey = (key || '').trim();
  }

  protected async proxyFetch(_targetUrl: string, body: unknown, call: ModelCallInfo, signal?: AbortSignal): Promise<Response> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json', ...(await authHeaders()) };
    if (this.byoKey) headers['X-OpenRouter-Key'] = this.byoKey;
    return this.loggedCall(call, () =>
      this.fetchWithRetry(PROXY_URL, {
        method: 'POST',
        headers,
        body: JSON.stringify({ body }),
        signal,
      })
    );
  }
}

export const getAppOpenRouterService = (settings: AppSettings): OpenRouterService =>
  new OpenRouterService(settings.provider === 'openrouter-byok' ? getOpenRouterKey() : '');

/** Selected model, or the first model in the provider's list when none is set. */
export const resolveOpenRouterModel = async (settings: AppSettings): Promise<string> => {
  if (settings.openrouterModel) return settings.openrouterModel;
  const models = await fetchOpenRouterModels(settings.provider === 'openrouter-byok' ? getOpenRouterKey() : '');
  if (models.length === 0) throw new Error('No OpenRouter models available');
  return models[0].id;
};
