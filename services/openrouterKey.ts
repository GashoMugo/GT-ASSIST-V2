/**
 * Bring-your-own OpenRouter key storage.
 *
 * Contract (spec 2026-11-27): the key lives ONLY in this browser's
 * localStorage. It is never sent to our servers except per request in the
 * `X-OpenRouter-Key` header, and is never written to Supabase, modelCallLog,
 * a URL, or an error message.
 *
 * Pure module (no imports) so the smoke test can bundle it standalone.
 */

export const OPENROUTER_KEY_STORAGE = 'openrouter_api_key';

/** localStorage when present (browser). Tests stub globalThis.localStorage. */
const store = (): Storage | null => {
  try {
    return typeof localStorage === 'undefined' ? null : localStorage;
  } catch {
    return null;
  }
};

export const getOpenRouterKey = (): string => store()?.getItem(OPENROUTER_KEY_STORAGE)?.trim() || '';

export const setOpenRouterKey = (key: string): void => {
  const trimmed = (key || '').trim();
  if (trimmed) store()?.setItem(OPENROUTER_KEY_STORAGE, trimmed);
  else store()?.removeItem(OPENROUTER_KEY_STORAGE);
};

export const clearOpenRouterKey = (): void => {
  store()?.removeItem(OPENROUTER_KEY_STORAGE);
};

/** `sk-or-v1-…1234` — enough to recognise the key, never enough to use it. */
export const maskOpenRouterKey = (key: string): string => {
  const trimmed = (key || '').trim();
  if (!trimmed) return '';
  if (trimmed.length <= 12) return '••••';
  return `${trimmed.slice(0, 6)}…${trimmed.slice(-4)}`;
};
