#!/usr/bin/env node
/* global process, console */
/**
 * Unit tests for the chat credit policy (owner decision 2026-11-27, F3):
 *  - Chutes chat deducts the normal chat cost;
 *  - OpenRouter Free (GashoTech's server key) deducts the SAME cost, logged
 *    with an `openrouter_free` model label;
 *  - a BYO OpenRouter key deducts NOTHING (the user's own account pays).
 *
 * Usage: node scripts/credit_policy_smoke.mjs
 */
import assert from 'node:assert';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const root = process.cwd();
const work = mkdtempSync(join(tmpdir(), 'credit-policy-'));
const esbuildBin = join(root, 'node_modules', '.bin', 'esbuild');

if (!existsSync(esbuildBin)) {
  console.error('[credit_policy_smoke] FAIL: esbuild not found — run npm ci first.');
  process.exit(1);
}

try {
  execFileSync(
    esbuildBin,
    ['services/creditCosts.ts', '--bundle', '--format=esm', '--platform=node', '--outfile=' + join(work, 'creditCosts.mjs')],
    { cwd: root, stdio: 'pipe' }
  );
  const { chatCharge } = await import('file://' + join(work, 'creditCosts.mjs'));

  const chutes = chatCharge('chutes', 'Qwen/Qwen3-32B-TEE');
  assert.equal(chutes.amount, 1, 'Chutes chat deducts the normal chat cost');
  assert.equal(chutes.label, 'Qwen/Qwen3-32B-TEE', 'Chutes ledger label is the model id');

  const free = chatCharge('openrouter-free', 'deepseek/deepseek-r1:free');
  assert.equal(free.amount, 1, 'OpenRouter Free (server key) deducts the same chat cost');
  assert.equal(free.label, 'openrouter_free:deepseek/deepseek-r1:free', 'Free mode is labelled openrouter_free:* in the ledger');

  const byok = chatCharge('openrouter-byok', 'deepseek/deepseek-r1:free', true);
  assert.equal(byok.amount, 0, 'BYO key deducts nothing');

  // "My own key" selected but no key saved: the send falls back to the server
  // key, so it must charge like OpenRouter Free (AEGIS H-1).
  const byokNoKey = chatCharge('openrouter-byok', 'deepseek/deepseek-r1:free');
  assert.equal(byokNoKey.amount, 1, 'byok without a saved key charges');
  assert.equal(byokNoKey.label, 'openrouter_free:deepseek/deepseek-r1:free', 'and is labelled as server-keyed');

  // Unknown/legacy provider: fail closed (charge), never silently free.
  assert.equal(chatCharge(undefined, 'legacy-model').amount, 1, 'missing provider still charges');

  console.log('PASS credits: chutes=1, openrouter-free=1 (labelled), byok=0');
} finally {
  rmSync(work, { recursive: true, force: true });
}
