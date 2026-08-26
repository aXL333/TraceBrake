import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const source = await readFile(new URL('../extension/background.js', import.meta.url), 'utf8');

test('browser executor claims at most one action per poll', () => {
  assert.match(source, /mcpCall\('cu_poll_actions',\s*\{\s*limit:\s*1\s*\}\)/);
  assert.doesNotMatch(source, /mcpCall\('cu_poll_actions',\s*\{\s*limit:\s*[2-9]/);
});

test('execution liveness guard binds panic, action state, and lease', () => {
  const guard = source.match(/async function ensureCuActionLive\(act\)\s*\{[\s\S]*?\n\}/)?.[0] ?? '';
  assert.match(guard, /computer_use_status/);
  assert.match(guard, /panic\.halted !== false/);
  assert.match(guard, /cu_action_status/);
  assert.match(guard, /executionToken/);
  assert.match(guard, /state \|\| ''\)\.toLowerCase\(\) !== 'executing'/);
});

test('every browser effect is preceded by a fresh liveness check', () => {
  const guardedEffects = [
    /ensureCuActionLive\(act\)[\s\S]{0,180}chrome\.tabs\.create/,
    /ensureCuActionLive\(act\)[\s\S]{0,180}chrome\.tabs\.update/,
    /ensureCuActionLive\(act\)[\s\S]{0,220}chrome\.tabs\.goBack/,
    /ensureCuActionLive\(act\)[\s\S]{0,260}chrome\.tabs\.goForward/,
    /ensureCuActionLive\(act\)[\s\S]{0,220}func:\s*injFill/,
    /ensureCuActionLive\(act\)[\s\S]{0,220}func:\s*injClick/,
    /ensureCuActionLive\(act\)[\s\S]{0,220}func:\s*injScroll/,
  ];
  for (const contract of guardedEffects) assert.match(source, contract);
});

test('lease is returned only to CU executor APIs', () => {
  assert.match(source, /cu_complete_action'[\s\S]{0,180}executionToken:\s*act\.executionToken/);
  assert.match(source, /cu_resolve_vault'[\s\S]{0,180}executionToken/);
  assert.doesNotMatch(source, /resultJson:[^\n]*executionToken/);
});
