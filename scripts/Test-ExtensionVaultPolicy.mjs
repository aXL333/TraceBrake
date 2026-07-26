import assert from 'node:assert/strict';
import { vaultRefs, buildVaultFillPolicy } from '../extension/vault-policy.mjs';

const mixed = vaultRefs(
    '{{vault:shop.example/login01/password}} {{vault:shop.example/card0001/cardnumber}}');
const policy = buildVaultFillPolicy(mixed, 'https://shop.example');

assert.equal(policy.requiredAutocomplete, '__invalid__');
assert.equal(policy.requirePasswordField, false);
console.log('Extension vault policy bypass test passed: mixed password/card references fail card policy.');
