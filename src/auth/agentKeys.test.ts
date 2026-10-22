import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { hashAgentKey, isAgentKeyShaped, loadAgentApiKeys } from './agentKeys.js';

const KEY = `amk_${'ab'.repeat(32)}`;
const HASH = createHash('sha256').update(KEY).digest('hex');
const OTHER_HASH = createHash('sha256').update('something else').digest('hex');

const env = (keys: unknown, authMode = 'oidc'): NodeJS.ProcessEnv => ({
  AUTH_MODE: authMode,
  AGENT_API_KEYS: typeof keys === 'string' ? keys : JSON.stringify(keys)
});

test('loadAgentApiKeys returns undefined when AGENT_API_KEYS is unset or blank', () => {
  assert.equal(loadAgentApiKeys({ AUTH_MODE: 'oidc' }), undefined);
  assert.equal(loadAgentApiKeys({ AUTH_MODE: 'oidc', AGENT_API_KEYS: '   ' }), undefined);
});

test('loadAgentApiKeys parses named entries into hash buffers and tokens', () => {
  const keys = loadAgentApiKeys(
    env({
      'devops-agent': { keySha256: HASH, argocdToken: 'argo-token-1' },
      'oncall-bot': { keySha256: OTHER_HASH, argocdToken: 'argo-token-2' }
    })
  );
  assert.ok(keys);
  assert.deepEqual(
    keys.map((k) => k.name),
    ['devops-agent', 'oncall-bot']
  );
  assert.equal(keys[0].keySha256.toString('hex'), HASH);
  assert.equal(keys[0].argocdToken, 'argo-token-1');
  assert.equal(keys[1].argocdToken, 'argo-token-2');
});

test('loadAgentApiKeys refuses invalid JSON, naming the variable but never the input', () => {
  assert.throws(
    () => loadAgentApiKeys(env('{"a": {"argocdToken": "SECRET-FRAGMENT" oops')),
    (e: unknown) => {
      assert.ok(e instanceof Error);
      assert.match(e.message, /AGENT_API_KEYS/);
      assert.doesNotMatch(e.message, /SECRET-FRAGMENT/);
      return true;
    }
  );
});

test('loadAgentApiKeys refuses a non-object or an empty object', () => {
  assert.throws(() => loadAgentApiKeys(env([])), /AGENT_API_KEYS/);
  assert.throws(() => loadAgentApiKeys(env({})), /AGENT_API_KEYS.*empty/);
});

test('loadAgentApiKeys refuses a name outside [a-z0-9-]', () => {
  for (const name of ['DevOps', 'devops agent', 'devops_agent', '', 'amk_pasted-key-by-mistake']) {
    assert.throws(
      () => loadAgentApiKeys(env({ [name]: { keySha256: HASH, argocdToken: 't' } })),
      (e: unknown) => {
        assert.ok(e instanceof Error);
        assert.match(e.message, /name/);
        if (name) assert.doesNotMatch(e.message, new RegExp(name.replace(/[-_ ]/g, '.')));
        return true;
      },
      `name "${name}" must be refused`
    );
  }
});

test('loadAgentApiKeys refuses a keySha256 that is not 64 lowercase hex characters', () => {
  for (const bad of [HASH.toUpperCase(), HASH.slice(1), `${HASH}0`, KEY, '']) {
    assert.throws(
      () => loadAgentApiKeys(env({ a: { keySha256: bad, argocdToken: 't' } })),
      /keySha256/,
      `hash "${bad}" must be refused`
    );
  }
});

test('loadAgentApiKeys refuses the same hash under two names', () => {
  assert.throws(
    () =>
      loadAgentApiKeys(
        env({
          a: { keySha256: HASH, argocdToken: 't1' },
          b: { keySha256: HASH, argocdToken: 't2' }
        })
      ),
    /same key/
  );
});

test('loadAgentApiKeys refuses a missing or blank argocdToken', () => {
  assert.throws(() => loadAgentApiKeys(env({ a: { keySha256: HASH } })), /argocdToken/);
  assert.throws(
    () => loadAgentApiKeys(env({ a: { keySha256: HASH, argocdToken: '  ' } })),
    /argocdToken/
  );
});

test('loadAgentApiKeys refuses AGENT_API_KEYS outside oidc mode', () => {
  const entry = { a: { keySha256: HASH, argocdToken: 't' } };
  assert.throws(() => loadAgentApiKeys(env(entry, 'token')), /AUTH_MODE=oidc/);
  assert.throws(
    () => loadAgentApiKeys({ AGENT_API_KEYS: JSON.stringify(entry) }),
    /AUTH_MODE=oidc/
  );
});

test('hashAgentKey is the SHA-256 of the whole key string, prefix included', () => {
  assert.equal(hashAgentKey(KEY).toString('hex'), HASH);
});

test('isAgentKeyShaped accepts only amk_ plus 64 lowercase hex characters', () => {
  assert.equal(isAgentKeyShaped(KEY), true);
  assert.equal(isAgentKeyShaped(KEY.toUpperCase()), false);
  assert.equal(isAgentKeyShaped(KEY.slice(0, -1)), false);
  assert.equal(isAgentKeyShaped(`${KEY}0`), false);
  // A base64url opaque OIDC token can start with "amk_" by chance (the alphabet
  // includes "_"), but it is 43 characters and not hex, so it never matches.
  assert.equal(isAgentKeyShaped('amk_' + 'A'.repeat(39)), false);
  assert.equal(isAgentKeyShaped(''), false);
});
