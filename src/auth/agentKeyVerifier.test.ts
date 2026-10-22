import assert from 'node:assert/strict';
import { test } from 'node:test';
import { InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import type { OAuthTokenVerifier } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { hashAgentKey, type AgentKey } from './agentKeys.js';
import {
  createCompositeVerifier,
  MACHINE_AUTH_TTL_SEC,
  machineAuthOf
} from './agentKeyVerifier.js';

const keyFor = (byte: string) => `amk_${byte.repeat(32)}`;
const KEY_A = keyFor('aa');
const KEY_B = keyFor('bb');
const KEY_C = keyFor('cc');
const UNKNOWN_KEY = keyFor('dd');
const OIDC_TOKEN = 'amk_' + 'x'.repeat(39); // base64url-ish, not a machine key

const entry = (name: string, key: string): AgentKey => ({
  name,
  keySha256: hashAgentKey(key),
  argocdToken: `argocd-token-for-${name}`
});
const KEYS = [entry('first', KEY_A), entry('second', KEY_B), entry('third', KEY_C)];

// A fallback verifier that records what it was asked and answers from a table.
const makeFallback = (answers: Record<string, AuthInfo> = {}) => {
  const seen: string[] = [];
  const verifier: OAuthTokenVerifier = {
    verifyAccessToken: async (token) => {
      seen.push(token);
      const info = answers[token];
      if (!info) throw new InvalidTokenError('Invalid or expired access token');
      return info;
    }
  };
  return { verifier, seen };
};

test('a configured key yields a machine AuthInfo bound to its ArgoCD token', async () => {
  const fallback = makeFallback();
  const verifier = createCompositeVerifier(fallback.verifier, KEYS);
  const before = Math.floor(Date.now() / 1000);

  const auth = await verifier.verifyAccessToken(KEY_B);

  assert.equal(auth.clientId, 'apikey:second');
  assert.deepEqual(auth.scopes, []);
  assert.equal(auth.token, KEY_B);
  assert.deepEqual(machineAuthOf(auth), {
    kind: 'apikey',
    principal: 'apikey:second',
    argocdToken: 'argocd-token-for-second'
  });
  // The SDK middleware rejects any AuthInfo without expiresAt, so the machine
  // path sets one; the key itself does not expire (rotation is by config).
  assert.ok(typeof auth.expiresAt === 'number');
  assert.ok(auth.expiresAt >= before + MACHINE_AUTH_TTL_SEC - 1);
  assert.deepEqual(fallback.seen, [], 'the OIDC verifier must not see a machine key');
});

test('an unknown key is rejected with InvalidTokenError and never reaches the fallback', async () => {
  const fallback = makeFallback();
  const verifier = createCompositeVerifier(fallback.verifier, KEYS);

  await assert.rejects(verifier.verifyAccessToken(UNKNOWN_KEY), (error: unknown) => {
    assert.ok(error instanceof InvalidTokenError);
    assert.doesNotMatch(error.message, /amk_/, 'the presented key must not be echoed');
    return true;
  });
  assert.deepEqual(fallback.seen, []);
});

test('a token that is not key-shaped is delegated to the fallback verbatim', async () => {
  const oidcInfo: AuthInfo = { token: OIDC_TOKEN, clientId: 'client-1', scopes: [], expiresAt: 1 };
  const fallback = makeFallback({ [OIDC_TOKEN]: oidcInfo });
  const verifier = createCompositeVerifier(fallback.verifier, KEYS);

  const auth = await verifier.verifyAccessToken(OIDC_TOKEN);

  assert.equal(auth, oidcInfo);
  assert.deepEqual(fallback.seen, [OIDC_TOKEN]);
  assert.equal(machineAuthOf(auth), undefined);
});

test('a fallback rejection propagates unchanged', async () => {
  const fallback = makeFallback();
  const verifier = createCompositeVerifier(fallback.verifier, KEYS);

  await assert.rejects(verifier.verifyAccessToken('opaque-oidc-token'), InvalidTokenError);
});

test('with no keys configured the fallback alone decides, even for a key-shaped token', async () => {
  for (const keys of [undefined, []]) {
    const fallback = makeFallback();
    const verifier = createCompositeVerifier(fallback.verifier, keys);

    await assert.rejects(verifier.verifyAccessToken(KEY_A), InvalidTokenError);
    assert.deepEqual(fallback.seen, [KEY_A]);
  }
});

test('every configured key is compared, even after a match (no early exit)', async () => {
  let compares = 0;
  const equals = (a: Buffer, b: Buffer) => {
    compares += 1;
    return a.equals(b);
  };
  const verifier = createCompositeVerifier(makeFallback().verifier, KEYS, { equals });

  await verifier.verifyAccessToken(KEY_A); // matches the first entry
  assert.equal(compares, KEYS.length);

  compares = 0;
  await assert.rejects(verifier.verifyAccessToken(UNKNOWN_KEY));
  assert.equal(compares, KEYS.length);
});
