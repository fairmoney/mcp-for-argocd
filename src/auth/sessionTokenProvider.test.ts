import assert from 'node:assert/strict';
import { afterEach, mock, test } from 'node:test';
import { InMemoryTokenStore } from './inMemoryTokenStore.js';
import { makeSessionTokenProvider } from './sessionTokenProvider.js';
import type { OidcConfig } from './config.js';
import type { OidcProviderMetadata } from './types.js';

const CONFIG: OidcConfig = {
  publicUrl: 'https://mcp.example.com',
  argocdBaseUrl: 'https://argocd.example.com',
  clientId: 'argocd-mcp',
  clientSecret: 'shhh',
  callbackPath: '/oauth/callback',
  callbackUrl: 'https://mcp.example.com/oauth/callback',
  tokenStore: 'memory'
};

const META: OidcProviderMetadata = {
  issuer: 'https://argocd.example.com/api/dex',
  authorizationEndpoint: 'https://argocd.example.com/api/dex/auth',
  tokenEndpoint: 'https://argocd.example.com/api/dex/token'
};

// sessionTokenProvider calls refreshUpstream WITHOUT a fetchImpl arg, so it uses
// the global fetch — inject a stub there. Each stub records the refresh token
// presented to Dex so tests can assert which one was used.
const stubDexFetch = (response: {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
}): { presentedRefreshTokens: string[] } => {
  const presentedRefreshTokens: string[] = [];
  mock.method(globalThis, 'fetch', async (_url: string | URL, init?: RequestInit) => {
    const body = new URLSearchParams((init?.body as string) ?? '');
    presentedRefreshTokens.push(body.get('refresh_token') ?? '');
    return new Response(JSON.stringify({ token_type: 'Bearer', ...response }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  });
  return { presentedRefreshTokens };
};

afterEach(() => mock.restoreAll());

test('current() returns the stored access token when not near expiry', async (t) => {
  const store = new InMemoryTokenStore();
  t.after(() => store.dispose());
  const { presentedRefreshTokens } = stubDexFetch({ access_token: 'SHOULD_NOT_BE_USED' });

  await store.putAccessToken('op1', {
    upstream: { accessToken: 'FRESH_JWT', refreshToken: 'R1', expiresAtMs: Date.now() + 3_600_000 },
    clientId: 'abc',
    sessionId: 's1'
  });

  const provider = makeSessionTokenProvider(store, META, CONFIG, 'op1');
  assert.equal(await provider.current(), 'FRESH_JWT');
  assert.equal(presentedRefreshTokens.length, 0, 'no upstream refresh should happen');
});

test('current() refreshes within the skew and writes back the rotated session record', async (t) => {
  const store = new InMemoryTokenStore();
  t.after(() => store.dispose());
  const { presentedRefreshTokens } = stubDexFetch({
    access_token: 'NEW_JWT',
    refresh_token: 'R2',
    expires_in: 300
  });

  await store.putAccessToken('op1', {
    // near expiry: within the 30s skew window
    upstream: { accessToken: 'OLD_JWT', refreshToken: 'R1', expiresAtMs: Date.now() + 5_000 },
    clientId: 'abc',
    sessionId: 's1'
  });
  await store.putSession('s1', { upstreamRefreshToken: 'R1', clientId: 'abc' });

  const provider = makeSessionTokenProvider(store, META, CONFIG, 'op1');
  assert.equal(await provider.current(), 'NEW_JWT');

  // The upstream refresh used the shared session's refresh token (R1)...
  assert.deepEqual(presentedRefreshTokens, ['R1']);
  // ...and the rotated refresh token (R2) was written back to the shared record.
  assert.equal((await store.getSession('s1'))?.upstreamRefreshToken, 'R2');
  // The new access token is persisted under the same opaque + sessionId.
  const stored = await store.getAccessToken('op1');
  assert.equal(stored?.upstream.accessToken, 'NEW_JWT');
  assert.equal(stored?.sessionId, 's1');
});

test('doRefresh throws when the session record is missing', async (t) => {
  const store = new InMemoryTokenStore();
  t.after(() => store.dispose());
  stubDexFetch({ access_token: 'NEW_JWT', refresh_token: 'R2', expires_in: 300 });

  await store.putAccessToken('op1', {
    upstream: { accessToken: 'OLD_JWT', refreshToken: 'R1', expiresAtMs: Date.now() + 5_000 },
    clientId: 'abc',
    sessionId: 's1'
  });
  // Deliberately no putSession('s1', ...).

  const provider = makeSessionTokenProvider(store, META, CONFIG, 'op1');
  await assert.rejects(() => provider.refresh(), /No upstream refresh token available/);
});

test('refresh() throws when the access token record is missing', async (t) => {
  const store = new InMemoryTokenStore();
  t.after(() => store.dispose());
  stubDexFetch({ access_token: 'NEW_JWT' });
  const provider = makeSessionTokenProvider(store, META, CONFIG, 'missing');
  await assert.rejects(() => provider.refresh(), /Session token not found/);
});
