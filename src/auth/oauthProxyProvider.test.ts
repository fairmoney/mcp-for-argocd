import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { Response as ExpressResponse } from 'express';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import { OAuthProxyProvider } from './oauthProxyProvider.js';
import { InMemoryTokenStore } from './inMemoryTokenStore.js';
import type { OidcConfig } from './config.js';

const CONFIG: OidcConfig = {
  publicUrl: 'https://mcp.example.com',
  argocdBaseUrl: 'https://argocd.example.com',
  clientId: 'argocd-mcp',
  clientSecret: 'shhh',
  callbackPath: '/oauth/callback',
  callbackUrl: 'https://mcp.example.com/oauth/callback',
  tokenStore: 'memory'
};

const META = {
  issuer: 'https://argocd.example.com/api/dex',
  authorizationEndpoint: 'https://argocd.example.com/api/dex/auth',
  tokenEndpoint: 'https://argocd.example.com/api/dex/token',
  scopesSupported: ['openid', 'groups']
};

// fetch stub: the Dex token endpoint returns a fixed upstream token.
const dexFetch: typeof fetch = (async (input: string | URL) => {
  if (input.toString().includes('/api/dex/token')) {
    return new Response(
      JSON.stringify({
        access_token: 'UPSTREAM_JWT',
        token_type: 'Bearer',
        expires_in: 300,
        refresh_token: 'UP_REFRESH'
      }),
      { status: 200 }
    );
  }
  return new Response('nope', { status: 404 });
}) as unknown as typeof fetch;

const makeProvider = () => {
  const store = new InMemoryTokenStore();
  const provider = new OAuthProxyProvider({
    config: CONFIG,
    store,
    discover: async () => META,
    fetchImpl: dexFetch
  });
  return { store, provider };
};

// A fake express Response that records a redirect target.
const fakeRes = () => {
  const out: { redirected?: string } = {};
  return {
    res: { redirect: (url: string) => (out.redirected = url) } as unknown as ExpressResponse,
    out
  };
};

const client: OAuthClientInformationFull = {
  client_id: 'mcp-client-1',
  redirect_uris: ['http://localhost:33418/callback']
} as OAuthClientInformationFull;

test('full flow: authorize -> callback -> exchange code -> verify token', async (t) => {
  const { store, provider } = makeProvider();
  t.after(() => store.dispose());

  // 1. authorize -> redirects to Dex, storing pending state keyed by upstream state.
  const { res, out } = fakeRes();
  await provider.authorize(
    client,
    {
      redirectUri: 'http://localhost:33418/callback',
      state: 'client-state',
      codeChallenge: 'client-challenge',
      scopes: ['openid']
    } as never,
    res
  );
  assert.ok(out.redirected?.startsWith('https://argocd.example.com/api/dex/auth'));
  const upstreamState = new URL(out.redirected!).searchParams.get('state')!;
  assert.ok(upstreamState);
  assert.equal(new URL(out.redirected!).searchParams.get('client_id'), 'argocd-mcp');

  // 2. upstream callback -> exchanges code, returns MCP client redirect with our code.
  const clientRedirect = await provider.handleUpstreamCallback('dex-code', upstreamState);
  const ourCode = new URL(clientRedirect).searchParams.get('code')!;
  assert.equal(new URL(clientRedirect).searchParams.get('state'), 'client-state');
  assert.ok(ourCode);

  // 3. client PKCE challenge is preserved for the token step.
  assert.equal(await provider.challengeForAuthorizationCode(client, ourCode), 'client-challenge');

  // 4. exchange our code -> opaque tokens; the real JWT stays server-side.
  const tokens = await provider.exchangeAuthorizationCode(client, ourCode);
  assert.notEqual(tokens.access_token, 'UPSTREAM_JWT');
  assert.equal(tokens.token_type, 'Bearer');

  // 5. verify -> AuthInfo carries the real upstream token in extra.
  const info = await provider.verifyAccessToken(tokens.access_token);
  assert.equal(info.extra?.argocdToken, 'UPSTREAM_JWT');
  assert.equal(info.extra?.argocdBaseUrl, 'https://argocd.example.com');
});

test('verifyAccessToken rejects an unknown opaque token', async (t) => {
  const { store, provider } = makeProvider();
  t.after(() => store.dispose());
  await assert.rejects(() => provider.verifyAccessToken('bogus'), /Invalid/);
});
