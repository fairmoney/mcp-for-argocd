import assert from 'node:assert/strict';
import { mock, test } from 'node:test';
import type { Response as ExpressResponse } from 'express';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import {
  InvalidGrantError,
  InvalidTokenError
} from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { OAuthProxyProvider } from './oauthProxyProvider.js';
import { InMemoryTokenStore } from './inMemoryTokenStore.js';
import { makeSessionTokenProvider } from './sessionTokenProvider.js';
import type { OidcConfig } from './config.js';

const CONFIG: OidcConfig = {
  mode: 'explicit',
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
  await assert.rejects(
    () => provider.verifyAccessToken('bogus'),
    (error: unknown) => {
      // Must be the SDK's InvalidTokenError so the bearer middleware answers 401.
      assert.ok(error instanceof InvalidTokenError);
      assert.match(error.message, /Invalid/);
      return true;
    }
  );
});

// A Dex stub that models refresh-token ROTATION: each refresh_token grant only
// succeeds for the currently-valid refresh token and returns a fresh one,
// invalidating the previous. It records every presented refresh token so tests
// can assert which copy each path used.
const makeRotatingDex = () => {
  let current = 'R1';
  let counter = 1;
  const presented: string[] = [];
  const fetchImpl = (async (input: string | URL, init?: RequestInit) => {
    if (!input.toString().includes('/api/dex/token')) return new Response('nope', { status: 404 });
    const body = new URLSearchParams((init?.body as string) ?? '');
    if (body.get('grant_type') === 'authorization_code') {
      return new Response(
        JSON.stringify({
          access_token: 'UPSTREAM_JWT_1',
          token_type: 'Bearer',
          expires_in: 300,
          refresh_token: 'R1'
        }),
        { status: 200 }
      );
    }
    // refresh_token grant
    const token = body.get('refresh_token') ?? '';
    presented.push(token);
    if (token !== current) {
      // Dex rejects a refresh token it has already rotated away.
      return new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 400 });
    }
    counter += 1;
    current = `R${counter}`;
    return new Response(
      JSON.stringify({
        access_token: `UPSTREAM_JWT_${counter}`,
        token_type: 'Bearer',
        expires_in: 300,
        refresh_token: current
      }),
      { status: 200 }
    );
  }) as unknown as typeof fetch;
  return { fetchImpl, presented };
};

// Drive authorize -> callback -> exchange code to establish a live session,
// returning the issued opaque tokens.
const establishSession = async (provider: OAuthProxyProvider) => {
  const { res, out } = fakeRes();
  await provider.authorize(
    client,
    {
      redirectUri: 'http://localhost:33418/callback',
      state: 'cs',
      codeChallenge: 'cc',
      scopes: ['openid']
    } as never,
    res
  );
  const upstreamState = new URL(out.redirected!).searchParams.get('state')!;
  const clientRedirect = await provider.handleUpstreamCallback('dex-code', upstreamState);
  const ourCode = new URL(clientRedirect).searchParams.get('code')!;
  return provider.exchangeAuthorizationCode(client, ourCode);
};

test('exchangeRefreshToken rotates opaque tokens and updates the shared session record', async (t) => {
  const store = new InMemoryTokenStore();
  const { fetchImpl } = makeRotatingDex();
  const provider = new OAuthProxyProvider({
    config: CONFIG,
    store,
    discover: async () => META,
    fetchImpl
  });
  t.after(() => store.dispose());

  const tokens1 = await establishSession(provider);
  const oldAccess = tokens1.access_token;
  const oldRefresh = tokens1.refresh_token!;
  assert.ok(oldRefresh);

  const tokens2 = await provider.exchangeRefreshToken(client, oldRefresh);
  // New opaque access + refresh minted.
  assert.notEqual(tokens2.access_token, oldAccess);
  assert.notEqual(tokens2.refresh_token, oldRefresh);
  // Old opaque refresh is consumed (single-use).
  assert.equal(await store.getRefreshToken(oldRefresh), undefined);
  // New opaque refresh resolves and points at the same session.
  const newRefreshRecord = await store.getRefreshToken(tokens2.refresh_token!);
  assert.ok(newRefreshRecord);
  // The shared session record now holds Dex's rotated upstream refresh token.
  const session = await store.getSession(newRefreshRecord!.sessionId);
  assert.equal(session?.upstreamRefreshToken, 'R2');
  // The OLD opaque access token is intentionally kept (a long-lived server-side
  // session may still hold it); it expires on its own TTL rather than here.
  assert.ok(await store.getAccessToken(oldAccess));
});

// Core proof for FIX 1: after a client-facing refresh rotates Dex's refresh
// token, the server-side sessionTokenProvider must use the ROTATED token from
// the shared session record, not its stale original.
test('desync regression: server-side refresh uses the rotated token from the shared session', async (t) => {
  const store = new InMemoryTokenStore();
  const { fetchImpl, presented } = makeRotatingDex();
  const provider = new OAuthProxyProvider({
    config: CONFIG,
    store,
    discover: async () => META,
    fetchImpl
  });
  t.after(() => {
    mock.restoreAll();
    store.dispose();
  });

  const tokens1 = await establishSession(provider);
  const opaqueAccess = tokens1.access_token; // captured by the server-side session at init

  // 1. Client-facing refresh: Dex rotates R1 -> R2; session record updated.
  await provider.exchangeRefreshToken(client, tokens1.refresh_token!);

  // 2. Server-side refresh path shares the same store but uses global fetch.
  mock.method(globalThis, 'fetch', fetchImpl);
  const sessionProvider = makeSessionTokenProvider(store, META, CONFIG, opaqueAccess);
  const jwt = await sessionProvider.refresh();

  // The server-side path succeeded (Dex would 400 a stale token) using R2, the
  // rotated token — not the original R1.
  assert.equal(jwt, 'UPSTREAM_JWT_3');
  assert.deepEqual(presented, ['R1', 'R2']);
});

// A failed client-facing refresh must answer invalid_grant (400), not a plain
// error the SDK turns into a 500: only invalid_grant tells an MCP client to
// drop its refresh token and run the sign-in again.
const isInvalidGrant = (error: unknown) => {
  assert.ok(error instanceof InvalidGrantError, `got ${String(error)}`);
  return true;
};

test('exchangeRefreshToken: an unknown refresh token is invalid_grant', async (t) => {
  const { store, provider } = makeProvider();
  t.after(() => store.dispose());
  await assert.rejects(() => provider.exchangeRefreshToken(client, 'bogus'), isInvalidGrant);
});

test('exchangeRefreshToken: a refresh token without a session is invalid_grant', async (t) => {
  const { store, provider } = makeProvider();
  t.after(() => store.dispose());
  await store.putRefreshToken('opaque-r', { clientId: client.client_id, sessionId: 'gone' });
  await assert.rejects(() => provider.exchangeRefreshToken(client, 'opaque-r'), isInvalidGrant);
});

test('exchangeRefreshToken: Dex rejecting the grant is invalid_grant and ends the session', async (t) => {
  const store = new InMemoryTokenStore();
  t.after(() => store.dispose());
  const { fetchImpl } = makeRotatingDex();
  const provider = new OAuthProxyProvider({
    config: CONFIG,
    store,
    discover: async () => META,
    fetchImpl
  });
  const tokens = await establishSession(provider);
  const record = await store.getRefreshToken(tokens.refresh_token!);
  // Dex has moved on (e.g. it restarted and lost its refresh tokens).
  await store.putSession(record!.sessionId, {
    upstreamRefreshToken: 'R-unknown-to-dex',
    clientId: client.client_id
  });

  await assert.rejects(
    () => provider.exchangeRefreshToken(client, tokens.refresh_token!),
    isInvalidGrant
  );
  assert.equal(await store.getSession(record!.sessionId), undefined);
});

test('exchangeRefreshToken: a Dex outage is not invalid_grant and keeps the session', async (t) => {
  const store = new InMemoryTokenStore();
  t.after(() => store.dispose());
  const { fetchImpl: rotating } = makeRotatingDex();
  let down = false;
  const fetchImpl = (async (input: string | URL, init?: RequestInit) =>
    down ? new Response('down', { status: 503 }) : rotating(input, init)) as typeof fetch;
  const provider = new OAuthProxyProvider({
    config: CONFIG,
    store,
    discover: async () => META,
    fetchImpl
  });
  const tokens = await establishSession(provider);
  const record = await store.getRefreshToken(tokens.refresh_token!);
  down = true;

  await assert.rejects(
    () => provider.exchangeRefreshToken(client, tokens.refresh_token!),
    (error: unknown) => {
      assert.ok(!(error instanceof InvalidGrantError));
      return true;
    }
  );
  assert.ok(await store.getSession(record!.sessionId));
  assert.ok(await store.getRefreshToken(tokens.refresh_token!), 'the client may retry');
});

// The revoking path only holds the access token its HTTP session started
// with; a client that refreshed holds a newer one, which must die too.
test('verifyAccessToken refuses every access token of a revoked login', async (t) => {
  const store = new InMemoryTokenStore();
  t.after(() => store.dispose());
  const { fetchImpl } = makeRotatingDex();
  const provider = new OAuthProxyProvider({
    config: CONFIG,
    store,
    discover: async () => META,
    fetchImpl
  });
  const first = await establishSession(provider);
  const second = await provider.exchangeRefreshToken(client, first.refresh_token!);
  const { sessionId } = (await store.getRefreshToken(second.refresh_token!))!;
  await provider.verifyAccessToken(second.access_token);

  await store.deleteSession(sessionId);

  for (const token of [first.access_token, second.access_token]) {
    await assert.rejects(
      () => provider.verifyAccessToken(token),
      (error: unknown) => error instanceof InvalidTokenError
    );
  }
});

// A server-side refresh rotates R1 while the client is presenting R1 itself:
// Dex refuses the stale token, but the login is alive, so the client must get
// fresh tokens (via one retry with the rotated token), not a forced sign-in.
test('exchangeRefreshToken: losing a rotation race retries with the rotated token', async (t) => {
  const store = new InMemoryTokenStore();
  t.after(() => store.dispose());
  const { fetchImpl: rotating } = makeRotatingDex();
  const race: { sessionId?: string } = {};
  const presented: string[] = [];
  const fetchImpl = (async (input: string | URL, init?: RequestInit) => {
    const token = new URLSearchParams((init?.body as string) ?? '').get('refresh_token');
    if (race.sessionId && token) {
      presented.push(token);
      if (token === 'R1') {
        // Another path wins the rotation while this request is at Dex.
        await store.putSession(race.sessionId, {
          upstreamRefreshToken: 'R-rotated',
          clientId: client.client_id
        });
        return new Response(JSON.stringify({ error: 'invalid_request' }), { status: 400 });
      }
      return new Response(
        JSON.stringify({ access_token: 'JWT_OK', refresh_token: 'R-next', expires_in: 300 }),
        { status: 200 }
      );
    }
    return rotating(input, init);
  }) as typeof fetch;
  const provider = new OAuthProxyProvider({
    config: CONFIG,
    store,
    discover: async () => META,
    fetchImpl
  });
  const tokens = await establishSession(provider);
  race.sessionId = (await store.getRefreshToken(tokens.refresh_token!))!.sessionId;

  const next = await provider.exchangeRefreshToken(client, tokens.refresh_token!);

  assert.deepEqual(presented, ['R1', 'R-rotated']);
  assert.equal((await store.getSession(race.sessionId))?.upstreamRefreshToken, 'R-next');
  await provider.verifyAccessToken(next.access_token);
});

// Our Dex uses a SAML connector, which issues no refresh token: such a login
// never has a session record and must still be accepted.
test('verifyAccessToken accepts a login that has no refresh token', async (t) => {
  const store = new InMemoryTokenStore();
  t.after(() => store.dispose());
  const samlDex = (async () =>
    new Response(
      JSON.stringify({ access_token: 'SAML_JWT', token_type: 'Bearer', expires_in: 300 }),
      { status: 200 }
    )) as unknown as typeof fetch;
  const provider = new OAuthProxyProvider({
    config: CONFIG,
    store,
    discover: async () => META,
    fetchImpl: samlDex
  });

  const tokens = await establishSession(provider);

  assert.equal(tokens.refresh_token, undefined);
  const info = await provider.verifyAccessToken(tokens.access_token);
  assert.equal(info.extra?.argocdToken, 'SAML_JWT');
});
