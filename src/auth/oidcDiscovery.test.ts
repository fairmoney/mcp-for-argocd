import assert from 'node:assert/strict';
import { test } from 'node:test';
import { discoverOidc, SSONotConfiguredError } from './oidcDiscovery.js';

// Build a fake fetch that returns `settings` for /api/v1/settings and
// `wellKnown` for any /.well-known/openid-configuration request.
const fakeFetch = (settings: unknown, wellKnown?: unknown): typeof fetch =>
  (async (input: string | URL) => {
    const url = input.toString();
    if (url.includes('/api/v1/settings')) {
      return new Response(JSON.stringify(settings), { status: 200 });
    }
    if (url.includes('/.well-known/openid-configuration')) {
      return new Response(JSON.stringify(wellKnown), { status: 200 });
    }
    return new Response('not found', { status: 404 });
  }) as unknown as typeof fetch;

test('discoverOidc derives Dex endpoints when dexConfig has connectors', async () => {
  const settings = { dexConfig: { connectors: [{ type: 'oidc', name: 'corp' }] } };
  const meta = await discoverOidc('https://argocd.example.com', fakeFetch(settings));
  assert.equal(meta.issuer, 'https://argocd.example.com/api/dex');
  assert.equal(meta.authorizationEndpoint, 'https://argocd.example.com/api/dex/auth');
  assert.equal(meta.tokenEndpoint, 'https://argocd.example.com/api/dex/token');
});

test('discoverOidc falls back to external OIDC well-known', async () => {
  const settings = { oidcConfig: { issuer: 'https://issuer.example.com', clientID: 'argocd' } };
  const wellKnown = {
    issuer: 'https://issuer.example.com',
    authorization_endpoint: 'https://issuer.example.com/authorize',
    token_endpoint: 'https://issuer.example.com/oauth/token'
  };
  const meta = await discoverOidc('https://argocd.example.com', fakeFetch(settings, wellKnown));
  assert.equal(meta.authorizationEndpoint, 'https://issuer.example.com/authorize');
  assert.equal(meta.tokenEndpoint, 'https://issuer.example.com/oauth/token');
});

test('discoverOidc throws SSONotConfiguredError when neither is present', async () => {
  await assert.rejects(
    () => discoverOidc('https://argocd.example.com', fakeFetch({})),
    SSONotConfiguredError
  );
});
