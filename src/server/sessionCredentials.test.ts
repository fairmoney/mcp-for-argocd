import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { BearerTokenProvider } from '../argocd/http.js';
import { resolveSessionCredentials, resolveSessionOwner } from './sessionCredentials.js';

// The oidc /mcp handler binds each HTTP session to an owner and, when it
// creates one, builds its ArgoCD credentials from the AuthInfo the middleware
// attached. A passthrough session uses the forwarded ArgoCD token and is owned
// by that token's fingerprint; an OIDC session gets the refreshable provider
// for its opaque token and is owned by its login.

const oidcProvider: BearerTokenProvider = {
  current: async () => 'live',
  refresh: async () => 'refreshed'
};

const FP = 'f'.repeat(64);
const passthroughAuth: AuthInfo = {
  token: 'argocd-token',
  clientId: 'argocd:devops-agent',
  scopes: [],
  expiresAt: 1,
  extra: {
    kind: 'argocd-token',
    argocdToken: 'argocd-token',
    fingerprint: FP,
    principal: 'argocd:devops-agent'
  }
};
const oidcAuth: AuthInfo = {
  token: 'opaque-token',
  clientId: 'client-1',
  scopes: [],
  expiresAt: 1,
  extra: { argocdToken: 'upstream', argocdBaseUrl: 'https://argocd', sessionId: 'login-42' }
};

test('a forwarded ArgoCD token is owned by its own fingerprint', () => {
  assert.equal(resolveSessionOwner(passthroughAuth), `argocd-token:${FP}`);
});

test('an OIDC bearer is owned by its login, not by the registered client', () => {
  assert.equal(resolveSessionOwner(oidcAuth), 'oidc:login-42');
  // Two logins through the same registered client get different owners.
  const other: AuthInfo = {
    ...oidcAuth,
    token: 'other-opaque',
    extra: { ...oidcAuth.extra, sessionId: 'login-43' }
  };
  assert.notEqual(resolveSessionOwner(other), resolveSessionOwner(oidcAuth));
});

test('a token record without a session id fails closed rather than binding to the client', () => {
  const legacy: AuthInfo = { ...oidcAuth, extra: { argocdToken: 'upstream' } };
  assert.throws(() => resolveSessionOwner(legacy), /session id/);
  const none: AuthInfo = { ...oidcAuth, extra: undefined };
  assert.throws(() => resolveSessionOwner(none), /session id/);
});

test('a passthrough AuthInfo yields the forwarded token, its principal and owner', () => {
  let providerBuiltFor: string | undefined;

  const creds = resolveSessionCredentials(passthroughAuth, (opaque) => {
    providerBuiltFor = opaque;
    return oidcProvider;
  });

  assert.deepEqual(creds, {
    owner: `argocd-token:${FP}`,
    principal: 'argocd:devops-agent',
    tokenSource: 'argocd-token'
  });
  assert.equal(
    providerBuiltFor,
    undefined,
    'no OIDC session provider is built for a forwarded token'
  );
});

test('an OIDC AuthInfo yields the refreshable provider for its opaque token and no principal', () => {
  let providerBuiltFor: string | undefined;

  const creds = resolveSessionCredentials(oidcAuth, (opaque) => {
    providerBuiltFor = opaque;
    return oidcProvider;
  });

  assert.equal(creds.owner, 'oidc:login-42');
  assert.equal(creds.principal, undefined);
  assert.equal(creds.tokenSource, oidcProvider);
  assert.equal(providerBuiltFor, 'opaque-token');
});
