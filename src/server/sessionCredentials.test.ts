import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { BearerTokenProvider } from '../argocd/http.js';
import { resolveSessionCredentials, resolveSessionOwner } from './sessionCredentials.js';

// The oidc /mcp handler binds each HTTP session to an owner and, when it
// creates one, builds its ArgoCD credentials from the AuthInfo the bearer
// middleware attached. A machine session uses the static ArgoCD token bound
// to its key and is owned by "apikey:<name>"; an OIDC session gets the
// refreshable provider for its opaque token and is owned by its login.

const oidcProvider: BearerTokenProvider = {
  current: async () => 'live',
  refresh: async () => 'refreshed'
};

const machineAuth: AuthInfo = {
  token: 'amk_key',
  clientId: 'apikey:devops-agent',
  scopes: [],
  expiresAt: 1,
  extra: { kind: 'apikey', principal: 'apikey:devops-agent', argocdToken: 'argocd-token' }
};
const oidcAuth: AuthInfo = {
  token: 'opaque-token',
  clientId: 'client-1',
  scopes: [],
  expiresAt: 1,
  extra: { argocdToken: 'upstream', argocdBaseUrl: 'https://argocd', sessionId: 'login-42' }
};

test('a machine key is its own owner', () => {
  assert.equal(resolveSessionOwner(machineAuth), 'apikey:devops-agent');
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

test('a machine AuthInfo yields the static ArgoCD token, its principal and owner', () => {
  let providerBuiltFor: string | undefined;

  const creds = resolveSessionCredentials(machineAuth, (opaque) => {
    providerBuiltFor = opaque;
    return oidcProvider;
  });

  assert.deepEqual(creds, {
    owner: 'apikey:devops-agent',
    principal: 'apikey:devops-agent',
    tokenSource: 'argocd-token'
  });
  assert.equal(providerBuiltFor, undefined, 'no OIDC session provider is built for a key');
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
