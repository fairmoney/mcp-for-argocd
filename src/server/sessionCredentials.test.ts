import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { BearerTokenProvider } from '../argocd/http.js';
import { resolveSessionCredentials } from './sessionCredentials.js';

// The oidc /mcp handler builds each session's ArgoCD credentials from the
// AuthInfo the bearer middleware attached. A machine session uses the static
// ArgoCD token bound to its key and is owned by "apikey:<name>"; an OIDC
// session gets the refreshable provider built from its opaque token and is
// owned by its registered client id.

const oidcProvider: BearerTokenProvider = {
  current: async () => 'live',
  refresh: async () => 'refreshed'
};

test('a machine AuthInfo yields the static ArgoCD token, its principal and owner', () => {
  const auth: AuthInfo = {
    token: 'amk_key',
    clientId: 'apikey:devops-agent',
    scopes: [],
    expiresAt: 1,
    extra: { kind: 'apikey', principal: 'apikey:devops-agent', argocdToken: 'argocd-token' }
  };
  let providerBuiltFor: string | undefined;

  const creds = resolveSessionCredentials(auth, (opaque) => {
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
  const auth: AuthInfo = { token: 'opaque-token', clientId: 'client-1', scopes: [], expiresAt: 1 };
  let providerBuiltFor: string | undefined;

  const creds = resolveSessionCredentials(auth, (opaque) => {
    providerBuiltFor = opaque;
    return oidcProvider;
  });

  assert.equal(creds.owner, 'client-1');
  assert.equal(creds.principal, undefined);
  assert.equal(creds.tokenSource, oidcProvider);
  assert.equal(providerBuiltFor, 'opaque-token');
});
