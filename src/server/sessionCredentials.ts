import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { BearerTokenProvider, TokenSource } from '../argocd/http.js';
import { machineAuthOf } from '../auth/agentKeyVerifier.js';

export interface SessionCredentials {
  // Who may reuse the session id; see resolveSessionOwner.
  owner: string;
  // Set for machine sessions only; every tool call is logged with it.
  principal?: string;
  // What the session's ArgoCD client authenticates with.
  tokenSource: TokenSource;
}

// The principal an HTTP session is bound to. A machine key is its own
// principal. An OIDC bearer is bound to the login it came from (the token
// record's session id, which survives token refresh), not to the registered
// MCP client: a hosted connector registers one client for many people, and
// they must not be able to pick up each other's sessions. The client id is
// only a fallback for a token record without a session id.
export const resolveSessionOwner = (auth: AuthInfo): string => {
  const machine = machineAuthOf(auth);
  if (machine) return machine.principal;
  const sessionId = auth.extra?.sessionId;
  return typeof sessionId === 'string' && sessionId
    ? `oidc:${sessionId}`
    : `client:${auth.clientId}`;
};

// Turn the AuthInfo the bearer middleware attached into the session's ArgoCD
// credentials. A machine key carries its ArgoCD token outright (no refresh:
// a 401 from ArgoCD surfaces as the tool error, as in token mode). An OIDC
// login gets the refreshable provider built from its opaque token. Only
// called when a session is created; a lookup needs resolveSessionOwner alone.
export const resolveSessionCredentials = (
  auth: AuthInfo,
  oidcProviderFor: (opaqueToken: string) => BearerTokenProvider
): SessionCredentials => {
  const owner = resolveSessionOwner(auth);
  const machine = machineAuthOf(auth);
  if (machine) {
    return { owner, principal: machine.principal, tokenSource: machine.argocdToken };
  }
  return { owner, tokenSource: oidcProviderFor(auth.token) };
};
