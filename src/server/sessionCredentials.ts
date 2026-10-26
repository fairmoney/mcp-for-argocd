import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { BearerTokenProvider, TokenSource } from '../argocd/http.js';
import { passthroughAuthOf } from '../auth/argocdTokenPassthrough.js';

export interface SessionCredentials {
  // Who may reuse the session id; see resolveSessionOwner.
  owner: string;
  // Set for passthrough sessions only; every tool call is logged with it.
  principal?: string;
  // What the session's ArgoCD client authenticates with.
  tokenSource: TokenSource;
}

// The principal an HTTP session is bound to. A forwarded ArgoCD token is bound
// to itself (its fingerprint), so only a caller presenting the same token can
// pick the session up. An OIDC bearer is bound to the login it came from (the
// token record's session id, which survives token refresh), not to the
// registered MCP client: a hosted connector registers one client for many
// people, and they must not be able to pick up each other's sessions. Every
// stored token carries that id; a record without one is a bug in the store,
// and binding to anything weaker instead would silently merge those people's
// sessions, so it fails closed (the handler answers 500 and logs it).
export const resolveSessionOwner = (auth: AuthInfo): string => {
  const passthrough = passthroughAuthOf(auth);
  if (passthrough) return `argocd-token:${passthrough.fingerprint}`;
  const sessionId = auth.extra?.sessionId;
  if (typeof sessionId !== 'string' || !sessionId) {
    throw new Error('OIDC token record carries no session id; refusing to bind the session');
  }
  return `oidc:${sessionId}`;
};

// Turn the AuthInfo the middleware attached into the session's ArgoCD
// credentials. A forwarded ArgoCD token is used as is (no refresh: a 401 from
// ArgoCD surfaces as the tool error, as in token mode). An OIDC login gets the
// refreshable provider built from its opaque token. Only called when a
// session is created; a lookup needs resolveSessionOwner alone.
export const resolveSessionCredentials = (
  auth: AuthInfo,
  oidcProviderFor: (opaqueToken: string) => BearerTokenProvider
): SessionCredentials => {
  const owner = resolveSessionOwner(auth);
  const passthrough = passthroughAuthOf(auth);
  if (passthrough) {
    return { owner, principal: passthrough.principal, tokenSource: passthrough.argocdToken };
  }
  return { owner, tokenSource: oidcProviderFor(auth.token) };
};
