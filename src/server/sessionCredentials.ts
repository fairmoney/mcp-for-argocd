import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { BearerTokenProvider, TokenSource } from '../argocd/http.js';
import { machineAuthOf } from '../auth/agentKeyVerifier.js';

export interface SessionCredentials {
  // Who may reuse the session id: an OIDC client id or "apikey:<name>".
  owner: string;
  // Set for machine sessions only; every tool call is logged with it.
  principal?: string;
  // What the session's ArgoCD client authenticates with.
  tokenSource: TokenSource;
}

// Turn the AuthInfo the bearer middleware attached into the session's ArgoCD
// credentials. A machine key carries its ArgoCD token outright (no refresh:
// a 401 from ArgoCD surfaces as the tool error, as in token mode). An OIDC
// login gets the refreshable provider built from its opaque token.
export const resolveSessionCredentials = (
  auth: AuthInfo,
  oidcProviderFor: (opaqueToken: string) => BearerTokenProvider
): SessionCredentials => {
  const machine = machineAuthOf(auth);
  if (machine) {
    return {
      owner: machine.principal,
      principal: machine.principal,
      tokenSource: machine.argocdToken
    };
  }
  return { owner: auth.clientId, tokenSource: oidcProviderFor(auth.token) };
};
