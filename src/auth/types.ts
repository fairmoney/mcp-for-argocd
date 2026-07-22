// Shared, logic-free types for the OIDC/SSO auth layer.

// OIDC provider endpoints, normalized from ArgoCD's /api/v1/settings (Dex) or
// the provider's /.well-known/openid-configuration (direct external OIDC).
export interface OidcProviderMetadata {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  userinfoEndpoint?: string;
  scopesSupported?: string[];
}

// A PKCE (RFC 7636) verifier/challenge pair. We only ever use S256.
export interface PkceChallenge {
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: 'S256';
}

// The token set minted by the upstream provider (Dex) for the logged-in user.
// This is the credential actually accepted by the ArgoCD API. expiresAtMs is an
// absolute epoch time so freshness checks don't depend on when it was fetched.
export interface UpstreamToken {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  expiresAtMs?: number;
}
