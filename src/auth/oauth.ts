import { createHash, randomBytes } from 'node:crypto';
import type { OidcProviderMetadata, PkceChallenge, UpstreamToken } from './types.js';

export const generateState = (): string => randomBytes(32).toString('base64url');
export const generateOpaqueToken = (): string => randomBytes(32).toString('base64url');

export const generatePkce = (): PkceChallenge => {
  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
  return { codeVerifier, codeChallenge, codeChallengeMethod: 'S256' };
};

export const buildAuthorizeUrl = (
  meta: OidcProviderMetadata,
  opts: {
    clientId: string;
    redirectUri: string;
    scopes: string[];
    state: string;
    pkce: PkceChallenge;
  }
): string => {
  const url = new URL(meta.authorizationEndpoint);
  url.searchParams.set('client_id', opts.clientId);
  url.searchParams.set('redirect_uri', opts.redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', opts.scopes.join(' '));
  url.searchParams.set('state', opts.state);
  url.searchParams.set('code_challenge', opts.pkce.codeChallenge);
  url.searchParams.set('code_challenge_method', opts.pkce.codeChallengeMethod);
  return url.toString();
};

interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
  id_token?: string;
}

// Fallback lifetime when the provider omits expires_in. Populating expiresAtMs
// unconditionally guarantees the SDK's requireBearerAuth never sees an
// undefined AuthInfo.expiresAt (which it treats as an error and 401s on).
const DEFAULT_UPSTREAM_TTL_SEC = 3600;

const toUpstreamToken = (r: TokenResponse): UpstreamToken => ({
  accessToken: r.access_token,
  refreshToken: r.refresh_token,
  idToken: r.id_token,
  expiresAtMs: Date.now() + (r.expires_in ?? DEFAULT_UPSTREAM_TTL_SEC) * 1000
});

const MAX_DESCRIPTION = 160;

// The token endpoint refused a request. Dex answers a refresh token it no
// longer knows (unknown, already rotated, expired, or lost in a Dex restart)
// with 400 invalid_request, and a client mismatch with 400 invalid_grant:
// those mean the login cannot be renewed. Everything else (401
// invalid_client from a wrong client secret, 5xx, an unreadable body) is a
// configuration fault or transient, and must not end anyone's login.
//
// The message carries only the status and the OAuth error code, because it
// can reach the MCP client as a tool error. Dex's free-text description is
// kept apart, for logs.
export class UpstreamTokenError extends Error {
  public readonly description?: string;

  constructor(
    public readonly status: number,
    public readonly oauthError?: string,
    description?: string
  ) {
    super(`Upstream token endpoint returned ${status}` + (oauthError ? `: ${oauthError}` : ''));
    this.name = 'UpstreamTokenError';
    this.description =
      description && description.length > MAX_DESCRIPTION
        ? `${description.slice(0, MAX_DESCRIPTION)}...`
        : description;
  }

  get grantRejected(): boolean {
    return (
      this.status === 400 &&
      (this.oauthError === 'invalid_request' || this.oauthError === 'invalid_grant')
    );
  }
}

// What to log about a failed token request: the message plus Dex's reason.
export const describeTokenError = (error: unknown): string => {
  if (error instanceof UpstreamTokenError) {
    return error.description ? `${error.message} (${error.description})` : error.message;
  }
  return error instanceof Error ? error.message : String(error);
};

// Only the RFC 6749 error fields are read from the body; they carry no token.
const readOAuthError = async (res: Response): Promise<{ error?: string; description?: string }> => {
  try {
    const body = (await res.json()) as { error?: unknown; error_description?: unknown };
    return {
      error: typeof body.error === 'string' ? body.error : undefined,
      description: typeof body.error_description === 'string' ? body.error_description : undefined
    };
  } catch {
    return {};
  }
};

const postToken = async (
  meta: OidcProviderMetadata,
  params: URLSearchParams,
  fetchImpl: typeof fetch
): Promise<UpstreamToken> => {
  const res = await fetchImpl(meta.tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: params.toString()
  });
  if (!res.ok) {
    const { error, description } = await readOAuthError(res);
    throw new UpstreamTokenError(res.status, error, description);
  }
  return toUpstreamToken((await res.json()) as TokenResponse);
};

// Exchange an authorization code for tokens using the confidential client
// (client_secret) plus the PKCE verifier.
export const exchangeCode = async (
  meta: OidcProviderMetadata,
  opts: {
    clientId: string;
    clientSecret: string;
    code: string;
    redirectUri: string;
    codeVerifier: string;
  },
  fetchImpl: typeof fetch = fetch
): Promise<UpstreamToken> => {
  const params = new URLSearchParams();
  params.set('grant_type', 'authorization_code');
  params.set('client_id', opts.clientId);
  params.set('client_secret', opts.clientSecret);
  params.set('code', opts.code);
  params.set('redirect_uri', opts.redirectUri);
  params.set('code_verifier', opts.codeVerifier);
  return postToken(meta, params, fetchImpl);
};

export const refreshUpstream = async (
  meta: OidcProviderMetadata,
  opts: { clientId: string; clientSecret: string; refreshToken: string },
  fetchImpl: typeof fetch = fetch
): Promise<UpstreamToken> => {
  const params = new URLSearchParams();
  params.set('grant_type', 'refresh_token');
  params.set('client_id', opts.clientId);
  params.set('client_secret', opts.clientSecret);
  params.set('refresh_token', opts.refreshToken);
  return postToken(meta, params, fetchImpl);
};
