import type { Response } from 'express';
import type {
  OAuthServerProvider,
  AuthorizationParams
} from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type {
  OAuthClientInformationFull,
  OAuthTokens
} from '@modelcontextprotocol/sdk/shared/auth.js';
import { randomBytes } from 'node:crypto';
import type { OidcConfig } from './config.js';
import type { OidcProviderMetadata } from './types.js';
import type { TokenStore } from './tokenStore.js';
import {
  buildAuthorizeUrl,
  exchangeCode,
  generateOpaqueToken,
  generatePkce,
  generateState,
  refreshUpstream
} from './oauth.js';
import { logger } from '../logging/logging.js';

const PENDING_TTL_SEC = 600; // 10 min to complete the upstream login
const CODE_TTL_SEC = 300; // 5 min to redeem our authorization code
const DEFAULT_SCOPES = ['openid', 'profile', 'email', 'groups', 'offline_access'];

export interface OAuthProxyProviderDeps {
  config: OidcConfig;
  store: TokenStore;
  discover: () => Promise<OidcProviderMetadata>;
  fetchImpl?: typeof fetch;
}

// Proxies MCP OAuth 2.1 to ArgoCD's Dex. MCP clients register with us and speak
// OAuth to us; we run the real Auth-Code + PKCE flow against Dex with our
// confidential client. The MCP client only ever receives an opaque token; the
// real Dex-minted token is kept in the TokenStore and forwarded to ArgoCD.
export class OAuthProxyProvider implements OAuthServerProvider {
  // We validate the MCP client's PKCE locally (challengeForAuthorizationCode),
  // so the SDK must not forward the verifier upstream.
  readonly skipLocalPkceValidation = false;
  private config: OidcConfig;
  private store: TokenStore;
  private discover: () => Promise<OidcProviderMetadata>;
  private fetchImpl: typeof fetch;
  private metaCache?: OidcProviderMetadata;

  constructor(deps: OAuthProxyProviderDeps) {
    this.config = deps.config;
    this.store = deps.store;
    this.discover = deps.discover;
    this.fetchImpl = deps.fetchImpl ?? fetch;
  }

  private async meta(): Promise<OidcProviderMetadata> {
    if (!this.metaCache) this.metaCache = await this.discover();
    return this.metaCache;
  }

  get clientsStore(): OAuthRegisteredClientsStore {
    return {
      getClient: (clientId: string) => this.store.getClient(clientId),
      registerClient: async (metadata) => {
        const client: OAuthClientInformationFull = {
          ...metadata,
          client_id: randomBytes(16).toString('hex'),
          client_id_issued_at: Math.floor(Date.now() / 1000)
        };
        await this.store.putClient(client);
        logger.info({ clientId: client.client_id }, 'Registered MCP OAuth client');
        return client;
      }
    };
  }

  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: Response
  ): Promise<void> {
    const meta = await this.meta();
    const upstreamPkce = generatePkce();
    const upstreamState = generateState();

    await this.store.putPendingAuth(
      upstreamState,
      {
        upstreamState,
        upstreamPkce,
        clientRedirectUri: params.redirectUri,
        clientState: params.state,
        clientCodeChallenge: params.codeChallenge,
        clientId: client.client_id
      },
      PENDING_TTL_SEC
    );

    const url = buildAuthorizeUrl(meta, {
      clientId: this.config.clientId,
      redirectUri: this.config.callbackUrl,
      scopes: meta.scopesSupported?.length ? meta.scopesSupported : DEFAULT_SCOPES,
      state: upstreamState,
      pkce: upstreamPkce
    });
    logger.info({ clientId: client.client_id }, 'Redirecting to upstream OIDC provider');
    res.redirect(url);
  }

  // Called by the /oauth/callback route. Exchanges the Dex code for the upstream
  // token, mints our own authorization code, and returns the MCP client redirect.
  async handleUpstreamCallback(code: string, state: string): Promise<string> {
    const pending = await this.store.takePendingAuth(state);
    if (!pending) throw new Error('Unknown or expired authorization state');

    const meta = await this.meta();
    const upstream = await exchangeCode(
      meta,
      {
        clientId: this.config.clientId,
        clientSecret: this.config.clientSecret,
        code,
        redirectUri: this.config.callbackUrl,
        codeVerifier: pending.upstreamPkce.codeVerifier
      },
      this.fetchImpl
    );

    const ourCode = generateOpaqueToken();
    await this.store.putAuthCode(
      ourCode,
      {
        upstream,
        clientRedirectUri: pending.clientRedirectUri,
        clientState: pending.clientState,
        clientCodeChallenge: pending.clientCodeChallenge,
        clientId: pending.clientId
      },
      CODE_TTL_SEC
    );

    const redirect = new URL(pending.clientRedirectUri);
    redirect.searchParams.set('code', ourCode);
    if (pending.clientState) redirect.searchParams.set('state', pending.clientState);
    logger.info(
      { clientId: pending.clientId },
      'Upstream auth complete; redirecting to MCP client'
    );
    return redirect.toString();
  }

  async challengeForAuthorizationCode(
    _client: OAuthClientInformationFull,
    authorizationCode: string
  ): Promise<string> {
    // The SDK's token handler calls this BEFORE exchangeAuthorizationCode with
    // the same code, so we must not consume it here. The store only exposes
    // get-and-delete semantics, so take the record and immediately re-store it.
    const completed = await this.store.takeAuthCode(authorizationCode);
    if (!completed) throw new Error('Unknown or expired authorization code');
    await this.store.putAuthCode(authorizationCode, completed, CODE_TTL_SEC);
    return completed.clientCodeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string
  ): Promise<OAuthTokens> {
    const completed = await this.store.takeAuthCode(authorizationCode);
    if (!completed) throw new Error('Unknown or expired authorization code');

    const opaqueAccess = generateOpaqueToken();
    const opaqueRefresh = completed.upstream.refreshToken ? generateOpaqueToken() : undefined;
    const ttlSec = completed.upstream.expiresAtMs
      ? Math.max(1, Math.floor((completed.upstream.expiresAtMs - Date.now()) / 1000))
      : undefined;

    await this.store.putAccessToken(
      opaqueAccess,
      { upstream: completed.upstream, clientId: client.client_id },
      ttlSec
    );
    if (opaqueRefresh && completed.upstream.refreshToken) {
      await this.store.putRefreshToken(opaqueRefresh, {
        upstreamRefreshToken: completed.upstream.refreshToken,
        clientId: client.client_id
      });
    }

    return {
      access_token: opaqueAccess,
      token_type: 'Bearer',
      expires_in: ttlSec,
      refresh_token: opaqueRefresh
    };
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string
  ): Promise<OAuthTokens> {
    const record = await this.store.getRefreshToken(refreshToken);
    if (!record) throw new Error('Unknown or expired refresh token');
    const meta = await this.meta();

    const upstream = await refreshUpstream(
      meta,
      {
        clientId: this.config.clientId,
        clientSecret: this.config.clientSecret,
        refreshToken: record.upstreamRefreshToken
      },
      this.fetchImpl
    );

    const opaqueAccess = generateOpaqueToken();
    const opaqueRefresh = upstream.refreshToken ? generateOpaqueToken() : undefined;
    const ttlSec = upstream.expiresAtMs
      ? Math.max(1, Math.floor((upstream.expiresAtMs - Date.now()) / 1000))
      : undefined;

    await this.store.putAccessToken(opaqueAccess, { upstream, clientId: client.client_id }, ttlSec);
    await this.store.deleteRefreshToken(refreshToken);
    if (opaqueRefresh && upstream.refreshToken) {
      await this.store.putRefreshToken(opaqueRefresh, {
        upstreamRefreshToken: upstream.refreshToken,
        clientId: client.client_id
      });
    }

    return {
      access_token: opaqueAccess,
      token_type: 'Bearer',
      expires_in: ttlSec,
      refresh_token: opaqueRefresh
    };
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const stored = await this.store.getAccessToken(token);
    if (!stored) throw new Error('Invalid or expired access token');
    return {
      token,
      clientId: stored.clientId,
      scopes: [],
      expiresAt: stored.upstream.expiresAtMs
        ? Math.floor(stored.upstream.expiresAtMs / 1000)
        : undefined,
      extra: {
        argocdToken: stored.upstream.accessToken,
        argocdBaseUrl: this.config.argocdBaseUrl
      }
    };
  }
}
