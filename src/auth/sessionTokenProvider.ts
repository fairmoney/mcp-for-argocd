import type { OidcConfig } from './config.js';
import type { OidcProviderMetadata } from './types.js';
import type { TokenStore } from './tokenStore.js';
import type { BearerTokenProvider } from '../argocd/http.js';
import { refreshUpstream } from './oauth.js';

// Bridges an issued opaque access token to a live upstream bearer for the
// ArgoCD HttpClient. current() returns the stored upstream token, refreshing it
// when expired/near-expiry; refresh() forces a refresh (called on a 401).
export const makeSessionTokenProvider = (
  store: TokenStore,
  meta: OidcProviderMetadata,
  config: OidcConfig,
  opaqueAccessToken: string
): BearerTokenProvider => {
  const SKEW_MS = 30_000;

  const doRefresh = async (): Promise<string> => {
    const stored = await store.getAccessToken(opaqueAccessToken);
    if (!stored?.upstream.refreshToken) {
      throw new Error('No upstream refresh token available for this session');
    }
    const next = await refreshUpstream(meta, {
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      refreshToken: stored.upstream.refreshToken
    });
    await store.putAccessToken(opaqueAccessToken, { upstream: next, clientId: stored.clientId });
    return next.accessToken;
  };

  return {
    async current(): Promise<string> {
      const stored = await store.getAccessToken(opaqueAccessToken);
      if (!stored) throw new Error('Session token not found (expired or revoked)');
      const exp = stored.upstream.expiresAtMs;
      if (exp && Date.now() > exp - SKEW_MS && stored.upstream.refreshToken) {
        return doRefresh();
      }
      return stored.upstream.accessToken;
    },
    refresh(): Promise<string> {
      return doRefresh();
    }
  };
};
