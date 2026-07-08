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

  // Refresh the upstream token using the shared per-session refresh token, then
  // write the rotated refresh token back to the same session record so the
  // client-facing path (exchangeRefreshToken) sees it too. Both paths reading
  // and writing this one record is what keeps them in sync across Dex's
  // refresh-token rotation.
  //
  // Known limitation: two SIMULTANEOUS refreshes (a client proactive refresh and
  // a server-side mid-request refresh within the same instant) can still race on
  // Dex — one may present a refresh token the other has already rotated away.
  // The shared record makes SEQUENTIAL refreshes (the common case) correct. We
  // deliberately do NOT add distributed locking here.
  const doRefresh = async (): Promise<string> => {
    const stored = await store.getAccessToken(opaqueAccessToken);
    if (!stored) throw new Error('Session token not found (expired or revoked)');
    const session = await store.getSession(stored.sessionId);
    if (!session) throw new Error('No upstream refresh token available for this session');
    const next = await refreshUpstream(meta, {
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      refreshToken: session.upstreamRefreshToken
    });
    if (next.refreshToken) {
      await store.putSession(stored.sessionId, {
        upstreamRefreshToken: next.refreshToken,
        clientId: session.clientId
      });
    }
    const ttlSec = next.expiresAtMs
      ? Math.max(1, Math.floor((next.expiresAtMs - Date.now()) / 1000))
      : undefined;
    await store.putAccessToken(
      opaqueAccessToken,
      { upstream: next, clientId: session.clientId, sessionId: stored.sessionId },
      ttlSec
    );
    return next.accessToken;
  };

  return {
    async current(): Promise<string> {
      const stored = await store.getAccessToken(opaqueAccessToken);
      if (!stored) throw new Error('Session token not found (expired or revoked)');
      const exp = stored.upstream.expiresAtMs;
      // Only attempt a proactive refresh when this session actually has an
      // upstream refresh token; otherwise keep using the token until it expires.
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
