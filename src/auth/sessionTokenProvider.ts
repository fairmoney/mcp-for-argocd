import type { OidcConfig } from './config.js';
import type { OidcProviderMetadata } from './types.js';
import type { TokenStore } from './tokenStore.js';
import type { BearerTokenProvider } from '../argocd/http.js';
import { describeTokenError, refreshUpstream, UpstreamTokenError } from './oauth.js';
import { logger } from '../logging/logging.js';

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
  // Concurrency: refreshes from this provider (one HTTP session) are
  // de-duplicated in flight, so parallel tool calls share one refresh. A
  // refresh racing another path (a client refresh, or another HTTP session of
  // the same login) can still present a token Dex has just rotated away; that
  // is detected by re-reading the session record, and the refresh is retried
  // with the rotated token instead of ending the login. No distributed lock.
  //
  // A login whose upstream token can no longer be renewed is revoked: the
  // opaque access token and the session record are deleted, so the next MCP
  // request fails the bearer check with a 401 and the client signs in again
  // (verifyAccessToken also refuses any other access token of a login whose
  // session record is gone). Keeping them would let the MCP go on accepting a
  // login that ArgoCD refuses, with nothing telling the client to sign in.
  const revoke = async (sessionId: string, reason: string): Promise<void> => {
    await store.deleteAccessToken(opaqueAccessToken);
    await store.deleteSession(sessionId);
    logger.warn({ reason }, 'Upstream token cannot be renewed; login revoked');
  };

  const refreshOnce = async (retried: boolean): Promise<string> => {
    const stored = await store.getAccessToken(opaqueAccessToken);
    if (!stored) throw new Error('Session token not found (expired or revoked)');
    const session = await store.getSession(stored.sessionId);
    if (!session) {
      // No refresh token was ever issued (Dex's SAML connector issues none)
      // or the login was ended: ArgoCD refused the token and it cannot be
      // renewed.
      await revoke(stored.sessionId, 'no upstream refresh token');
      throw new Error(
        'No upstream refresh token available for this session; the login was revoked, sign in again'
      );
    }
    let next;
    try {
      next = await refreshUpstream(meta, {
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        refreshToken: session.upstreamRefreshToken
      });
    } catch (error) {
      if (error instanceof UpstreamTokenError && error.grantRejected) {
        const now = await store.getSession(stored.sessionId);
        if (now && now.upstreamRefreshToken !== session.upstreamRefreshToken && !retried) {
          // Another path rotated the token while we were refreshing.
          return refreshOnce(true);
        }
        if (now && now.upstreamRefreshToken !== session.upstreamRefreshToken) throw error;
        await revoke(stored.sessionId, describeTokenError(error));
      } else {
        // Configuration fault or transient: keep the login.
        logger.warn({ reason: describeTokenError(error) }, 'Upstream token refresh failed');
      }
      throw error;
    }
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

  let inFlight: Promise<string> | undefined;
  const doRefresh = (): Promise<string> => {
    if (!inFlight) {
      inFlight = refreshOnce(false).finally(() => {
        inFlight = undefined;
      });
    }
    return inFlight;
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
