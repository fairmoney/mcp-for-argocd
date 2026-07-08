import type { OidcProviderMetadata } from './types.js';
import { logger } from '../logging/logging.js';

export class SSONotConfiguredError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SSONotConfiguredError';
  }
}

// Shape we care about from ArgoCD's /api/v1/settings response.
interface ArgoSettings {
  dexConfig?: { connectors?: unknown[] };
  oidcConfig?: { issuer?: string; clientID?: string; cliClientID?: string };
}

interface WellKnown {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  scopes_supported?: string[];
}

const stripTrailingSlashes = (s: string): string => s.replace(/\/+$/, '');

// Derive OIDC provider endpoints for the given ArgoCD instance. Bundled Dex is
// preferred: its endpoints are well-known under /api/dex, so we construct them
// directly (Dex behind ArgoCD does not always expose a reachable discovery doc
// at its issuer for server-to-server calls). External OIDC is resolved from the
// provider's discovery document.
export const discoverOidc = async (
  argocdBaseUrl: string,
  fetchImpl: typeof fetch = fetch
): Promise<OidcProviderMetadata> => {
  const base = stripTrailingSlashes(argocdBaseUrl);
  const settingsUrl = `${base}/api/v1/settings`;
  const res = await fetchImpl(settingsUrl, { headers: { Accept: 'application/json' } });
  if (!res.ok) {
    throw new Error(`Failed to fetch ArgoCD settings (${res.status}) from ${settingsUrl}`);
  }
  const settings = (await res.json()) as ArgoSettings;

  if (settings.dexConfig?.connectors?.length) {
    logger.info({ argocdBaseUrl: base }, 'Discovered bundled Dex OIDC provider');
    return {
      issuer: `${base}/api/dex`,
      authorizationEndpoint: `${base}/api/dex/auth`,
      tokenEndpoint: `${base}/api/dex/token`,
      userinfoEndpoint: `${base}/api/dex/userinfo`,
      scopesSupported: ['openid', 'profile', 'email', 'groups', 'offline_access']
    };
  }

  const issuer = settings.oidcConfig?.issuer;
  if (!issuer) {
    throw new SSONotConfiguredError(
      'SSO is not configured on this ArgoCD server: neither dexConfig connectors nor oidcConfig.issuer is present.'
    );
  }
  const wellKnownUrl = `${stripTrailingSlashes(issuer)}/.well-known/openid-configuration`;
  const wkRes = await fetchImpl(wellKnownUrl, { headers: { Accept: 'application/json' } });
  if (!wkRes.ok) {
    throw new Error(`Failed to fetch OIDC discovery (${wkRes.status}) from ${wellKnownUrl}`);
  }
  const wk = (await wkRes.json()) as WellKnown;
  logger.info({ issuer: wk.issuer }, 'Discovered external OIDC provider');
  return {
    issuer: wk.issuer,
    authorizationEndpoint: wk.authorization_endpoint,
    tokenEndpoint: wk.token_endpoint,
    userinfoEndpoint: wk.userinfo_endpoint,
    scopesSupported: wk.scopes_supported
  };
};
