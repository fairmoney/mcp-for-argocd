import { readFileSync } from 'node:fs';

export type AuthMode = 'token' | 'oidc';

export interface OidcConfig {
  publicUrl: string; // https, no trailing slash
  argocdBaseUrl: string;
  clientId: string;
  clientSecret: string;
  callbackPath: string; // '/oauth/callback'
  callbackUrl: string; // publicUrl + callbackPath
  tokenStore: 'memory' | 'redis';
  redisUrl?: string;
  encryptionKey?: Buffer;
}

const CALLBACK_PATH = '/oauth/callback';

// Read AUTH_MODE; default to today's token-based behavior. Reject typos loudly
// so a misspelled mode never silently falls back to the wrong behavior.
export const resolveAuthMode = (env: NodeJS.ProcessEnv = process.env): AuthMode => {
  const raw = (env.AUTH_MODE ?? '').trim().toLowerCase();
  if (raw === '' || raw === 'token') return 'token';
  if (raw === 'oidc') return 'oidc';
  throw new Error(`Invalid AUTH_MODE "${env.AUTH_MODE}": expected "token" or "oidc"`);
};

const readSecretFile = (path: string | undefined, label: string): string => {
  if (!path || !path.trim()) {
    throw new Error(`Missing required ${label} file path`);
  }
  try {
    return readFileSync(path.trim(), 'utf8').trim();
  } catch (error) {
    throw new Error(
      `Failed to read ${label} file at "${path}": ${error instanceof Error ? error.message : String(error)}`
    );
  }
};

const stripTrailingSlashes = (s: string): string => s.replace(/\/+$/, '');

// Build and validate the oidc-mode config. Fails closed: throws on any missing
// or malformed input so the process crashes at startup rather than serving a
// broken auth flow.
export const loadOidcConfig = (env: NodeJS.ProcessEnv = process.env): OidcConfig => {
  const publicUrlRaw = (env.MCP_PUBLIC_URL ?? '').trim();
  if (!publicUrlRaw) throw new Error('oidc mode requires MCP_PUBLIC_URL');
  let publicUrl: URL;
  try {
    publicUrl = new URL(publicUrlRaw);
  } catch {
    throw new Error(`MCP_PUBLIC_URL is not a valid URL: "${publicUrlRaw}"`);
  }
  if (publicUrl.protocol !== 'https:') {
    throw new Error(`MCP_PUBLIC_URL must use https (got "${publicUrl.protocol}")`);
  }

  const argocdBaseUrlRaw = (env.ARGOCD_BASE_URL ?? '').trim();
  if (!argocdBaseUrlRaw) throw new Error('oidc mode requires ARGOCD_BASE_URL');
  let argocdUrl: URL;
  try {
    argocdUrl = new URL(argocdBaseUrlRaw);
  } catch {
    throw new Error(`ARGOCD_BASE_URL is not a valid URL: "${argocdBaseUrlRaw}"`);
  }
  // ArgoCD may be reached over either http (in-cluster) or https.
  if (argocdUrl.protocol !== 'http:' && argocdUrl.protocol !== 'https:') {
    throw new Error(`ARGOCD_BASE_URL must use http or https (got "${argocdUrl.protocol}")`);
  }
  const argocdBaseUrl = stripTrailingSlashes(argocdBaseUrlRaw);

  const clientId = (env.ARGOCD_MCP_OIDC_CLIENT_ID ?? '').trim();
  if (!clientId) throw new Error('oidc mode requires ARGOCD_MCP_OIDC_CLIENT_ID');

  const clientSecret = readSecretFile(
    env.ARGOCD_MCP_OIDC_CLIENT_SECRET_FILE,
    'OIDC client secret (ARGOCD_MCP_OIDC_CLIENT_SECRET_FILE)'
  );

  const tokenStoreRaw = (env.TOKEN_STORE ?? 'memory').trim().toLowerCase();
  if (tokenStoreRaw !== 'memory' && tokenStoreRaw !== 'redis') {
    throw new Error(`Invalid TOKEN_STORE "${env.TOKEN_STORE}": expected "memory" or "redis"`);
  }
  const tokenStore = tokenStoreRaw as 'memory' | 'redis';

  let redisUrl: string | undefined;
  if (tokenStore === 'redis') {
    redisUrl = (env.REDIS_URL ?? '').trim();
    if (!redisUrl) throw new Error('TOKEN_STORE=redis requires REDIS_URL');
  }

  let encryptionKey: Buffer | undefined;
  if (env.TOKEN_STORE_ENCRYPTION_KEY_FILE) {
    const keyText = readSecretFile(
      env.TOKEN_STORE_ENCRYPTION_KEY_FILE,
      'token store encryption key (TOKEN_STORE_ENCRYPTION_KEY_FILE)'
    );
    // Accept a 32-byte key given as 64 hex chars or 32 raw bytes.
    encryptionKey = /^[0-9a-fA-F]{64}$/.test(keyText)
      ? Buffer.from(keyText, 'hex')
      : Buffer.from(keyText, 'utf8');
    if (encryptionKey.length !== 32) {
      throw new Error('TOKEN_STORE_ENCRYPTION_KEY must be 32 bytes (AES-256)');
    }
  }

  const normalizedPublic = stripTrailingSlashes(publicUrl.toString());
  return {
    publicUrl: normalizedPublic,
    argocdBaseUrl,
    clientId,
    clientSecret,
    callbackPath: CALLBACK_PATH,
    callbackUrl: `${normalizedPublic}${CALLBACK_PATH}`,
    tokenStore,
    redisUrl,
    encryptionKey
  };
};
