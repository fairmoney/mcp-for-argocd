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

// Resolve the Redis connection URL for the token store.
//
// Precedence: an explicit REDIS_URL wins (the caller fully controls scheme,
// auth, and TLS). Otherwise build one from the discrete AWS-style vars:
// REDIS_ENDPOINT (host) + REDIS_PORT (default 6379). TLS is on by default
// (rediss://) because ElastiCache Serverless mandates it; set REDIS_TLS=false
// for a plaintext/self-hosted Redis.
//
// NOTE: only the primary/writer endpoint is used. The token store relies on
// read-after-write consistency (e.g. putAuthCode then takeAuthCode), so reads
// must not be served from a possibly-lagging replica — REDIS_READER_ENDPOINT is
// intentionally not consumed.
export const buildRedisUrl = (env: NodeJS.ProcessEnv = process.env): string | undefined => {
  const explicit = (env.REDIS_URL ?? '').trim();
  if (explicit) return explicit;

  const endpoint = (env.REDIS_ENDPOINT ?? '').trim();
  if (!endpoint) return undefined;

  const port = (env.REDIS_PORT ?? '').trim() || '6379';
  if (!/^\d+$/.test(port)) {
    throw new Error(`Invalid REDIS_PORT "${env.REDIS_PORT}": expected a port number`);
  }
  const useTls = (env.REDIS_TLS ?? 'true').trim().toLowerCase() !== 'false';
  return `${useTls ? 'rediss' : 'redis'}://${endpoint}:${port}`;
};

// Resolve the OIDC client secret, preferring a direct env var over a file.
// ARGOCD_MCP_OIDC_CLIENT_SECRET wins when set (non-blank); otherwise fall back
// to reading ARGOCD_MCP_OIDC_CLIENT_SECRET_FILE. Both paths trim, so a stray
// trailing newline (common with secretKeyRef injection) is harmless. Fails
// closed if neither source yields a value.
const resolveClientSecret = (env: NodeJS.ProcessEnv): string => {
  const direct = (env.ARGOCD_MCP_OIDC_CLIENT_SECRET ?? '').trim();
  if (direct) return direct;

  const filePath = env.ARGOCD_MCP_OIDC_CLIENT_SECRET_FILE;
  if (!filePath || !filePath.trim()) {
    throw new Error(
      'oidc mode requires the OIDC client secret via ARGOCD_MCP_OIDC_CLIENT_SECRET or ARGOCD_MCP_OIDC_CLIENT_SECRET_FILE'
    );
  }
  return readSecretFile(filePath, 'OIDC client secret (ARGOCD_MCP_OIDC_CLIENT_SECRET_FILE)');
};

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

  const clientSecret = resolveClientSecret(env);

  const tokenStoreRaw = (env.TOKEN_STORE ?? 'memory').trim().toLowerCase();
  if (tokenStoreRaw !== 'memory' && tokenStoreRaw !== 'redis') {
    throw new Error(`Invalid TOKEN_STORE "${env.TOKEN_STORE}": expected "memory" or "redis"`);
  }
  const tokenStore = tokenStoreRaw as 'memory' | 'redis';

  let redisUrl: string | undefined;
  if (tokenStore === 'redis') {
    redisUrl = buildRedisUrl(env);
    if (!redisUrl) throw new Error('TOKEN_STORE=redis requires REDIS_URL or REDIS_ENDPOINT');
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
