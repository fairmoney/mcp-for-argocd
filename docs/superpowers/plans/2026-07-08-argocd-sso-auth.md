# ArgoCD SSO Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in `oidc` auth mode to the HTTP transport so the server runs in-cluster behind an ingress and lets users log in via ArgoCD's native browser SSO, forwarding each user's own identity to the ArgoCD API.

**Architecture:** The server becomes an OAuth 2.1 authorization-server facade in front of ArgoCD's bundled Dex. MCP clients register with the server (DCR), the server proxies the Auth-Code + PKCE flow to Dex using a dedicated confidential client, issues the MCP client an opaque token, and keeps the real Dex-minted token server-side (in a memory or Redis `TokenStore`) to forward to ArgoCD per request. A lazy `HttpClient` refreshes the upstream token transparently.

**Tech Stack:** TypeScript (ESM, `.js` import suffixes), `@modelcontextprotocol/sdk` ^1.29 auth framework (`mcpAuthRouter`, `requireBearerAuth`, `OAuthServerProvider`), express 5, `ioredis` (new), `pino`. Tests: `node:test` + `node:assert/strict`, run with `pnpm test`.

## Global Constraints

- Language/module: TypeScript, ESM. All relative imports use the `.js` extension. `"type": "module"`.
- Tests: `node:test` (`import { test } from 'node:test'`) + `import assert from 'node:assert/strict'`. Colocated `*.test.ts`. Run all: `pnpm test`. Run one file: `node --import tsx --test src/path/file.test.ts`.
- Lint/format: `pnpm lint` (eslint + prettier). Prettier: single quotes, semicolons, width 100 (`.prettierrc`).
- Logging: `import { logger } from '../logging/logging.js'` (pino). **Never log secrets** (client secret, tokens, code verifiers).
- Secrets are read from **files**, not env values (matches `ARGOCD_TOKEN_REGISTRY_PATH`). Env vars point at file paths.
- Existing behavior (stdio, static token, token registry, per-call base URL, SSE, stateless HTTP) MUST be unchanged when `AUTH_MODE` is unset or `token`.
- New dependency: `ioredis` (prod), `ioredis-mock` (dev, for hermetic store tests).
- Fail closed: any misconfiguration in `oidc` mode throws at startup and exits non-zero.

---

## File Structure

Created:
- `src/auth/types.ts` — shared auth types (no logic).
- `src/auth/config.ts` — env parsing + startup validation.
- `src/auth/oidcDiscovery.ts` — derive OIDC endpoints from ArgoCD `/api/v1/settings`.
- `src/auth/oauth.ts` — PKCE/state/opaque-token helpers + Dex code/refresh exchange.
- `src/auth/tokenStore.ts` — `TokenStore` interface + record types.
- `src/auth/tokenStore.contract.ts` — shared contract test (imported, not auto-run).
- `src/auth/inMemoryTokenStore.ts` — `Map`-backed store.
- `src/auth/redisTokenStore.ts` — `ioredis`-backed store + optional AES-256-GCM at rest.
- `src/auth/tokenStoreFactory.ts` — pick a store from config.
- `src/auth/oauthProxyProvider.ts` — `OAuthServerProvider` implementation.
- `src/auth/sessionTokenProvider.ts` — per-session lazy bearer provider for `HttpClient`.
- Tests: `*.test.ts` beside each of the above with logic.

Modified:
- `src/argocd/http.ts` — accept a lazy token source; 401 refresh-and-retry.
- `src/argocd/client.ts` — thread the token source through.
- `src/server/server.ts` — pin base URL in `oidc` mode.
- `src/server/transport.ts` — `oidc` branch: mount auth router, callback route, bearer-protected `/mcp`.
- `src/cmd/cmd.ts` — no new flags required (config is env-driven); documented in README.
- `package.json` — add `ioredis`, `ioredis-mock`.
- `README.md` — SSO mode + ArgoCD Dex client + k8s manifests.

---

## Task 1: Shared types and auth configuration

**Files:**
- Create: `src/auth/types.ts`, `src/auth/config.ts`
- Test: `src/auth/config.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `src/auth/types.ts`: `interface OidcProviderMetadata { issuer, authorizationEndpoint, tokenEndpoint, userinfoEndpoint?, scopesSupported?: string[] }`; `interface PkceChallenge { codeVerifier: string; codeChallenge: string; codeChallengeMethod: 'S256' }`; `interface UpstreamToken { accessToken: string; refreshToken?: string; idToken?: string; expiresAtMs?: number }`.
  - `src/auth/config.ts`: `type AuthMode = 'token' | 'oidc'`; `interface OidcConfig { publicUrl: string; argocdBaseUrl: string; clientId: string; clientSecret: string; callbackPath: string; callbackUrl: string; tokenStore: 'memory' | 'redis'; redisUrl?: string; encryptionKey?: Buffer }`; `resolveAuthMode(env?): AuthMode`; `loadOidcConfig(env?): OidcConfig` (throws on invalid).

- [ ] **Step 1: Write `src/auth/types.ts`**

```ts
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
```

- [ ] **Step 2: Write the failing test `src/auth/config.test.ts`**

```ts
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolveAuthMode, loadOidcConfig } from './config.js';

const withSecretFile = (contents: string): { path: string; cleanup: () => void } => {
  const dir = mkdtempSync(join(tmpdir(), 'auth-config-test-'));
  const path = join(dir, 'secret');
  writeFileSync(path, contents, 'utf8');
  return { path, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
};

// A minimal valid env for oidc mode, parameterized by the secret file path.
const validEnv = (secretPath: string): NodeJS.ProcessEnv => ({
  AUTH_MODE: 'oidc',
  MCP_PUBLIC_URL: 'https://argocd-mcp.example.com/',
  ARGOCD_BASE_URL: 'https://argocd.example.com',
  ARGOCD_MCP_OIDC_CLIENT_ID: 'argocd-mcp',
  ARGOCD_MCP_OIDC_CLIENT_SECRET_FILE: secretPath
});

test('resolveAuthMode defaults to token when unset', () => {
  assert.equal(resolveAuthMode({}), 'token');
});

test('resolveAuthMode reads oidc', () => {
  assert.equal(resolveAuthMode({ AUTH_MODE: 'oidc' }), 'oidc');
});

test('resolveAuthMode rejects unknown modes', () => {
  assert.throws(() => resolveAuthMode({ AUTH_MODE: 'sso' }), /AUTH_MODE/);
});

test('loadOidcConfig parses a valid env, trims trailing slash, builds callbackUrl', () => {
  const { path, cleanup } = withSecretFile('  s3cret\n');
  try {
    const cfg = loadOidcConfig(validEnv(path));
    assert.equal(cfg.publicUrl, 'https://argocd-mcp.example.com');
    assert.equal(cfg.callbackUrl, 'https://argocd-mcp.example.com/oauth/callback');
    assert.equal(cfg.clientSecret, 's3cret'); // trimmed
    assert.equal(cfg.tokenStore, 'memory');
  } finally {
    cleanup();
  }
});

test('loadOidcConfig rejects a non-https public URL', () => {
  const { path, cleanup } = withSecretFile('s');
  try {
    assert.throws(
      () => loadOidcConfig({ ...validEnv(path), MCP_PUBLIC_URL: 'http://mcp.example.com' }),
      /https/
    );
  } finally {
    cleanup();
  }
});

test('loadOidcConfig requires REDIS_URL when TOKEN_STORE=redis', () => {
  const { path, cleanup } = withSecretFile('s');
  try {
    assert.throws(
      () => loadOidcConfig({ ...validEnv(path), TOKEN_STORE: 'redis' }),
      /REDIS_URL/
    );
  } finally {
    cleanup();
  }
});

test('loadOidcConfig throws a clear error when the secret file is missing', () => {
  assert.throws(
    () => loadOidcConfig(validEnv('/does/not/exist')),
    /client secret/i
  );
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `node --import tsx --test src/auth/config.test.ts`
Expected: FAIL — cannot find module `./config.js`.

- [ ] **Step 4: Write `src/auth/config.ts`**

```ts
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

  const argocdBaseUrl = stripTrailingSlashes((env.ARGOCD_BASE_URL ?? '').trim());
  if (!argocdBaseUrl) throw new Error('oidc mode requires ARGOCD_BASE_URL');

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
```

- [ ] **Step 5: Run test to verify it passes**

Run: `node --import tsx --test src/auth/config.test.ts`
Expected: PASS (7 tests).

- [ ] **Step 6: Lint & commit**

```bash
pnpm lint
git add src/auth/types.ts src/auth/config.ts src/auth/config.test.ts
git commit -m "feat(auth): add oidc auth config parsing and startup validation"
```

---

## Task 2: OIDC discovery from ArgoCD settings

**Files:**
- Create: `src/auth/oidcDiscovery.ts`
- Test: `src/auth/oidcDiscovery.test.ts`

**Interfaces:**
- Consumes: `OidcProviderMetadata` (Task 1).
- Produces:
  - `class SSONotConfiguredError extends Error`.
  - `async function discoverOidc(argocdBaseUrl: string, fetchImpl?: typeof fetch): Promise<OidcProviderMetadata>` — returns Dex endpoints when `dexConfig.connectors` is present, else external OIDC via `.well-known`. Throws `SSONotConfiguredError` when neither is configured.

- [ ] **Step 1: Write the failing test `src/auth/oidcDiscovery.test.ts`**

```ts
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { discoverOidc, SSONotConfiguredError } from './oidcDiscovery.js';

// Build a fake fetch that returns `settings` for /api/v1/settings and
// `wellKnown` for any /.well-known/openid-configuration request.
const fakeFetch = (settings: unknown, wellKnown?: unknown): typeof fetch =>
  (async (input: string | URL) => {
    const url = input.toString();
    if (url.includes('/api/v1/settings')) {
      return new Response(JSON.stringify(settings), { status: 200 });
    }
    if (url.includes('/.well-known/openid-configuration')) {
      return new Response(JSON.stringify(wellKnown), { status: 200 });
    }
    return new Response('not found', { status: 404 });
  }) as unknown as typeof fetch;

test('discoverOidc derives Dex endpoints when dexConfig has connectors', async () => {
  const settings = { dexConfig: { connectors: [{ type: 'oidc', name: 'corp' }] } };
  const meta = await discoverOidc('https://argocd.example.com', fakeFetch(settings));
  assert.equal(meta.issuer, 'https://argocd.example.com/api/dex');
  assert.equal(meta.authorizationEndpoint, 'https://argocd.example.com/api/dex/auth');
  assert.equal(meta.tokenEndpoint, 'https://argocd.example.com/api/dex/token');
});

test('discoverOidc falls back to external OIDC well-known', async () => {
  const settings = { oidcConfig: { issuer: 'https://issuer.example.com', clientID: 'argocd' } };
  const wellKnown = {
    issuer: 'https://issuer.example.com',
    authorization_endpoint: 'https://issuer.example.com/authorize',
    token_endpoint: 'https://issuer.example.com/oauth/token'
  };
  const meta = await discoverOidc('https://argocd.example.com', fakeFetch(settings, wellKnown));
  assert.equal(meta.authorizationEndpoint, 'https://issuer.example.com/authorize');
  assert.equal(meta.tokenEndpoint, 'https://issuer.example.com/oauth/token');
});

test('discoverOidc throws SSONotConfiguredError when neither is present', async () => {
  await assert.rejects(
    () => discoverOidc('https://argocd.example.com', fakeFetch({})),
    SSONotConfiguredError
  );
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --import tsx --test src/auth/oidcDiscovery.test.ts`
Expected: FAIL — cannot find module `./oidcDiscovery.js`.

- [ ] **Step 3: Write `src/auth/oidcDiscovery.ts`**

```ts
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --import tsx --test src/auth/oidcDiscovery.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Lint & commit**

```bash
pnpm lint
git add src/auth/oidcDiscovery.ts src/auth/oidcDiscovery.test.ts
git commit -m "feat(auth): discover OIDC/Dex endpoints from ArgoCD settings"
```

---

## Task 3: Lazy `HttpClient` token source + 401 refresh-retry

**Files:**
- Modify: `src/argocd/http.ts`, `src/argocd/client.ts`
- Test: `src/argocd/http.test.ts`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `src/argocd/http.ts`: `interface BearerTokenProvider { current(): Promise<string>; refresh(): Promise<string> }`; `type TokenSource = string | BearerTokenProvider`; `class HttpClient` constructor becomes `constructor(baseUrl: string, token: TokenSource)`. On `401` with a provider source, it calls `provider.refresh()` and retries the request once.
  - `src/argocd/client.ts`: `class ArgoCDClient` constructor becomes `constructor(baseUrl: string, token: TokenSource)`.

- [ ] **Step 1: Write the failing test `src/argocd/http.test.ts`**

```ts
import assert from 'node:assert/strict';
import { test, mock } from 'node:test';
import { HttpClient, type BearerTokenProvider } from './http.js';

// Install a mocked global fetch that records Authorization headers and returns
// queued responses in order. Returns a handle to inspect captured headers.
const installFetch = (responses: Array<{ status: number; body: unknown }>) => {
  const authHeaders: string[] = [];
  let i = 0;
  mock.method(globalThis, 'fetch', async (_url: unknown, init?: RequestInit) => {
    const headers = (init?.headers ?? {}) as Record<string, string>;
    authHeaders.push(headers['Authorization'] ?? headers['authorization'] ?? '');
    const r = responses[Math.min(i, responses.length - 1)];
    i += 1;
    return new Response(JSON.stringify(r.body), { status: r.status });
  });
  return { authHeaders };
};

test('static string token is sent as a Bearer header', async (t) => {
  const { authHeaders } = installFetch([{ status: 200, body: { ok: true } }]);
  t.after(() => mock.restoreAll());
  const client = new HttpClient('https://argo.example.com', 'static-token');
  const res = await client.get<{ ok: boolean }>('/api/v1/applications');
  assert.equal(res.status, 200);
  assert.equal(authHeaders[0], 'Bearer static-token');
});

test('provider token is resolved per request via current()', async (t) => {
  const { authHeaders } = installFetch([{ status: 200, body: {} }]);
  t.after(() => mock.restoreAll());
  const provider: BearerTokenProvider = {
    current: async () => 'live-token',
    refresh: async () => 'unused'
  };
  const client = new HttpClient('https://argo.example.com', provider);
  await client.get('/api/v1/applications');
  assert.equal(authHeaders[0], 'Bearer live-token');
});

test('on 401 the client refreshes once and retries with the new token', async (t) => {
  const { authHeaders } = installFetch([
    { status: 401, body: { error: 'expired' } },
    { status: 200, body: { ok: true } }
  ]);
  t.after(() => mock.restoreAll());
  let current = 'old-token';
  const provider: BearerTokenProvider = {
    current: async () => current,
    refresh: async () => {
      current = 'new-token';
      return current;
    }
  };
  const client = new HttpClient('https://argo.example.com', provider);
  const res = await client.get('/api/v1/applications');
  assert.equal(res.status, 200);
  assert.deepEqual(authHeaders, ['Bearer old-token', 'Bearer new-token']);
});

test('a static-token 401 is not retried', async (t) => {
  const { authHeaders } = installFetch([{ status: 401, body: {} }]);
  t.after(() => mock.restoreAll());
  const client = new HttpClient('https://argo.example.com', 'static');
  const res = await client.get('/api/v1/applications');
  assert.equal(res.status, 401);
  assert.equal(authHeaders.length, 1);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --import tsx --test src/argocd/http.test.ts`
Expected: FAIL — `HttpClient` does not export `BearerTokenProvider` / does not retry.

- [ ] **Step 3: Rewrite `src/argocd/http.ts`**

Replace the current `HttpClient` (constructor + `request`/`requestStream`) with the lazy-token version. Keep `HttpResponse`, `SearchParams`, `absUrl`, and the `get/getStream/post/put/delete` method bodies identical except that they call the new `request`/`requestStream`.

```ts
export interface HttpResponse<T> {
  status: number;
  headers: Headers;
  body: T;
}

type SearchParams = Record<string, string | number | boolean | undefined | null> | null;

// A refreshable source of bearer tokens. current() returns the token to use for
// the next request; refresh() is called once after a 401 to obtain a new one.
export interface BearerTokenProvider {
  current(): Promise<string>;
  refresh(): Promise<string>;
}

export type TokenSource = string | BearerTokenProvider;

export class HttpClient {
  public readonly baseUrl: string;
  private readonly tokenSource: TokenSource;

  constructor(baseUrl: string, token: TokenSource) {
    this.baseUrl = baseUrl;
    this.tokenSource = token;
  }

  private isProvider(): boolean {
    return typeof this.tokenSource !== 'string';
  }

  private async currentToken(): Promise<string> {
    return typeof this.tokenSource === 'string'
      ? this.tokenSource
      : await this.tokenSource.current();
  }

  private async refreshToken(): Promise<string> {
    // Only reachable when tokenSource is a provider (guarded by isProvider()).
    return (this.tokenSource as BearerTokenProvider).refresh();
  }

  private headersFor(token: string, extra?: HeadersInit): Record<string, string> {
    return {
      ...(extra as Record<string, string>),
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json'
    };
  }

  private async request<R>(
    url: string,
    params?: SearchParams,
    init?: RequestInit
  ): Promise<HttpResponse<R>> {
    const urlObject = this.absUrl(url);
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        urlObject.searchParams.set(key, value?.toString() || '');
      });
    }

    let token = await this.currentToken();
    let response = await fetch(urlObject, {
      ...init,
      headers: this.headersFor(token, init?.headers)
    });

    // A session-scoped SSO token can expire mid-session. When it does, refresh
    // once and retry a single time. Static-string tokens are never retried.
    if (response.status === 401 && this.isProvider()) {
      token = await this.refreshToken();
      response = await fetch(urlObject, {
        ...init,
        headers: this.headersFor(token, init?.headers)
      });
    }

    const body = await response.json();
    return { status: response.status, headers: response.headers, body: body as R };
  }

  private async requestStream<R>(
    url: string,
    params?: SearchParams,
    cb?: (chunk: R) => void,
    init?: RequestInit
  ) {
    const urlObject = this.absUrl(url);
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        urlObject.searchParams.set(key, value?.toString() || '');
      });
    }
    const token = await this.currentToken();
    const response = await fetch(urlObject, {
      ...init,
      headers: this.headersFor(token, init?.headers)
    });
    const reader = response.body?.getReader();
    if (!reader) {
      throw new Error('response body is not readable');
    }
    const decoder = new TextDecoder('utf-8');
    let buffer = '';
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';
      for (const line of lines) {
        if (line.trim()) {
          const json = JSON.parse(line);
          cb?.(json['result']);
        }
      }
    }
  }

  absUrl(url: string): URL {
    if (url.startsWith('http://') || url.startsWith('https://')) {
      return new URL(url);
    }
    return new URL(url, this.baseUrl);
  }

  async get<R>(url: string, params?: SearchParams): Promise<HttpResponse<R>> {
    return this.request<R>(url, params);
  }

  async getStream<R>(url: string, params?: SearchParams, cb?: (chunk: R) => void): Promise<void> {
    await this.requestStream<R>(url, params, cb);
  }

  async post<T, R>(url: string, params?: SearchParams, body?: T): Promise<HttpResponse<R>> {
    return this.request<R>(url, params, {
      method: 'POST',
      body: body ? JSON.stringify(body) : undefined
    });
  }

  async put<T, R>(url: string, params?: SearchParams, body?: T): Promise<HttpResponse<R>> {
    return this.request<R>(url, params, {
      method: 'PUT',
      body: body ? JSON.stringify(body) : undefined
    });
  }

  async delete<R>(url: string, params?: SearchParams): Promise<HttpResponse<R>> {
    return this.request<R>(url, params, { method: 'DELETE' });
  }
}
```

- [ ] **Step 4: Update `src/argocd/client.ts` constructor**

Change the `ArgoCDClient` constructor to accept a `TokenSource` and pass it through (rename `apiToken` type only — the field can stay for reference but is no longer required).

```ts
import { HttpClient, type TokenSource } from './http.js';
// ...
export class ArgoCDClient {
  private baseUrl: string;
  private client: HttpClient;

  constructor(baseUrl: string, token: TokenSource) {
    this.baseUrl = baseUrl;
    this.client = new HttpClient(this.baseUrl, token);
  }
  // ... rest unchanged
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `node --import tsx --test src/argocd/http.test.ts`
Expected: PASS (4 tests).
Run the full suite to confirm no regression: `pnpm test`
Expected: all existing tests PASS (server.test.ts still constructs `new ArgoCDClient(baseUrl, token)` with a string — still valid).

- [ ] **Step 6: Lint & commit**

```bash
pnpm lint
git add src/argocd/http.ts src/argocd/client.ts src/argocd/http.test.ts
git commit -m "feat(argocd): lazy HttpClient token source with 401 refresh-retry"
```

---

## Task 4: `TokenStore` interface, contract test, and in-memory store

**Files:**
- Create: `src/auth/tokenStore.ts`, `src/auth/tokenStore.contract.ts`, `src/auth/inMemoryTokenStore.ts`
- Test: `src/auth/inMemoryTokenStore.test.ts`

**Interfaces:**
- Consumes: `UpstreamToken` (Task 1); `OAuthClientInformationFull` from `@modelcontextprotocol/sdk/shared/auth.js`.
- Produces:
  - `src/auth/tokenStore.ts`: record types `PendingAuth`, `CompletedAuth`, `StoredToken`, `RefreshRecord` and `interface TokenStore` (methods listed below).
  - `src/auth/tokenStore.contract.ts`: `function runTokenStoreContract(name: string, makeStore: () => TokenStore): void` — registers `node:test` cases valid for any implementation.
  - `src/auth/inMemoryTokenStore.ts`: `class InMemoryTokenStore implements TokenStore`.

- [ ] **Step 1: Write `src/auth/tokenStore.ts`**

```ts
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { PkceChallenge, UpstreamToken } from './types.js';

// Short-lived state while the upstream (Dex) flow is in progress, keyed by the
// upstream `state` value.
export interface PendingAuth {
  upstreamState: string;
  upstreamPkce: PkceChallenge;
  clientRedirectUri: string;
  clientState?: string;
  clientCodeChallenge: string;
  clientId: string;
}

// State after the upstream exchange succeeds, keyed by the authorization code we
// mint for the MCP client.
export interface CompletedAuth {
  upstream: UpstreamToken;
  clientRedirectUri: string;
  clientState?: string;
  clientCodeChallenge: string;
  clientId: string;
}

// The real upstream token behind an issued opaque access token.
export interface StoredToken {
  upstream: UpstreamToken;
  clientId: string;
}

// The upstream refresh token behind an issued opaque refresh token.
export interface RefreshRecord {
  upstreamRefreshToken: string;
  clientId: string;
}

// All OAuth server-side state lives behind this interface so the deployment can
// pick in-memory (single replica) or Redis (horizontally scalable) without any
// change to the provider.
export interface TokenStore {
  // Dynamic client registrations (no expiry).
  putClient(client: OAuthClientInformationFull): Promise<void>;
  getClient(clientId: string): Promise<OAuthClientInformationFull | undefined>;

  // Pending upstream flow state (get-and-delete semantics).
  putPendingAuth(state: string, value: PendingAuth, ttlSec: number): Promise<void>;
  takePendingAuth(state: string): Promise<PendingAuth | undefined>;

  // Authorization codes we issue to MCP clients (get-and-delete semantics).
  putAuthCode(code: string, value: CompletedAuth, ttlSec: number): Promise<void>;
  takeAuthCode(code: string): Promise<CompletedAuth | undefined>;

  // Issued opaque access tokens.
  putAccessToken(opaque: string, value: StoredToken, ttlSec?: number): Promise<void>;
  getAccessToken(opaque: string): Promise<StoredToken | undefined>;
  deleteAccessToken(opaque: string): Promise<void>;

  // Issued opaque refresh tokens.
  putRefreshToken(opaque: string, value: RefreshRecord): Promise<void>;
  getRefreshToken(opaque: string): Promise<RefreshRecord | undefined>;
  deleteRefreshToken(opaque: string): Promise<void>;

  // Release resources (timers, connections).
  dispose(): void;
}
```

- [ ] **Step 2: Write `src/auth/tokenStore.contract.ts`**

```ts
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { TokenStore } from './tokenStore.js';

const client = (id: string): OAuthClientInformationFull =>
  ({ client_id: id, redirect_uris: ['http://localhost/cb'] }) as OAuthClientInformationFull;

// Shared behavior every TokenStore implementation must satisfy. Called once per
// implementation from that implementation's *.test.ts file.
export const runTokenStoreContract = (name: string, makeStore: () => TokenStore): void => {
  test(`[${name}] client round-trips`, async (t) => {
    const store = makeStore();
    t.after(() => store.dispose());
    await store.putClient(client('abc'));
    const got = await store.getClient('abc');
    assert.equal(got?.client_id, 'abc');
    assert.equal(await store.getClient('missing'), undefined);
  });

  test(`[${name}] pending auth is get-and-delete`, async (t) => {
    const store = makeStore();
    t.after(() => store.dispose());
    await store.putPendingAuth(
      's1',
      {
        upstreamState: 's1',
        upstreamPkce: { codeVerifier: 'v', codeChallenge: 'c', codeChallengeMethod: 'S256' },
        clientRedirectUri: 'http://localhost/cb',
        clientCodeChallenge: 'cc',
        clientId: 'abc'
      },
      600
    );
    const first = await store.takePendingAuth('s1');
    assert.equal(first?.clientId, 'abc');
    const second = await store.takePendingAuth('s1');
    assert.equal(second, undefined); // consumed
  });

  test(`[${name}] access token round-trips and deletes`, async (t) => {
    const store = makeStore();
    t.after(() => store.dispose());
    await store.putAccessToken('opaque1', {
      upstream: { accessToken: 'A', refreshToken: 'R', expiresAtMs: 1_000_000 },
      clientId: 'abc'
    });
    const got = await store.getAccessToken('opaque1');
    assert.equal(got?.upstream.accessToken, 'A');
    await store.deleteAccessToken('opaque1');
    assert.equal(await store.getAccessToken('opaque1'), undefined);
  });

  test(`[${name}] refresh token round-trips and deletes`, async (t) => {
    const store = makeStore();
    t.after(() => store.dispose());
    await store.putRefreshToken('r1', { upstreamRefreshToken: 'UR', clientId: 'abc' });
    assert.equal((await store.getRefreshToken('r1'))?.upstreamRefreshToken, 'UR');
    await store.deleteRefreshToken('r1');
    assert.equal(await store.getRefreshToken('r1'), undefined);
  });
};
```

- [ ] **Step 3: Write the failing test `src/auth/inMemoryTokenStore.test.ts`**

```ts
import { runTokenStoreContract } from './tokenStore.contract.js';
import { InMemoryTokenStore } from './inMemoryTokenStore.js';

runTokenStoreContract('memory', () => new InMemoryTokenStore());
```

- [ ] **Step 4: Run test to verify it fails**

Run: `node --import tsx --test src/auth/inMemoryTokenStore.test.ts`
Expected: FAIL — cannot find module `./inMemoryTokenStore.js`.

- [ ] **Step 5: Write `src/auth/inMemoryTokenStore.ts`**

```ts
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type {
  TokenStore,
  PendingAuth,
  CompletedAuth,
  StoredToken,
  RefreshRecord
} from './tokenStore.js';

interface Expiring<T> {
  value: T;
  expiresAtMs?: number;
}

// Single-process TokenStore. A periodic sweep evicts expired flow-state and
// access-token entries. Use only with a single replica; for multiple replicas
// use RedisTokenStore so state is shared across pods.
export class InMemoryTokenStore implements TokenStore {
  private clients = new Map<string, OAuthClientInformationFull>();
  private pending = new Map<string, Expiring<PendingAuth>>();
  private codes = new Map<string, Expiring<CompletedAuth>>();
  private access = new Map<string, Expiring<StoredToken>>();
  private refresh = new Map<string, Expiring<RefreshRecord>>();
  private sweep: ReturnType<typeof setInterval>;

  constructor() {
    this.sweep = setInterval(() => this.evictExpired(), 60_000);
    if (this.sweep.unref) this.sweep.unref();
  }

  private nowMs(): number {
    return Date.now();
  }

  private fresh<T>(map: Map<string, Expiring<T>>, key: string): T | undefined {
    const entry = map.get(key);
    if (!entry) return undefined;
    if (entry.expiresAtMs && this.nowMs() > entry.expiresAtMs) {
      map.delete(key);
      return undefined;
    }
    return entry.value;
  }

  private evictExpired(): void {
    const now = this.nowMs();
    for (const map of [this.pending, this.codes, this.access, this.refresh]) {
      for (const [key, entry] of map) {
        if (entry.expiresAtMs && now > entry.expiresAtMs) map.delete(key);
      }
    }
  }

  async putClient(client: OAuthClientInformationFull): Promise<void> {
    this.clients.set(client.client_id, client);
  }
  async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
    return this.clients.get(clientId);
  }

  async putPendingAuth(state: string, value: PendingAuth, ttlSec: number): Promise<void> {
    this.pending.set(state, { value, expiresAtMs: this.nowMs() + ttlSec * 1000 });
  }
  async takePendingAuth(state: string): Promise<PendingAuth | undefined> {
    const v = this.fresh(this.pending, state);
    this.pending.delete(state);
    return v;
  }

  async putAuthCode(code: string, value: CompletedAuth, ttlSec: number): Promise<void> {
    this.codes.set(code, { value, expiresAtMs: this.nowMs() + ttlSec * 1000 });
  }
  async takeAuthCode(code: string): Promise<CompletedAuth | undefined> {
    const v = this.fresh(this.codes, code);
    this.codes.delete(code);
    return v;
  }

  async putAccessToken(opaque: string, value: StoredToken, ttlSec?: number): Promise<void> {
    this.access.set(opaque, {
      value,
      expiresAtMs: ttlSec ? this.nowMs() + ttlSec * 1000 : undefined
    });
  }
  async getAccessToken(opaque: string): Promise<StoredToken | undefined> {
    return this.fresh(this.access, opaque);
  }
  async deleteAccessToken(opaque: string): Promise<void> {
    this.access.delete(opaque);
  }

  async putRefreshToken(opaque: string, value: RefreshRecord): Promise<void> {
    this.refresh.set(opaque, { value });
  }
  async getRefreshToken(opaque: string): Promise<RefreshRecord | undefined> {
    return this.fresh(this.refresh, opaque);
  }
  async deleteRefreshToken(opaque: string): Promise<void> {
    this.refresh.delete(opaque);
  }

  dispose(): void {
    clearInterval(this.sweep);
  }
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `node --import tsx --test src/auth/inMemoryTokenStore.test.ts`
Expected: PASS (4 contract tests, prefixed `[memory]`).

- [ ] **Step 7: Lint & commit**

```bash
pnpm lint
git add src/auth/tokenStore.ts src/auth/tokenStore.contract.ts src/auth/inMemoryTokenStore.ts src/auth/inMemoryTokenStore.test.ts
git commit -m "feat(auth): TokenStore interface, contract test, in-memory store"
```

---

## Task 5: Redis token store (with optional at-rest encryption) + store factory

**Files:**
- Create: `src/auth/encryption.ts`, `src/auth/redisTokenStore.ts`, `src/auth/tokenStoreFactory.ts`
- Test: `src/auth/redisTokenStore.test.ts`
- Modify: `package.json` (add `ioredis`, `ioredis-mock`)

**Interfaces:**
- Consumes: `TokenStore` and records (Task 4); `OidcConfig` (Task 1).
- Produces:
  - `src/auth/encryption.ts`: `interface ValueCodec { encode(s: string): string; decode(s: string): string }`; `plainCodec: ValueCodec`; `aesGcmCodec(key: Buffer): ValueCodec`.
  - `src/auth/redisTokenStore.ts`: `class RedisTokenStore implements TokenStore` with `constructor(redis: RedisLike, codec?: ValueCodec)`; `type RedisLike` (the subset of `ioredis` used).
  - `src/auth/tokenStoreFactory.ts`: `function createTokenStore(config: OidcConfig): TokenStore`.

- [ ] **Step 1: Add dependencies**

```bash
pnpm add ioredis
pnpm add -D ioredis-mock @types/ioredis-mock
```
Expected: `package.json` gains `ioredis` under dependencies and `ioredis-mock` + types under devDependencies. Commit these together with the code below.

- [ ] **Step 2: Write `src/auth/encryption.ts`**

```ts
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

// A reversible string codec used to protect token values written to an external
// store (Redis). plainCodec is a no-op; aesGcmCodec encrypts at rest.
export interface ValueCodec {
  encode(plaintext: string): string;
  decode(encoded: string): string;
}

export const plainCodec: ValueCodec = {
  encode: (s) => s,
  decode: (s) => s
};

// AES-256-GCM. Output format: base64(iv).base64(authTag).base64(ciphertext).
export const aesGcmCodec = (key: Buffer): ValueCodec => {
  if (key.length !== 32) throw new Error('aesGcmCodec requires a 32-byte key');
  return {
    encode(plaintext: string): string {
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
      const tag = cipher.getAuthTag();
      return `${iv.toString('base64')}.${tag.toString('base64')}.${enc.toString('base64')}`;
    },
    decode(encoded: string): string {
      const [ivB64, tagB64, dataB64] = encoded.split('.');
      if (!ivB64 || !tagB64 || !dataB64) throw new Error('malformed encrypted value');
      const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(ivB64, 'base64'));
      decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
      return Buffer.concat([
        decipher.update(Buffer.from(dataB64, 'base64')),
        decipher.final()
      ]).toString('utf8');
    }
  };
};
```

- [ ] **Step 3: Write the failing test `src/auth/redisTokenStore.test.ts`**

```ts
import assert from 'node:assert/strict';
import { test } from 'node:test';
import RedisMock from 'ioredis-mock';
import { runTokenStoreContract } from './tokenStore.contract.js';
import { RedisTokenStore } from './redisTokenStore.js';
import { aesGcmCodec } from './encryption.js';

// Contract: run the shared suite against a fresh in-memory Redis each time.
runTokenStoreContract('redis', () => new RedisTokenStore(new RedisMock()));

// Contract with encryption enabled, to prove encode/decode is transparent.
runTokenStoreContract(
  'redis+aes',
  () => new RedisTokenStore(new RedisMock(), aesGcmCodec(Buffer.alloc(32, 7)))
);

test('[redis+aes] stored value is not plaintext in Redis', async (t) => {
  const redis = new RedisMock();
  const store = new RedisTokenStore(redis, aesGcmCodec(Buffer.alloc(32, 7)));
  t.after(() => store.dispose());
  await store.putAccessToken('opaqueX', {
    upstream: { accessToken: 'SUPER_SECRET_JWT' },
    clientId: 'abc'
  });
  const raw = (await redis.get('argocd-mcp:access:opaqueX')) ?? '';
  assert.ok(!raw.includes('SUPER_SECRET_JWT'), 'raw Redis value must be encrypted');
  const got = await store.getAccessToken('opaqueX');
  assert.equal(got?.upstream.accessToken, 'SUPER_SECRET_JWT');
});
```

- [ ] **Step 4: Run test to verify it fails**

Run: `node --import tsx --test src/auth/redisTokenStore.test.ts`
Expected: FAIL — cannot find module `./redisTokenStore.js`.

- [ ] **Step 5: Write `src/auth/redisTokenStore.ts`**

```ts
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type {
  TokenStore,
  PendingAuth,
  CompletedAuth,
  StoredToken,
  RefreshRecord
} from './tokenStore.js';
import { plainCodec, type ValueCodec } from './encryption.js';

// The subset of ioredis we use. Declared structurally so tests can pass
// ioredis-mock without a type dependency on the concrete client.
export interface RedisLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, mode?: 'EX', ttlSec?: number): Promise<unknown>;
  del(key: string): Promise<unknown>;
  quit(): Promise<unknown>;
}

const NS = 'argocd-mcp';
const K = {
  client: (id: string) => `${NS}:client:${id}`,
  pending: (s: string) => `${NS}:pending:${s}`,
  code: (c: string) => `${NS}:code:${c}`,
  access: (o: string) => `${NS}:access:${o}`,
  refresh: (o: string) => `${NS}:refresh:${o}`
};

// Redis-backed TokenStore. Key TTL is native (SET ... EX), so no sweep is
// needed. Values are run through `codec` so tokens can be encrypted at rest.
// Sharing one Redis across replicas lets an OAuth callback be served by a
// different pod than the /authorize that created the pending state.
export class RedisTokenStore implements TokenStore {
  constructor(
    private redis: RedisLike,
    private codec: ValueCodec = plainCodec
  ) {}

  private async putJson(key: string, value: unknown, ttlSec?: number): Promise<void> {
    const payload = this.codec.encode(JSON.stringify(value));
    if (ttlSec && ttlSec > 0) {
      await this.redis.set(key, payload, 'EX', ttlSec);
    } else {
      await this.redis.set(key, payload);
    }
  }

  private async getJson<T>(key: string): Promise<T | undefined> {
    const raw = await this.redis.get(key);
    if (raw === null) return undefined;
    return JSON.parse(this.codec.decode(raw)) as T;
  }

  private async take<T>(key: string): Promise<T | undefined> {
    const v = await this.getJson<T>(key);
    if (v !== undefined) await this.redis.del(key);
    return v;
  }

  async putClient(client: OAuthClientInformationFull): Promise<void> {
    await this.putJson(K.client(client.client_id), client);
  }
  async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
    return this.getJson<OAuthClientInformationFull>(K.client(clientId));
  }

  async putPendingAuth(state: string, value: PendingAuth, ttlSec: number): Promise<void> {
    await this.putJson(K.pending(state), value, ttlSec);
  }
  async takePendingAuth(state: string): Promise<PendingAuth | undefined> {
    return this.take<PendingAuth>(K.pending(state));
  }

  async putAuthCode(code: string, value: CompletedAuth, ttlSec: number): Promise<void> {
    await this.putJson(K.code(code), value, ttlSec);
  }
  async takeAuthCode(code: string): Promise<CompletedAuth | undefined> {
    return this.take<CompletedAuth>(K.code(code));
  }

  async putAccessToken(opaque: string, value: StoredToken, ttlSec?: number): Promise<void> {
    await this.putJson(K.access(opaque), value, ttlSec);
  }
  async getAccessToken(opaque: string): Promise<StoredToken | undefined> {
    return this.getJson<StoredToken>(K.access(opaque));
  }
  async deleteAccessToken(opaque: string): Promise<void> {
    await this.redis.del(K.access(opaque));
  }

  async putRefreshToken(opaque: string, value: RefreshRecord): Promise<void> {
    await this.putJson(K.refresh(opaque), value);
  }
  async getRefreshToken(opaque: string): Promise<RefreshRecord | undefined> {
    return this.getJson<RefreshRecord>(K.refresh(opaque));
  }
  async deleteRefreshToken(opaque: string): Promise<void> {
    await this.redis.del(K.refresh(opaque));
  }

  dispose(): void {
    // Best-effort close; ignore errors during shutdown.
    void this.redis.quit().catch(() => undefined);
  }
}
```

- [ ] **Step 6: Write `src/auth/tokenStoreFactory.ts`**

```ts
import Redis from 'ioredis';
import type { OidcConfig } from './config.js';
import type { TokenStore } from './tokenStore.js';
import { InMemoryTokenStore } from './inMemoryTokenStore.js';
import { RedisTokenStore } from './redisTokenStore.js';
import { aesGcmCodec, plainCodec } from './encryption.js';
import { logger } from '../logging/logging.js';

// Build the TokenStore chosen by config. Redis enables multiple replicas; the
// optional encryption key protects tokens written to Redis at rest.
export const createTokenStore = (config: OidcConfig): TokenStore => {
  if (config.tokenStore === 'redis') {
    if (!config.redisUrl) throw new Error('TOKEN_STORE=redis requires REDIS_URL');
    logger.info('Using Redis token store');
    const codec = config.encryptionKey ? aesGcmCodec(config.encryptionKey) : plainCodec;
    return new RedisTokenStore(new Redis(config.redisUrl), codec);
  }
  logger.info('Using in-memory token store (single replica only)');
  return new InMemoryTokenStore();
};
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `node --import tsx --test src/auth/redisTokenStore.test.ts`
Expected: PASS (8 contract tests across `[redis]` and `[redis+aes]`, plus the encryption assertion).

- [ ] **Step 8: Lint & commit**

```bash
pnpm lint
git add package.json pnpm-lock.yaml src/auth/encryption.ts src/auth/redisTokenStore.ts src/auth/tokenStoreFactory.ts src/auth/redisTokenStore.test.ts
git commit -m "feat(auth): Redis token store with optional at-rest encryption + factory"
```

---

## Task 6: OAuth helpers + `OAuthProxyProvider`

**Files:**
- Create: `src/auth/oauth.ts`, `src/auth/oauthProxyProvider.ts`, `src/auth/sessionTokenProvider.ts`
- Test: `src/auth/oauthProxyProvider.test.ts`

**Interfaces:**
- Consumes: `OidcProviderMetadata`, `PkceChallenge`, `UpstreamToken` (Task 1); `OidcConfig` (Task 1); `TokenStore` + records (Task 4); `BearerTokenProvider` (Task 3); `discoverOidc` (Task 2).
- Produces:
  - `src/auth/oauth.ts`: `generateState(): string`; `generateOpaqueToken(): string`; `generatePkce(): PkceChallenge`; `buildAuthorizeUrl(meta, {clientId, redirectUri, scopes, state, pkce}): string`; `async exchangeCode(meta, {clientId, clientSecret, code, redirectUri, codeVerifier}, fetchImpl?): Promise<UpstreamToken>`; `async refreshUpstream(meta, {clientId, clientSecret, refreshToken}, fetchImpl?): Promise<UpstreamToken>`.
  - `src/auth/oauthProxyProvider.ts`: `class OAuthProxyProvider implements OAuthServerProvider` with an extra method `handleUpstreamCallback(code: string, state: string): Promise<string>` returning the MCP client redirect URL.
  - `src/auth/sessionTokenProvider.ts`: `makeSessionTokenProvider(store, meta, config, opaqueAccessToken): BearerTokenProvider`.

- [ ] **Step 1: Write `src/auth/oauth.ts`**

```ts
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
  opts: { clientId: string; redirectUri: string; scopes: string[]; state: string; pkce: PkceChallenge }
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

const toUpstreamToken = (r: TokenResponse): UpstreamToken => ({
  accessToken: r.access_token,
  refreshToken: r.refresh_token,
  idToken: r.id_token,
  expiresAtMs: r.expires_in ? Date.now() + r.expires_in * 1000 : undefined
});

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
    throw new Error(`Upstream token endpoint returned ${res.status}`);
  }
  return toUpstreamToken((await res.json()) as TokenResponse);
};

// Exchange an authorization code for tokens using the confidential client
// (client_secret) plus the PKCE verifier.
export const exchangeCode = async (
  meta: OidcProviderMetadata,
  opts: { clientId: string; clientSecret: string; code: string; redirectUri: string; codeVerifier: string },
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
```

- [ ] **Step 2: Write `src/auth/sessionTokenProvider.ts`**

```ts
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
```

- [ ] **Step 3: Write the failing test `src/auth/oauthProxyProvider.test.ts`**

```ts
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { Response as ExpressResponse } from 'express';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import { OAuthProxyProvider } from './oauthProxyProvider.js';
import { InMemoryTokenStore } from './inMemoryTokenStore.js';
import type { OidcConfig } from './config.js';

const CONFIG: OidcConfig = {
  publicUrl: 'https://mcp.example.com',
  argocdBaseUrl: 'https://argocd.example.com',
  clientId: 'argocd-mcp',
  clientSecret: 'shhh',
  callbackPath: '/oauth/callback',
  callbackUrl: 'https://mcp.example.com/oauth/callback',
  tokenStore: 'memory'
};

const META = {
  issuer: 'https://argocd.example.com/api/dex',
  authorizationEndpoint: 'https://argocd.example.com/api/dex/auth',
  tokenEndpoint: 'https://argocd.example.com/api/dex/token',
  scopesSupported: ['openid', 'groups']
};

// fetch stub: the Dex token endpoint returns a fixed upstream token.
const dexFetch: typeof fetch = (async (input: string | URL) => {
  if (input.toString().includes('/api/dex/token')) {
    return new Response(
      JSON.stringify({ access_token: 'UPSTREAM_JWT', token_type: 'Bearer', expires_in: 300, refresh_token: 'UP_REFRESH' }),
      { status: 200 }
    );
  }
  return new Response('nope', { status: 404 });
}) as unknown as typeof fetch;

const makeProvider = () => {
  const store = new InMemoryTokenStore();
  const provider = new OAuthProxyProvider({
    config: CONFIG,
    store,
    discover: async () => META,
    fetchImpl: dexFetch
  });
  return { store, provider };
};

// A fake express Response that records a redirect target.
const fakeRes = () => {
  const out: { redirected?: string } = {};
  return {
    res: { redirect: (url: string) => (out.redirected = url) } as unknown as ExpressResponse,
    out
  };
};

const client: OAuthClientInformationFull = {
  client_id: 'mcp-client-1',
  redirect_uris: ['http://localhost:33418/callback']
} as OAuthClientInformationFull;

test('full flow: authorize -> callback -> exchange code -> verify token', async (t) => {
  const { store, provider } = makeProvider();
  t.after(() => store.dispose());

  // 1. authorize -> redirects to Dex, storing pending state keyed by upstream state.
  const { res, out } = fakeRes();
  await provider.authorize(client, {
    redirectUri: 'http://localhost:33418/callback',
    state: 'client-state',
    codeChallenge: 'client-challenge',
    scopes: ['openid']
  } as never, res);
  assert.ok(out.redirected?.startsWith('https://argocd.example.com/api/dex/auth'));
  const upstreamState = new URL(out.redirected!).searchParams.get('state')!;
  assert.ok(upstreamState);
  assert.equal(new URL(out.redirected!).searchParams.get('client_id'), 'argocd-mcp');

  // 2. upstream callback -> exchanges code, returns MCP client redirect with our code.
  const clientRedirect = await provider.handleUpstreamCallback('dex-code', upstreamState);
  const ourCode = new URL(clientRedirect).searchParams.get('code')!;
  assert.equal(new URL(clientRedirect).searchParams.get('state'), 'client-state');
  assert.ok(ourCode);

  // 3. client PKCE challenge is preserved for the token step.
  assert.equal(await provider.challengeForAuthorizationCode(client, ourCode), 'client-challenge');

  // 4. exchange our code -> opaque tokens; the real JWT stays server-side.
  const tokens = await provider.exchangeAuthorizationCode(client, ourCode);
  assert.notEqual(tokens.access_token, 'UPSTREAM_JWT');
  assert.equal(tokens.token_type, 'Bearer');

  // 5. verify -> AuthInfo carries the real upstream token in extra.
  const info = await provider.verifyAccessToken(tokens.access_token);
  assert.equal(info.extra?.argocdToken, 'UPSTREAM_JWT');
  assert.equal(info.extra?.argocdBaseUrl, 'https://argocd.example.com');
});

test('verifyAccessToken rejects an unknown opaque token', async (t) => {
  const { store, provider } = makeProvider();
  t.after(() => store.dispose());
  await assert.rejects(() => provider.verifyAccessToken('bogus'), /Invalid/);
});
```

- [ ] **Step 4: Run test to verify it fails**

Run: `node --import tsx --test src/auth/oauthProxyProvider.test.ts`
Expected: FAIL — cannot find module `./oauthProxyProvider.js`.

- [ ] **Step 5: Write `src/auth/oauthProxyProvider.ts`**

```ts
import type { Response } from 'express';
import type { OAuthServerProvider, AuthorizationParams } from '@modelcontextprotocol/sdk/server/auth/provider.js';
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
    logger.info({ clientId: pending.clientId }, 'Upstream auth complete; redirecting to MCP client');
    return redirect.toString();
  }

  async challengeForAuthorizationCode(
    _client: OAuthClientInformationFull,
    authorizationCode: string
  ): Promise<string> {
    const completed = await this.store.takeAuthCode(authorizationCode);
    if (!completed) throw new Error('Unknown or expired authorization code');
    // Re-store under the same code so exchangeAuthorizationCode can consume it.
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

    await this.store.putAccessToken(
      opaqueAccess,
      { upstream, clientId: client.client_id },
      ttlSec
    );
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
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `node --import tsx --test src/auth/oauthProxyProvider.test.ts`
Expected: PASS (2 tests).

> Note on `challengeForAuthorizationCode`: the SDK calls it before `exchangeAuthorizationCode`, so it must NOT consume the code. The implementation take-then-re-puts to preserve it; verify this ordering against the installed SDK during implementation and, if the SDK provides a non-destructive read, prefer that.

- [ ] **Step 7: Lint & commit**

```bash
pnpm lint
git add src/auth/oauth.ts src/auth/oauthProxyProvider.ts src/auth/sessionTokenProvider.ts src/auth/oauthProxyProvider.test.ts
git commit -m "feat(auth): OAuth proxy provider + helpers + session token provider"
```

---

## Task 7: Wire the `oidc` mode into the HTTP transport + pin base URL

**Files:**
- Modify: `src/server/server.ts`, `src/server/transport.ts`
- Test: `src/server/oidcTransport.test.ts`

**Interfaces:**
- Consumes: everything from Tasks 1–6.
- Produces:
  - `src/server/server.ts`: `ServerInfo` gains optional `pinBaseUrl?: boolean` and `tokenSource?: TokenSource`. When `pinBaseUrl` is true, `resolveClient` ignores the per-call `argocdBaseUrl` and always uses the default; when `tokenSource` is set it is used to build the client.
  - `src/server/transport.ts`: `connectHttpTransport(port, stateless?)` unchanged signature but reads `resolveAuthMode()`; in `oidc` mode it mounts the auth router, the callback route, and bearer-protected `/mcp`.

- [ ] **Step 1: Write the failing test `src/server/oidcTransport.test.ts`**

```ts
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServer } from './server.js';

// In oidc mode the per-call argocdBaseUrl override must be ignored: a user's
// token is only ever sent to the configured ARGOCD_BASE_URL. We assert this by
// checking that resolveClient (via a tool handler) refuses to build a client
// for a different base URL. Reuse the handler-invocation trick from server.test.ts.
const callTool = async (
  server: ReturnType<typeof createServer>,
  toolName: string,
  args: Record<string, unknown>
): Promise<{ isError?: boolean; content: { text: string }[] }> => {
  const registered = (
    server as unknown as {
      _registeredTools: Record<string, { handler: (...a: unknown[]) => Promise<unknown> }>;
    }
  )._registeredTools;
  return (await registered[toolName].handler(args, {})) as {
    isError?: boolean;
    content: { text: string }[];
  };
};

test('oidc mode pins the base URL: per-call override is ignored', async () => {
  // A tokenSource that would "work" for any base URL, so the only thing that can
  // stop an evil base URL is the pinning logic.
  const server = createServer({
    argocdBaseUrl: 'https://argocd.internal.example.com',
    argocdApiToken: '',
    pinBaseUrl: true,
    tokenSource: 'user-token'
  });
  // list_clusters against an attacker-controlled base URL: since pinning forces
  // the default base URL, the client is built for the default host, not evil.com.
  // We can only observe indirectly: the call attempts the default host. Assert no
  // throw about "missing base URL" and that the override did not select evil.com.
  // (Network is not hit in this unit test environment; we assert the guard path.)
  const result = await callTool(server, 'list_clusters', {
    argocdBaseUrl: 'https://evil.example.com'
  });
  // The handler returns an error result on network failure, but crucially the
  // error must not reference evil.example.com as the resolved host.
  const text = result.content.map((c) => c.text).join('\n');
  assert.ok(!text.includes('evil.example.com'), 'must not target the overridden base URL');
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --import tsx --test src/server/oidcTransport.test.ts`
Expected: FAIL — `createServer` does not accept `pinBaseUrl`/`tokenSource`.

- [ ] **Step 3: Modify `src/server/server.ts`**

Add the two `ServerInfo` fields and honor them in the constructor and `resolveClient`. Show the exact edits.

At the top, import the type:
```ts
import { HttpClient, type TokenSource } from '../argocd/http.js';
```

Extend `ServerInfo`:
```ts
type ServerInfo = {
  argocdBaseUrl: string;
  argocdApiToken: string;
  tokenRegistry?: TokenRegistry;
  // When true (oidc mode), ignore the per-call argocdBaseUrl argument and always
  // target argocdBaseUrl. Prevents sending a user token to an arbitrary host.
  pinBaseUrl?: boolean;
  // When set (oidc mode), build the ArgoCD client with this refreshable source
  // instead of the static token string.
  tokenSource?: TokenSource;
};
```

Add fields to the class and set them in the constructor:
```ts
  private pinBaseUrl: boolean;
  private tokenSource: TokenSource;
```
```ts
    this.pinBaseUrl = serverInfo.pinBaseUrl ?? false;
    this.tokenSource = serverInfo.tokenSource ?? serverInfo.argocdApiToken;
    this.argocdClient = new ArgoCDClient(serverInfo.argocdBaseUrl, this.tokenSource);
```

Update `resolveClient` to pin the base URL and use the token source in oidc mode. Replace the base-URL selection line and the default-client fast path:
```ts
  private resolveClient(args: ArgoCDArgs): ArgoCDClient {
    // In oidc mode the base URL is pinned to the configured default and the
    // per-call override is ignored (a user's token must never be redirected to
    // an arbitrary host). The token comes from the refreshable session source.
    if (this.pinBaseUrl) {
      if (!this.defaultBaseUrl) {
        throw new Error('oidc mode requires a configured ARGOCD_BASE_URL');
      }
      return this.argocdClient;
    }

    const baseUrl = args.argocdBaseUrl || this.defaultBaseUrl;
    // ... existing logic unchanged from here ...
```

- [ ] **Step 4: Run the pinning test to verify it passes**

Run: `node --import tsx --test src/server/oidcTransport.test.ts`
Expected: PASS. Also run `pnpm test` to confirm `server.test.ts` still passes (default `pinBaseUrl=false` preserves all existing behavior).

- [ ] **Step 5: Modify `src/server/transport.ts` — add the `oidc` branch**

Add imports:
```ts
import { resolveAuthMode, loadOidcConfig } from '../auth/config.js';
import { discoverOidc } from '../auth/oidcDiscovery.js';
import { createTokenStore } from '../auth/tokenStoreFactory.js';
import { OAuthProxyProvider } from '../auth/oauthProxyProvider.js';
import { makeSessionTokenProvider } from '../auth/sessionTokenProvider.js';
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
```

In `connectHttpTransport`, branch on the auth mode. Keep the existing body as the `token`-mode branch; add the `oidc` branch before it:
```ts
export const connectHttpTransport = (port: number, stateless = false) => {
  const app = express();
  app.use(express.json());

  app.get('/healthz', (_, res) => {
    res.status(200).json({ status: 'ok' });
  });

  const httpTransports: { [sessionId: string]: StreamableHTTPServerTransport } = {};

  if (resolveAuthMode() === 'oidc') {
    const config = loadOidcConfig();
    const store = createTokenStore(config);
    // Cache discovery once; the provider also memoizes internally.
    const discover = () => discoverOidc(config.argocdBaseUrl);
    const provider = new OAuthProxyProvider({ config, store, discover });

    // OAuth 2.1 metadata + endpoints (/.well-known/*, /authorize, /token, /register).
    app.use(
      mcpAuthRouter({
        provider,
        issuerUrl: new URL(config.publicUrl),
        baseUrl: new URL(config.publicUrl)
      })
    );

    // The Dex redirect lands here (registered as the static client redirectURI).
    app.get(config.callbackPath, async (req, res) => {
      const code = req.query.code as string | undefined;
      const state = req.query.state as string | undefined;
      if (!code || !state) {
        res.status(400).send('Missing code or state');
        return;
      }
      try {
        const redirect = await provider.handleUpstreamCallback(code, state);
        res.redirect(redirect);
      } catch (error) {
        logger.error(
          { error: error instanceof Error ? error.message : String(error) },
          'OAuth callback failed'
        );
        res.status(400).send('Authentication failed');
      }
    });

    const bearerAuth = requireBearerAuth({ verifier: provider });

    app.post('/mcp', bearerAuth, async (req, res) => {
      const sessionIdFromHeader = req.headers['mcp-session-id'] as string | undefined;
      let transport: StreamableHTTPServerTransport;

      if (!stateless && sessionIdFromHeader && httpTransports[sessionIdFromHeader]) {
        transport = httpTransports[sessionIdFromHeader];
      } else if (stateless || (!sessionIdFromHeader && isInitializeRequest(req.body))) {
        const opaque = req.auth!.token; // set by requireBearerAuth
        const meta = await discover();
        const tokenSource = makeSessionTokenProvider(store, meta, config, opaque);

        transport = new StreamableHTTPServerTransport(
          stateless
            ? { sessionIdGenerator: undefined }
            : {
                sessionIdGenerator: () => randomUUID(),
                onsessioninitialized: (id) => {
                  httpTransports[id] = transport;
                }
              }
        );
        if (!stateless) {
          transport.onclose = () => {
            if (transport.sessionId) delete httpTransports[transport.sessionId];
          };
        }

        const server = createServer({
          argocdBaseUrl: config.argocdBaseUrl,
          argocdApiToken: '',
          pinBaseUrl: true,
          tokenSource
        });
        await server.connect(transport);
      } else {
        const errorMsg = sessionIdFromHeader
          ? `Invalid or expired session ID: ${sessionIdFromHeader}`
          : 'Bad Request: Not an initialization request and no valid session ID provided.';
        res.status(400).json({
          jsonrpc: '2.0',
          error: { code: -32000, message: errorMsg },
          id: req.body?.id !== undefined ? req.body.id : null
        });
        return;
      }
      await transport.handleRequest(req, res, req.body);
    });

    app.get('/mcp', (_req, res) => res.status(405).send('Method Not Allowed'));
    app.delete('/mcp', (_req, res) => res.status(405).send('Method Not Allowed'));

    logger.info(
      { port, argocdBaseUrl: config.argocdBaseUrl, tokenStore: config.tokenStore },
      `Connecting to Http Stream transport on port: ${port} (oidc auth mode)`
    );
    app.listen(port);
    return;
  }

  // ---- token mode (existing behavior, unchanged) ----
  // (the current /mcp handler, resolveCredentials usage, handleSessionRequest,
  //  and app.listen stay exactly as they are today)
```

Keep the entire existing `token`-mode implementation (the current function body from `app.post('/mcp', ...)` onward) in the `else` path unchanged.

- [ ] **Step 6: Build to typecheck the wiring**

Run: `pnpm build`
Expected: `tsup` completes with no type errors. (This is the primary check for Task 7's wiring, since the transport opens a real port and is covered end-to-end by the manual acceptance test in Task 8.)

- [ ] **Step 7: Run the full suite + lint**

Run: `pnpm test` — Expected: all pass (existing + new).
Run: `pnpm lint` — Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add src/server/server.ts src/server/transport.ts src/server/oidcTransport.test.ts
git commit -m "feat(server): wire oidc auth mode into HTTP transport, pin base URL"
```

---

## Task 8: Documentation and deployment artifacts

**Files:**
- Create: `deploy/README.md`, `deploy/dex-staticclient.yaml`, `deploy/mcp-deployment.yaml`
- Modify: `README.md`

**Interfaces:** none (docs/manifests).

- [ ] **Step 1: Write `deploy/dex-staticclient.yaml`**

```yaml
# Add to the argocd-cm ConfigMap under data.dex\.config. This registers a
# dedicated confidential OAuth client for the MCP server whose redirect URI is
# the MCP server's public ingress callback.
#
# The client secret must also be present in the argocd-secret Secret under the
# key referenced by $oidc.argocd-mcp.clientSecret, and mounted into the MCP
# server (see mcp-deployment.yaml) at ARGOCD_MCP_OIDC_CLIENT_SECRET_FILE.
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-cm
  namespace: argocd
data:
  dex.config: |
    connectors:
      # ... your existing upstream IdP connector(s) ...
    staticClients:
      - id: argocd-mcp
        name: ArgoCD MCP
        secret: $oidc.argocd-mcp.clientSecret
        redirectURIs:
          - https://argocd-mcp.example.com/oauth/callback
```

- [ ] **Step 2: Write `deploy/mcp-deployment.yaml`**

```yaml
# Minimal in-cluster deployment of the MCP server in oidc mode behind an ingress,
# with a Redis-backed token store for horizontal scaling.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: argocd-mcp
  namespace: argocd
spec:
  replicas: 2
  selector:
    matchLabels: { app: argocd-mcp }
  template:
    metadata:
      labels: { app: argocd-mcp }
    spec:
      containers:
        - name: argocd-mcp
          image: ghcr.io/argoproj-labs/argocd-mcp:latest
          args: ['http']
          ports: [{ containerPort: 3000 }]
          env:
            - { name: AUTH_MODE, value: oidc }
            - { name: MCP_PUBLIC_URL, value: https://argocd-mcp.example.com }
            - { name: ARGOCD_BASE_URL, value: https://argocd-server.argocd.svc }
            - { name: ARGOCD_MCP_OIDC_CLIENT_ID, value: argocd-mcp }
            - { name: ARGOCD_MCP_OIDC_CLIENT_SECRET_FILE, value: /secrets/oidc/clientSecret }
            - { name: TOKEN_STORE, value: redis }
            - { name: REDIS_URL, value: redis://argocd-mcp-redis:6379 }
          volumeMounts:
            - { name: oidc-secret, mountPath: /secrets/oidc, readOnly: true }
          readinessProbe:
            httpGet: { path: /healthz, port: 3000 }
      volumes:
        - name: oidc-secret
          secret:
            secretName: argocd-mcp-oidc
---
apiVersion: v1
kind: Service
metadata:
  name: argocd-mcp
  namespace: argocd
spec:
  selector: { app: argocd-mcp }
  ports: [{ port: 80, targetPort: 3000 }]
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: argocd-mcp
  namespace: argocd
spec:
  tls:
    - hosts: [argocd-mcp.example.com]
      secretName: argocd-mcp-tls
  rules:
    - host: argocd-mcp.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service: { name: argocd-mcp, port: { number: 80 } }
```

- [ ] **Step 3: Write `deploy/README.md`**

Document, in prose: the prerequisites (ArgoCD with Dex SSO already working), the four steps (create the `argocd-mcp-oidc` Secret with the client secret; add the Dex static client from `dex-staticclient.yaml`; if the issued token carries `aud: argocd-mcp`, add it to `oidc.config.allowedAudiences` in `argocd-cm`, otherwise note the opaque indirection makes this unnecessary; apply `mcp-deployment.yaml` plus a Redis Deployment/Service or managed Redis), and how to add the server in Claude as a remote MCP server at `https://argocd-mcp.example.com/mcp`. State plainly that `TOKEN_STORE=memory` requires `replicas: 1`.

- [ ] **Step 4: Add a "SSO (oidc) mode" section to `README.md`**

Under the existing Authentication docs, add a subsection listing the env vars from the config table in the design doc, a one-paragraph description of the browser flow, and a link to `deploy/README.md`. Keep the existing token-mode docs intact and note that oidc mode is opt-in via `AUTH_MODE=oidc`.

- [ ] **Step 5: Verify build & lint, then commit**

```bash
pnpm build && pnpm lint
git add deploy/ README.md
git commit -m "docs: SSO (oidc) mode deployment guide and manifests"
```

---

## Self-Review

**1. Spec coverage:**
- Opt-in oidc mode → Task 1 (config), Task 7 (wiring). ✓
- Per-user passthrough via opaque tokens → Task 6 (provider). ✓
- Bundled-Dex discovery → Task 2. ✓
- Public-ingress callback / `MCP_PUBLIC_URL` → Task 1 (callbackUrl), Task 7 (callback route). ✓
- Dedicated confidential Dex client → Task 6 (client_secret in exchange), Task 8 (Dex staticClient). ✓
- Redis token store + at-rest encryption → Task 5. ✓
- In-memory store → Task 4. ✓
- Lazy HttpClient + 401 refresh → Task 3. ✓
- Base-URL pinning (anti-exfiltration) → Task 7 (server.ts). ✓
- Two expiry layers → Task 3 (401 retry) + Task 6 (`exchangeRefreshToken`) + `sessionTokenProvider`. ✓
- Error handling / fail-closed → Task 1 (startup), Task 7 (callback 400s). ✓
- Testing (unit + contract + build) → each task; manual acceptance → Task 8 deploy README. ✓
- Backward compatibility → Tasks 3 & 7 preserve token-mode paths; `pnpm test` gate each task. ✓

**2. Placeholder scan:** No "TBD"/"handle appropriately"/"similar to". Docs-only steps (Task 8 steps 3–4) describe exact content to write, which is appropriate for prose deliverables.

**3. Type consistency:** `TokenSource`/`BearerTokenProvider` (Task 3) consumed by `sessionTokenProvider` and `server.ts` (Tasks 6–7). `TokenStore` method names identical across interface (Task 4), in-memory (Task 4), Redis (Task 5), provider (Task 6). `UpstreamToken.expiresAtMs`, `StoredToken.upstream`, `RefreshRecord.upstreamRefreshToken` used consistently. `OidcConfig.callbackUrl`/`clientId`/`clientSecret` consistent across Tasks 1/6/7. `OidcProviderMetadata.authorizationEndpoint`/`tokenEndpoint` consistent across Tasks 1/2/6.

**Known verification point** (flagged in Task 6 Step 6): confirm the SDK's `challengeForAuthorizationCode` is called before `exchangeAuthorizationCode` and adjust the take-then-re-put if the installed `@modelcontextprotocol/sdk` exposes a non-destructive read. This is the one place the plan depends on SDK call ordering.
