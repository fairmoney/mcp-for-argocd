# Design: ArgoCD SSO authentication for the MCP HTTP transport

**Date:** 2026-07-08
**Status:** Approved design, pending implementation plan
**Author:** Cristian Calin (with Claude)

## Problem

Today the server authenticates to ArgoCD with a **static API token** supplied out-of-band
(header `x-argocd-api-token`, env `ARGOCD_API_TOKEN`, or a per-base-URL token registry file).
The token is resolved once and frozen into the HTTP client
([`src/argocd/http.ts`](../../../src/argocd/http.ts), [`src/server/tokenRegistry.ts`](../../../src/server/tokenRegistry.ts),
[`src/server/transport.ts`](../../../src/server/transport.ts)).

We want to run this server **in-cluster, behind an HTTPS ingress**, expose it as a remote MCP
server, and let users **log in through the native ArgoCD SSO experience**: the MCP client opens a
browser, the user completes the SSO chain (ArgoCD's bundled Dex → upstream corporate IdP), and the
resulting identity is used for ArgoCD API calls — so ArgoCD enforces that user's own RBAC and audit
trail. No pre-provisioned, long-lived token stored anywhere.

## Goals

- Browser-driven SSO login initiated automatically by the MCP client (no separate CLI step).
- Per-user identity passthrough: ArgoCD sees the real user, not a shared service account.
- Runs remotely in a Kubernetes cluster behind an ingress; horizontally scalable.
- Fully **opt-in**: the existing stdio / static-token / registry / per-call-base-URL behavior is
  untouched when the mode is off, keeping the change upstream-mergeable.

## Non-goals (YAGNI for this iteration)

- The stdio CLI-login flow (`login`/`logout`/`whoami`, `~/.argocd-mcp/auth.json`). PR #86 covers
  that separately; not needed for the remote-server use case.
- Multi-ArgoCD-instance SSO. The `oidc` mode fronts a **single** configured ArgoCD instance.
- Direct (non-Dex) external OIDC. The discovery layer is written to support it, but the target and
  test matrix is bundled-Dex-→-upstream-IdP.

## Prior art

[argoproj-labs/mcp-for-argocd#86](https://github.com/argoproj-labs/mcp-for-argocd/pull/86)
("feat: add SSO authentication support") implements a very similar HTTP OAuth flow plus a stdio CLI
login. We **borrow its proven patterns** but do not adopt its structure, because it is built to run
on the user's laptop:

- It hardcodes `mcpBaseUrl = http://localhost:${port}` (OAuth issuer/resource metadata) and the Dex
  callback to `http://localhost:8085/auth/callback` — the redirect URI ArgoCD pre-registers for the
  built-in `argo-cd-cli` public client. That only resolves when the browser and the callback server
  share a host. It cannot run behind an ingress.
- Its token/auth state is in-process memory only, so it cannot scale to multiple replicas.

Patterns we reuse: OIDC discovery from ArgoCD's `/api/v1/settings`; the **opaque-token
indirection** (issue a random token to the MCP client, keep the real ArgoCD JWT server-side); PKCE;
refresh-token handling.

## Approach

Add an opt-in **`oidc` auth mode** to the HTTP transport. In this mode the server is an OAuth 2.1
**authorization-server facade** in front of ArgoCD's Dex. Dex has no dynamic client registration and
does not know MCP clients' ephemeral redirect URIs, so the server absorbs that gap: MCP clients
register with *the server*, and the server holds a single pre-provisioned confidential identity
(`argocd-mcp`) toward Dex.

### End-to-end flow

```
Claude/Cursor (laptop)                 In-cluster MCP server                 ArgoCD (Dex → IdP)

 1. POST /mcp (no token)      ───▶  401 + WWW-Authenticate: Bearer
                                     resource_metadata="…/.well-known/oauth-protected-resource"
 2. GET /.well-known/oauth-protected-resource      ───▶  served by server
 3. GET /.well-known/oauth-authorization-server    ───▶  served by server (issuer = MCP_PUBLIC_URL)
 4. POST /register (DCR)                            ───▶  server issues an MCP client_id
 5. browser ▶ GET  MCP /authorize   ───▶  302 → Dex /api/dex/auth
                                          (client_id=argocd-mcp, PKCE, redirect=…/oauth/callback)
                                          user authenticates: Dex → upstream IdP
 6. Dex 302 ▶ GET  MCP /oauth/callback?code&state  ───▶  server exchanges code @ Dex
                                          (confidential client_secret + PKCE verifier)
                                          → real ArgoCD-accepted tokens
 7. 302 ▶ client's localhost redirect_uri + our authorization code
 8. POST MCP /token (our code + client PKCE)       ───▶  opaque access + refresh token
 9. POST /mcp  Authorization: Bearer <opaque>      ───▶  verify → map opaque → real JWT
                                                          → ArgoCD API call as the real user
```

The one decisive change vs PR #86: **`MCP_PUBLIC_URL` drives the issuer/resource metadata and the
callback URL**, so step 6 returns to `https://<ingress>/oauth/callback` (reachable by the browser),
not `http://localhost:8085`.

## Configuration

All env-driven for k8s. Secrets are read from **files**, matching the existing token-registry
convention (keeps them out of the process environment, crash dumps, and child-process inheritance).

| Variable | Required (oidc mode) | Purpose |
|---|---|---|
| `AUTH_MODE` | — | `token` (default, today's behavior) or `oidc` |
| `MCP_PUBLIC_URL` | yes | External HTTPS base URL. Drives OAuth issuer, resource metadata, and `${MCP_PUBLIC_URL}/oauth/callback`. Must be `https://`. |
| `ARGOCD_BASE_URL` | yes | The single ArgoCD instance this server fronts |
| `ARGOCD_MCP_OIDC_CLIENT_ID` | yes | Dedicated Dex static client id (e.g. `argocd-mcp`) |
| `ARGOCD_MCP_OIDC_CLIENT_SECRET_FILE` | yes | Path to the mounted client secret |
| `TOKEN_STORE` | — | `memory` (default) or `redis` |
| `REDIS_URL` | when `TOKEN_STORE=redis` | e.g. `redis://argocd-mcp-redis:6379` |
| `TOKEN_STORE_ENCRYPTION_KEY_FILE` | optional | Path to a 32-byte key; when set, stored ArgoCD tokens are encrypted at rest (AES-256-GCM) |

**Startup validation (fail closed):** in `oidc` mode, a missing `MCP_PUBLIC_URL`, non-HTTPS public
URL, missing client id/secret, `TOKEN_STORE=redis` without `REDIS_URL`, or an ArgoCD `/api/v1/settings`
response indicating SSO is not configured → the process logs a clear error and exits, rather than
starting in a broken state.

## Components

Each is a small, independently testable unit with an explicit interface.

### 1. `src/auth/oidcDiscovery.ts`
Fetches ArgoCD `/api/v1/settings`, derives the OIDC provider metadata. For bundled Dex, constructs
the known `/api/dex/{auth,token,userinfo}` endpoints and issuer `${ARGOCD_BASE_URL}/api/dex`. For a
direct external OIDC config, fetches the provider's `/.well-known/openid-configuration`. Result is
cached. Throws a typed `SSONotConfiguredError` when neither is present.
*Depends on:* `fetch`, `ARGOCD_BASE_URL`. *Borrowed from* PR #86 `settings.ts`.

### 2. `src/auth/tokenStore.ts`
Interface abstracting all OAuth server-side state, so scaling is a config choice:

```ts
interface TokenStore {
  // short-lived flow state
  putPendingAuth(state: string, v: PendingAuth, ttlSec: number): Promise<void>;
  takePendingAuth(state: string): Promise<PendingAuth | undefined>;   // get + delete
  putAuthCode(code: string, v: CompletedAuth, ttlSec: number): Promise<void>;
  takeAuthCode(code: string): Promise<CompletedAuth | undefined>;      // get + delete
  // long-lived issued tokens
  putAccessToken(opaque: string, v: StoredToken, ttlSec?: number): Promise<void>;
  getAccessToken(opaque: string): Promise<StoredToken | undefined>;
  deleteAccessToken(opaque: string): Promise<void>;
  putRefreshToken(opaque: string, v: RefreshRecord): Promise<void>;
  getRefreshToken(opaque: string): Promise<RefreshRecord | undefined>;
  deleteRefreshToken(opaque: string): Promise<void>;
}
```

Two implementations:
- **`InMemoryTokenStore`** — `Map`-backed; a periodic sweep evicts expired entries (the flow-state
  entries carry an `expiresAt`). Single-replica only.
- **`RedisTokenStore`** — `ioredis`-backed; keys namespaced (`argocd-mcp:pending:*`, `:code:*`,
  `:access:*`, `:refresh:*`); TTL via native key expiry (no sweep needed). Enables multiple replicas
  behind the ingress — a callback can land on a different pod than the `/authorize` that created the
  pending state. Values optionally AES-256-GCM encrypted when `TOKEN_STORE_ENCRYPTION_KEY_FILE` is set.

`ioredis` chosen for its simple promise API and built-in Sentinel/Cluster support.

### 3. `src/auth/oauthProxyProvider.ts`
Implements the MCP SDK `OAuthServerProvider` interface:
- `clientsStore` — DCR: register/lookup MCP clients (persisted in the `TokenStore`).
- `authorize(client, params, res)` — create PKCE + state for the *upstream* Dex flow, persist a
  `PendingAuth` (keyed by upstream state) binding the MCP client's redirect URI/state/PKCE challenge,
  then 302 to Dex `/api/dex/auth` with `client_id=argocd-mcp`, `redirect_uri=${MCP_PUBLIC_URL}/oauth/callback`.
- `handleUpstreamCallback(code, state)` — look up + consume the `PendingAuth`, exchange the code at
  Dex's token endpoint using the **confidential client secret + PKCE verifier**, store a
  `CompletedAuth` under a freshly minted authorization code, return the MCP client's redirect URL
  with that code.
- `challengeForAuthorizationCode` / `exchangeAuthorizationCode` — standard MCP-side PKCE + swap our
  code for an **opaque** access token (and opaque refresh token), storing the `opaque → real JWT`
  mapping in the `TokenStore`.
- `exchangeRefreshToken` — refresh the upstream token via Dex, rotate the opaque tokens.
- `verifyAccessToken(opaque)` — look up the stored real token; return `AuthInfo` whose
  `extra = { argocdToken, argocdBaseUrl }`.

*Borrowed from* PR #86 `mcp-oauth-provider.ts`. **Changes:** public-ingress callback URL; confidential
client (sends `client_secret` on token exchange); state persisted via `TokenStore` (not a private Map).

### 4. `src/argocd/http.ts` — lazy token (core refactor)
Today `HttpClient` computes `Authorization: Bearer ${apiToken}` once in the constructor and freezes
it. A session-scoped SSO token expires, so a frozen header silently kills the session after minutes.

Change `HttpClient` to accept a **token source**: `string | (() => Promise<string>)`. Each request
resolves the current bearer via the source. On a `401`, invalidate/refresh once and retry the request
a single time. The static-token path passes a string (behavior identical to today); the `oidc` path
passes a getter backed by the `TokenStore` + provider refresh, so mid-session refresh is transparent.
`ArgoCDClient` ([`src/argocd/client.ts`](../../../src/argocd/client.ts)) is updated to thread the token
source through.

**Two independent expiry layers** — keep them distinct:
- *Client-facing* opaque access token expiry is handled by the **MCP client** via the standard OAuth
  refresh grant (`exchangeRefreshToken`), which rotates the opaque token. The `requireBearerAuth`
  middleware runs per request, so a rotated opaque bearer keeps validating regardless of MCP session id.
- *Upstream* ArgoCD/Dex token expiry is handled **server-side** by the lazy `HttpClient` token source:
  it resolves the current upstream token **for the session's opaque bearer** from the `TokenStore` on
  each call, refreshing the upstream token (via the stored upstream refresh token) when it is expired
  or near expiry and writing the result back to the store. The token source therefore keys off the
  session's identity and re-reads the store — it never captures an init-time token snapshot.

### 5. `src/server/transport.ts` — wiring
`connectHttpTransport` gains an `oidc` branch:
- Instantiate `oidcDiscovery`, `TokenStore` (per `TOKEN_STORE`), `OAuthProxyProvider`.
- `app.use(mcpAuthRouter({ provider, issuerUrl: MCP_PUBLIC_URL, baseUrl: MCP_PUBLIC_URL }))`.
- Mount `GET /oauth/callback` on the **same** express app (served via the ingress), which calls
  `provider.handleUpstreamCallback` and 302s back to the MCP client.
- Wrap `/mcp` in `requireBearerAuth({ verifier: provider })`; on session init, build the ArgoCD
  client with a token source that reads `req.auth.extra.argocdToken` (refreshable via the store).
- The existing `/healthz` endpoint stays public.

The legacy (`token`) branch is the current code, unchanged. `connectStdioTransport` and
`connectSSETransport` are unchanged.

### 6. `src/server/server.ts` — base-URL pinning in oidc mode
In `oidc` mode the per-call `argocdBaseUrl` tool argument is **ignored**; every call targets the
configured `ARGOCD_BASE_URL`. This preserves the existing anti-exfiltration property
([`resolveClient` in server.ts](../../../src/server/server.ts)): a user's token is never sent to an
arbitrary host chosen by the caller or a prompt-injected model.

## Error handling

- **SSO not configured on ArgoCD** → typed `SSONotConfiguredError`, fail closed at startup.
- **Misconfiguration** (missing public URL / secret / redis URL) → clear startup error, exit non-zero.
- **Unknown/expired state or auth code** at callback/token → 400, no state leak.
- **ArgoCD 401 mid-session** → `HttpClient` attempts one refresh-and-retry via the provider; if that
  fails, the tool call returns a clear auth error so the MCP client can re-run the OAuth flow.
- **Redis unavailable** → in `oidc`+`redis` mode this is fatal for auth; log and return 503 on auth
  paths rather than silently degrading to memory (which would split state across replicas).
- Secrets (client secret, tokens) are never logged.

## Security model

- **Opaque tokens**: the MCP client never receives a Dex JWT; the client-facing token is
  audience-bound to this server, satisfying the MCP spec's no-passthrough-of-foreign-audience rule.
- **Per-user RBAC**: the forwarded token is the user's own; ArgoCD enforces their permissions.
- **Base-URL pinned** (see §6).
- **Confidential client**: secret loaded from a mounted file, never from env or logs.
- **HTTPS issuer**: `MCP_PUBLIC_URL` must be https (OAuth metadata requirement for non-localhost);
  TLS terminates at the ingress, in-cluster traffic can be plaintext.
- **At-rest encryption** (optional) for stored tokens when a key file is provided.

## ArgoCD-side prerequisites (deliverable)

1. **Dex static client** in `argocd-cm` `dex.config`:
   ```yaml
   staticClients:
     - id: argocd-mcp
       name: ArgoCD MCP
       secret: $oidc.argocd-mcp.clientSecret   # from argocd-secret
       redirectURIs:
         - https://<mcp-ingress>/oauth/callback
   ```
2. If tokens carry `aud: argocd-mcp`, either add it to `oidc.config.allowedAudiences`, or rely on the
   opaque indirection (ArgoCD only ever receives a Dex-minted token it already trusts). Documented both.
3. Example k8s `Deployment` / `Service` / `Ingress` and a Redis `Deployment`/`Service` (or reference a
   managed Redis), plus a README "SSO mode" section.

## Testing

- **Unit**: `oauthProxyProvider` full sequence (authorize → callback → exchange → refresh → verify)
  against a mock Dex; `oidcDiscovery` parsing (Dex vs external vs not-configured); both `TokenStore`
  impls against a shared contract test (in-memory + `ioredis-mock`); `HttpClient` lazy token +
  401-refresh-retry; startup validation.
- **Integration**: full HTTP flow against a mocked Dex + `/api/v1/settings`, asserting opaque tokens
  are issued and the real token reaches ArgoCD.
- **Manual acceptance**: real Dex-backed ArgoCD in-cluster + Claude as the MCP client — browser SSO
  chain completes, a tool call runs as the logged-in user, session survives token refresh, and a
  second replica can serve a callback for a flow started on the first (Redis mode).

## Rollout

- Ship behind `AUTH_MODE=oidc`; default `token` means zero change for current users and CI.
- New dependency: `ioredis`.
- Document single-replica requirement for `TOKEN_STORE=memory`; multi-replica requires `redis`.
