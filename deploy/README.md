# Deploying argocd-mcp in SSO (oidc) Mode

This guide explains how to deploy the argocd-mcp server in SSO mode, where authentication is delegated to ArgoCD's Dex instance. The MCP server runs as an HTTP server behind a Kubernetes Ingress and uses a Redis-backed token store to support horizontal scaling.

## Prerequisites

- **ArgoCD cluster** with Dex SSO already configured and working (you must have an existing OIDC provider connector in your Dex config)
- **Kubernetes cluster** with the argocd namespace
- **Redis >= 6.2** (required for the atomic `GETDEL` command used by the token store)
- **TLS certificates** for the MCP server's public hostname (e.g., `argocd-mcp.example.com`) — either a cert-manager Certificate or a pre-created TLS Secret

## Deployment Steps

### Step 1: Create the Client Secret

Generate or obtain your MCP server's OIDC client secret (a random string; 32+ characters recommended). This **one secret value** must be stored in **two places**, and they must carry the **identical value**:

1. **`argocd-mcp-oidc` Secret** — mounted into the MCP pod and read via `ARGOCD_MCP_OIDC_CLIENT_SECRET_FILE`:

   ```bash
   kubectl create secret generic argocd-mcp-oidc \
     --from-literal=clientSecret=<your-client-secret> \
     -n argocd
   ```

2. **`argocd-secret` Secret** — consumed by Dex to resolve the `$oidc.argocd-mcp.clientSecret` reference in the static client config (see Step 2). Patch the existing `argocd-secret` to add the same value under the `oidc.argocd-mcp.clientSecret` key:

   ```bash
   kubectl -n argocd patch secret argocd-secret \
     -p '{"stringData":{"oidc.argocd-mcp.clientSecret":"<SAME value as the argocd-mcp-oidc Secret>"}}'
   ```

> **Both secrets must carry the identical value.** `argocd-secret` is read by Dex when it validates the client during the token exchange; `argocd-mcp-oidc` is mounted into the MCP pod and presented by the MCP server during that same exchange. If they differ, the token exchange fails with an invalid-client error.

### Step 2: Register the MCP Server as a Dex Static Client

Edit the `argocd-cm` ConfigMap and add the MCP server as a static client. Merge the snippet from `dex-staticclient.yaml` into your existing `dex.config` under the `staticClients` list. Replace `argocd-mcp.example.com` with the actual public hostname where the MCP server will be accessed.

Example:
```bash
kubectl get configmap argocd-cm -n argocd -o yaml > /tmp/argocd-cm-backup.yaml
kubectl patch configmap argocd-cm -n argocd -p '{
  "data": {
    "dex.config": "... your existing dex.config ...\n    staticClients:\n      - id: argocd-mcp\n        name: ArgoCD MCP\n        secret: $oidc.argocd-mcp.clientSecret\n        redirectURIs:\n          - https://argocd-mcp.example.com/oauth/callback"
  }
}'
```

> **Warning: patching `data.dex.config` REPLACES the entire value.** The `... your existing dex.config ...` placeholder above is not literal — you must substitute your current, complete `dex.config` (including all existing `connectors:`) and merely append the `staticClients` entry. Running the command verbatim will wipe your existing ArgoCD SSO configuration. Prefer `kubectl edit configmap argocd-cm -n argocd` to edit the value in place, and keep the backup produced by the first line above.

Once the ConfigMap is updated, Dex will automatically reload and register the new static client.

### Step 3: Configure Token Audience (REQUIRED if the token's `aud` is `argocd-mcp`)

The MCP server forwards the user's OIDC token to the ArgoCD API. ArgoCD **enforces**
the token's `aud` (audience) claim: it only accepts tokens minted for its own
clients (typically `argo-cd` and `argo-cd-cli`; the exact IDs come from your
ArgoCD/Dex config). It does **not** accept a token regardless of audience.

**Case A — token audience is NOT `argocd-mcp`:** If your Dex instance issues the
MCP's token without `argocd-mcp` in the `aud` claim (e.g. via cross-client
"trusted peers" so the audience remains one ArgoCD already trusts), ArgoCD accepts
it and no extra configuration is needed.

**Case B — token audience IS `argocd-mcp`:** Because the MCP uses its own Dex
static client (`id: argocd-mcp`), Dex stamps `aud: ["argocd-mcp"]` on the issued
token. ArgoCD then rejects **every** MCP request with `401`
`invalid session: failed to verify the token`. Making ArgoCD accept it depends on
how ArgoCD consumes its OIDC provider:

- **External OIDC mode** (`argocd-cm` has a full `oidc.config` with `issuer` +
  `clientID`): add `argocd-mcp` to `oidc.config.allowedAudiences`, alongside your
  existing ArgoCD client ID (do not drop it):

  ```yaml
  data:
    oidc.config: |
      name: <your provider>
      issuer: <your issuer>
      clientID: <your ArgoCD client ID>
      clientSecret: <...>
      allowedAudiences:
        - <your ArgoCD client ID>
        - argocd-mcp
  ```

- **Bundled Dex mode** (`argocd-cm` has `dex.config`, no `oidc.config`): the
  allowed audiences are **hardcoded** to `argo-cd` and `argo-cd-cli`
  (`util/settings/settings.go` `OAuth2AllowedAudiences`), and ArgoCD does **not**
  expose `trustedPeers` on its generated `argo-cd` Dex client
  (`util/dex/config.go`), so **neither `allowedAudiences` nor Dex cross-client
  audience is available**. Do **not** add a bare `oidc.config: { allowedAudiences }`
  — a partial `oidc.config` (no `issuer`/`clientID`) switches ArgoCD into external
  mode and **breaks Dex/SAML login entirely**. To use this MCP with bundled Dex you
  must convert ArgoCD to consume Dex as external OIDC: register a static client for
  ArgoCD's own login (e.g. `id: argo-cd-oidc` with ArgoCD's `/auth/callback`
  redirect URI and a known secret), point `oidc.config` at
  `https://<argocd>/api/dex` with that client, and list both it and `argocd-mcp` in
  `allowedAudiences`. Your SAML connector keeps working underneath. **Test on a
  non-prod ArgoCD first — this changes the login flow.**

> **Diagnosing this:** if MCP tool calls fail, check the **argocd-server** logs.
> A line like `token verification failed for all audiences: ... expected audience
> "argo-cd" got ["argocd-mcp"]` confirms the audience mismatch. (The MCP surfaces
> it as `ArgoCD rejected the bearer token (401: invalid session: failed to verify
> the token)`.)

### Step 4: Deploy the MCP Server and Redis

1. **Review and customize** `mcp-deployment.yaml`:
   - Replace `https://argocd-mcp.example.com` with your actual public MCP hostname (env: `MCP_PUBLIC_URL`)
   - Verify `ARGOCD_BASE_URL` points to your ArgoCD server (e.g., `https://argocd-server.argocd.svc` for in-cluster access or the public URL if cross-cluster)
   - If using in-memory token store (for single-replica deployments), change `TOKEN_STORE` to `memory`, remove the `REDIS_URL` env var, and set `replicas: 1` in the Deployment spec

2. **Deploy the manifests:**
   ```bash
   kubectl apply -f mcp-deployment.yaml
   ```

3. **Deploy or verify Redis** (if using `TOKEN_STORE=redis`):

   **Option A: Deploy a Redis pod in-cluster** (minimal, for testing):
   ```bash
   kubectl run argocd-mcp-redis \
     --image=redis:7-alpine \
     -n argocd \
     -- redis-server --appendonly yes
   kubectl expose pod argocd-mcp-redis --port=6379 -n argocd
   ```

   **Option B: Use a managed Redis service** (production recommended):
   - Provision a managed Redis instance (AWS ElastiCache, Azure Cache for Redis, Google Cloud Memorystore, etc.)
   - Update `REDIS_URL` in `mcp-deployment.yaml` to your managed Redis endpoint
   - Ensure your Kubernetes cluster can reach the Redis instance

4. **Verify the deployment:**
   ```bash
   kubectl logs -f deployment/argocd-mcp -n argocd
   kubectl port-forward svc/argocd-mcp 8080:80 -n argocd
   curl http://localhost:8080/healthz
   ```

## Adding the MCP Server to Claude

Once the deployment is running and accessible at your public hostname (e.g., `https://argocd-mcp.example.com`), add it to Claude Desktop or Claude Code as a remote MCP server:

### Claude Desktop

Edit `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "argocd-mcp": {
      "url": "https://argocd-mcp.example.com/mcp",
      "env": {}
    }
  }
}
```

### Claude Code

Add the server from your shell with the `claude mcp add` command:
```bash
claude mcp add --transport http argocd-mcp https://argocd-mcp.example.com/mcp
```

The browser-based SSO flow opens automatically on the first tool use, prompting you to authenticate with Dex.

## Environment Variables Reference

| Variable | Required | Default | Description |
|---|---|---|---|
| `AUTH_MODE` | No | `token` | Set to `oidc` to enable SSO mode. |
| `ARGOCD_MCP_OIDC_CLIENT_MODE` | No | `explicit` | OIDC client mode. `explicit` uses a dedicated `argocd-mcp` Dex static client. `derived` reuses ArgoCD's own `argo-cd` client: the secret is derived from `argocd-secret`'s `server.secretkey` and the callback moves to `/auth/callback`. Requires ArgoCD's bundled Dex. |
| `ARGOCD_SERVER_SECRETKEY_FILE` | Yes*§ | — | Path to a mounted copy of `argocd-secret`'s `server.secretkey` (mount only that key via `items:`). Required (and only allowed) when `ARGOCD_MCP_OIDC_CLIENT_MODE=derived`. |
| `MCP_PUBLIC_URL` | Yes* | — | The public HTTPS URL where the MCP server is accessed (e.g., `https://argocd-mcp.example.com`). Used to construct the OAuth callback URL. Must use HTTPS; trailing slashes are stripped automatically. |
| `ARGOCD_BASE_URL` | Yes* | — | The URL of the ArgoCD server (http or https). Used for token validation and API calls. Trailing slashes are stripped automatically. |
| `ARGOCD_MCP_OIDC_CLIENT_ID` | Yes*‡ | — | The OIDC client ID registered with Dex. No default (required in oidc mode); conventional/example value: `argocd-mcp`. |
| `ARGOCD_MCP_OIDC_CLIENT_SECRET` | Yes*†‡ | — | The OIDC client secret provided directly as an env var (e.g., via a Kubernetes `secretKeyRef`). Trimmed on read. Takes precedence over `..._FILE` when both are set and non-blank. |
| `ARGOCD_MCP_OIDC_CLIENT_SECRET_FILE` | Yes*†‡ | — | Path to a file containing the OIDC client secret (e.g., `/secrets/oidc/clientSecret`). Used as the fallback when `ARGOCD_MCP_OIDC_CLIENT_SECRET` is unset or blank. |
| `TOKEN_STORE` | No | `memory` | Token storage backend: `memory` (single-replica only) or `redis` (horizontally scalable). |
| `REDIS_URL` | No | — | Explicit Redis connection URL (e.g., `redis://localhost:6379`, or `rediss://` for TLS). Takes precedence over the discrete `REDIS_ENDPOINT`/`REDIS_PORT` vars below. One of `REDIS_URL` or `REDIS_ENDPOINT` is required when `TOKEN_STORE=redis`. |
| `REDIS_ENDPOINT` | No | — | Redis primary/writer host, used to build the connection URL when `REDIS_URL` is unset (e.g., an AWS ElastiCache Serverless endpoint). Only the writer endpoint is used — the token store needs read-after-write consistency, so a reader/replica endpoint must not be configured here. |
| `REDIS_PORT` | No | `6379` | Port paired with `REDIS_ENDPOINT`. |
| `REDIS_TLS` | No | `true` | When building from `REDIS_ENDPOINT`, use TLS (`rediss://`). Defaults to `true` (required by ElastiCache Serverless); set to `false` for a plaintext/self-hosted Redis. |
| `TOKEN_STORE_ENCRYPTION_KEY_FILE` | No | — | Path to a file containing a 32-byte AES-256 key (as 64 hex characters or raw bytes) for encrypting tokens at rest. Optional; if omitted, tokens are stored in plaintext. |
| `TRUST_PROXY_HOPS` | No | `1` | Number of reverse-proxy hops in front of the server (used for the HTTP transport). `1` for a single Kubernetes ingress; increase for stacked proxies (e.g. AWS ALB + nginx ingress = `2`); `0` disables proxy trust. Must be set correctly or the OAuth router's rate limiter logs `ERR_ERL_UNEXPECTED_X_FORWARDED_FOR`. |

**\* Required when `AUTH_MODE=oidc`; not used in token mode.*
**† Provide the client secret via *exactly one* of these two; if neither is set, startup fails closed.*
**‡ Explicit mode only. Setting any of these with `ARGOCD_MCP_OIDC_CLIENT_MODE=derived` fails startup.*
**§ Derived mode only. SECURITY: `server.secretkey` also signs ArgoCD session JWTs — derived mode places the MCP server in the same trust tier as the ArgoCD API server. See `deploy/derived-mode.yaml`.*

## Token Store Modes

### In-Memory Store (`TOKEN_STORE=memory`)

- Suitable for single-replica deployments or testing
- Tokens are held in RAM; all tokens are lost on pod restart
- **Must set `replicas: 1` in the Deployment spec** — multiple replicas without sticky sessions will cause inconsistent state
- No Redis required

### Redis Store (`TOKEN_STORE=redis`)

- Suitable for multi-replica deployments (standard production setup)
- Tokens are stored in Redis with atomic `GETDEL` operations for consumption
- **Requires Redis >= 6.2** for the `GETDEL` command (introduced in Redis 6.2)
- Tokens persist across pod restarts (but are lost if Redis is restarted without persistence)
- Supports optional encryption at rest via `TOKEN_STORE_ENCRYPTION_KEY_FILE`
- Replicas can scale horizontally without sticky sessions

## Troubleshooting

**MCP server logs show "Missing required OIDC field":**
- Verify all required `AUTH_MODE=oidc` environment variables are set
- Check that the secret files are correctly mounted and readable

**OAuth callback returns a `400` error:**
- Confirm the Dex static client's `redirectURIs` matches your `MCP_PUBLIC_URL` + `/oauth/callback`
- Verify the client secret in the Kubernetes Secret matches the value in the Dex config

**Readiness probe failing:**
- Check that the MCP pod can reach the ArgoCD server via `ARGOCD_BASE_URL`
- Inspect logs for TLS/certificate errors if using HTTPS for `ARGOCD_BASE_URL`

**Tokens rejected or Redis connection errors:**
- If using `TOKEN_STORE=redis`, ensure the `REDIS_URL` is correct and the pod can connect
- Verify Redis version is >= 6.2: `redis-cli info server` should show `redis_version:6.2` or higher
