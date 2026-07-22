# Dual OIDC client modes: explicit and derived

**Date:** 2026-07-22
**Status:** Approved
**Branch:** feat/argocd-sso-auth

## Problem

With ArgoCD's bundled Dex, the API server only accepts tokens whose `aud` is
`argo-cd` or `argo-cd-cli` — hardcoded in
`ArgoCDSettings.OAuth2AllowedAudiences()` (argo-cd v3.3.12,
`util/settings/settings.go:1974`). Our current design registers a separate
`argocd-mcp` static client in `dex.config`, so the tokens Dex mints for us
carry `aud: argocd-mcp` and ArgoCD rejects them with 401 (observed on
non-prod-v10 as a misleading "No upstream refresh token" symptom).
`allowedAudiences` is only honored when an external `oidc.config` is set, not
with bundled Dex.

## Decision

Support two OIDC client modes in the MCP server, selected by env var. The
existing behavior remains the default.

### Mode selection

- New env var `ARGOCD_MCP_OIDC_CLIENT_MODE`: `explicit` (default) | `derived`.
- Unset/blank → `explicit` (full backward compatibility).
- Any other value → startup error naming the variable (matches
  `resolveAuthMode`'s fail-closed convention).

### Explicit mode (today's behavior, unchanged)

- `clientId` from `ARGOCD_MCP_OIDC_CLIENT_ID`.
- `clientSecret` from `ARGOCD_MCP_OIDC_CLIENT_SECRET` or `_FILE`.
- `callbackPath` = `/oauth/callback`.
- Requires the `argocd-mcp` static client injected into `dex.config`
  (deploy/dex-staticclient.yaml). On bundled-Dex installs this additionally
  requires ArgoCD to run an external `oidc.config` with `allowedAudiences`
  including `argocd-mcp` — otherwise ArgoCD 401s the tokens.

### Derived mode (new)

Reuses ArgoCD's own `argo-cd` Dex static client, exploiting three v3.3.12
contracts:

1. **Client secret is derivable.** `DexOAuth2ClientSecret()`
   (`util/settings/settings.go:2099`) =
   `base64.URLEncoding(sha256(server.secretkey))[:40]`. Both `argocd-dex
   rundex` and the API server compute it independently; we become a third
   party to the same contract.
2. **Redirect URIs are extensible.** The generated `argo-cd` static client's
   `redirectURIs` include `<additionalUrls[i]>/auth/callback` for every entry
   in `argocd-cm`'s `additionalUrls` (`util/dex/config.go:76-85`). Adding the
   MCP public URL there registers our callback through a first-class knob.
3. **Audience check passes natively.** Tokens minted to client `argo-cd`
   carry `aud: argo-cd`, which the bundled-Dex allowlist accepts.

Resolution rules:

- Requires `ARGOCD_SERVER_SECRETKEY_FILE` — path to a mounted copy of
  `argocd-secret`'s `server.secretkey` (single-key mount only).
- `clientId` = `argo-cd` (constant).
- `clientSecret` = `base64url(sha256(secretkey))` truncated to 40 chars.
  Go's padded `URLEncoding` and Node's unpadded `base64url` agree on the
  first 40 chars (SHA-256 → 44 base64 chars; padding beyond index 40).
  Known vector, verified against Go, Node, and Python:
  `sha256("test-server-signature-key")` → `cbeOgaLo8YsJi74TXZRRLozNtAZyTrTdNTrYedoF`.
- `callbackPath` = `/auth/callback` (must match what
  `GenerateDexConfigYAML` registers for `additionalUrls` entries).
- Setting `ARGOCD_MCP_OIDC_CLIENT_ID`, `ARGOCD_MCP_OIDC_CLIENT_SECRET`, or
  `ARGOCD_MCP_OIDC_CLIENT_SECRET_FILE` together with derived mode is a
  startup error (fail closed; no ambiguity about which client is in use).

### Structure

Single `OidcConfig` shape, mode-resolved inside `loadOidcConfig()`
(src/auth/config.ts). `callbackPath` changes from module constant to
mode-dependent value. No changes to `OAuthProxyProvider`, discovery,
transports, or token stores — they already consume
`config.clientId/clientSecret/callbackPath/callbackUrl` opaquely.
A `mode` field is added to `OidcConfig` for logging/diagnostics.

## Security considerations

`server.secretkey` is also ArgoCD's session-JWT signing key
(`ServerSignature`). A pod holding it can mint arbitrary ArgoCD sessions, so
derived mode places the MCP server in the same trust tier as the ArgoCD API
server. This is documented prominently; the deploy manifest mounts only the
single `server.secretkey` key from `argocd-secret` (via `items:`), never the
whole secret (which also contains the admin password hash and TLS material).

Derived-mode logins are indistinguishable from ArgoCD UI logins in Dex and
audit logs (same client id, same `aud`). User identity and groups claims
remain per-human; only the OAuth client identity blurs. Accepted trade-off;
explicit mode remains available where client-level audit separation matters.

## Deploy & docs

- New derived-mode deployment variant in `deploy/`: no `argocd-mcp-oidc`
  secret, no `dex-staticclient.yaml`; adds the single-key `argocd-secret`
  mount and an `argocd-cm` snippet with `additionalUrls`.
- Docs state: derived mode requires bundled Dex; external-OIDC installs use
  explicit mode + `allowedAudiences`; trust-tier caveat above.

## Testing

- Mode resolution matrix: default, blank, `explicit`, `derived`, typo →
  throw; conflicting explicit vars in derived mode → throw; missing
  `ARGOCD_SERVER_SECRETKEY_FILE` in derived mode → throw.
- Secret derivation: known vector above; trailing-newline trimming of the
  mounted file.
- Callback path/URL per mode.
- Existing tests must pass unchanged (explicit default preserves behavior).

## Out of scope

- Dex `trustedPeers` / token-exchange approaches (blocked: the generated
  `argo-cd` static client cannot carry `trustedPeers`).
- Any change to ArgoCD itself.
