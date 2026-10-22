# Machine API keys alongside OIDC

**Date:** 2026-10-22
**Status:** Approved (2026-10-22, with the key-hash and client-address additions)
**Branch:** mb/OPS-6124-machine-keys
**Ticket:** OPS-6124

## Problem

The AWS DevOps Agent has to use the production instance (`AUTH_MODE=oidc`).
It cannot do a browser login; it can only present a fixed bearer token or API
key. In oidc mode every `/mcp` request goes through `requireBearerAuth`, whose
only verifier is `OAuthProxyProvider.verifyAccessToken`, and that accepts only
opaque tokens this server minted after a Dex authorization-code login. So a
machine has no way in.

Upstream offers no alternative. Its inbound credential, `MCP_AUTH_TOKEN`, is
one shared secret for the whole listener ("not a per-caller identity … for
different reach per caller, run separate instances", SECURITY.md). The team's
requirements are several callers, each with its own credential and its own
ArgoCD permissions, on one instance.

## Decision

In oidc mode, also accept named machine API keys, configured on the pod, each
bound to its own ArgoCD API token. This is the model of opensearch-edge-logs-mcp
(`AGENT_API_KEYS`) and of Cerberus (OAuth for people, `cerberus_sk_` keys for
machines). Permissions per key are ArgoCD's: the key's ArgoCD account and its
RBAC decide what the caller may do. The MCP registers the same tool set for
every session, as today.

### Configuration

`AGENT_API_KEYS`: a JSON object of named entries.

```json
{
  "devops-agent": { "keySha256": "<64 lowercase hex>", "argocdToken": "<ArgoCD API token>" }
}
```

- A name is `[a-z0-9-]+`. It is the principal, logged as `apikey:<name>`.
- A key is `amk_` plus 64 lowercase hex characters, generated with
  `printf 'amk_%s\n' "$(openssl rand -hex 32)"`. The caller holds the key; the
  pod holds only `keySha256`, the SHA-256 of the whole key string (prefix
  included), as 64 lowercase hex characters. Terraform computes it with
  `sha256()` from the same etfvars entry the caller's registration reads, so a
  pod compromise yields no inbound key. (The ArgoCD tokens are unavoidably
  plaintext.)
- `argocdToken` is the ArgoCD API token of a local ArgoCD account created for
  that caller (`argocd account generate-token --account <name>`).
- Startup refuses invalid JSON, an empty object, a bad name, a bad hash format,
  the same hash under two names, or a missing `argocdToken`. It also refuses the
  variable when `AUTH_MODE` is not `oidc`: token mode has no inbound
  authentication in this fork, so the keys would mean nothing there. All of this
  follows the fail-closed convention of `resolveAuthMode` and
  `ARGOCD_TOKEN_REGISTRY_PATH`.
- Unset means no machine path. Every other instance keeps today's behaviour.

### Request routing (oidc `/mcp`)

`requireBearerAuth` keeps gating `/mcp`; its verifier becomes a composite that
routes on the credential's shape, never on a header name:

| `Authorization: Bearer …` value | Verifier |
|---|---|
| starts with `amk_` | machine keys: hash the presented key and compare it against every configured `keySha256` with `timingSafeEqual`, with no early exit; a miss throws `InvalidTokenError` (SDK → 401); a hit yields `AuthInfo { clientId: "apikey:<name>", extra: { kind: "apikey", principal, argocdToken } }` |
| anything else | `OAuthProxyProvider.verifyAccessToken`, unchanged |

Only `Authorization: Bearer` is read. The DevOps Agent registers the key with
`authorization_config.bearer_token`, which emits exactly that header. (edge-logs
also accepts `X-API-Key`; not here, so there is one inbound path to reason about.)

A rejected key costs one pass over the configured keys and no outbound call,
and it creates no session, so bad keys cannot fill `MAX_SESSIONS`.

### Session construction

On initialize (and on every request in stateless mode) the handler reads
`req.auth.extra.kind`:

- `apikey`: `createServer({ argocdBaseUrl: config.argocdBaseUrl, argocdApiToken: '', pinBaseUrl: true, tokenSource: argocdToken, principal })`.
  The ArgoCD token is a plain string source: no refresh, a 401 from ArgoCD
  surfaces as the tool error, as it does in token mode.
- otherwise: `makeSessionTokenProvider(...)`, unchanged.

`pinBaseUrl: true` means the key's ArgoCD token is only ever sent to the
configured ArgoCD; `x-argocd-base-url` and the `argocdBaseUrl` tool argument are
ignored, and the token registry is not consulted.

### Session binding

`HttpSessionManager` records the `clientId` that opened each session. A request
that presents `mcp-session-id` must carry the same `clientId`, otherwise it gets
the existing "Invalid or expired session ID" 400. Today any authenticated caller
who knows a session's UUID can use it; this closes that for OIDC and machine
sessions alike. (OIDC `clientId` is the registered MCP client id, stable per
client, so no human flow changes.)

### Permissions

ArgoCD RBAC only, per the team's decision. The tool set stays process-wide
(`MCP_READ_ONLY`, `MCP_ENABLE_RESOURCE_MUTATIONS`). A machine session on an
instance that is not read-only sees the mutating tools; a call its account may
not make returns ArgoCD's 403 as a tool error. Note that `policy.default:
role:readonly` in our ArgoCD grants every account at least the built-in
read-only role, logs included; an explicit narrower role changes nothing.

### Attribution

`ServerInfo` gains `principal?: string`. When set, the tool wrapper logs
`{ principal, tool }` at info on every call (no arguments, no results). Machine
sessions set it; OIDC sessions do not, so nothing new is logged about people.
Session start and every rejection are logged with their reason. A machine
session's start line also carries the client address (`req.ip`, which honours
`X-Forwarded-For` through `TRUST_PROXY_HOPS`): it is the one signal that a key
is being used from somewhere other than its expected path. Keys and ArgoCD
tokens are never logged.

### Unchanged

The OIDC flow, token store, OAuth endpoints and callback; token mode; SSE; the
tool implementations.

## Negative paths

| Case | Expected |
|---|---|
| `AGENT_API_KEYS` unset | no machine path; an `amk_` bearer is handed to the OIDC verifier and gets 401 |
| `AGENT_API_KEYS` malformed, empty, duplicate key, bad name, missing token | process refuses to start, naming the problem |
| `AGENT_API_KEYS` set with `AUTH_MODE=token` | process refuses to start |
| Unknown `amk_` key | 401, no session, no outbound call |
| Valid key, ArgoCD token revoked | session starts; first tool call returns ArgoCD's 401 as a tool error |
| Valid key, ArgoCD unreachable | tool calls return the client error, as in token mode |
| Machine request reuses an OIDC session id (or vice versa) | 400 invalid session |
| Machine session passes `argocdBaseUrl` for another host | ignored; pinned URL used |
| Machine session calls a mutating tool its account may not use | ArgoCD 403 as tool error |
| Session capacity full | 503, as for OIDC |
| Stateless mode | verifier runs per request; works unchanged |

## Testing

- Unit, config: every refusal above, plus a valid object; the `AUTH_MODE` check.
- Unit, verifier: routing by prefix; constant-time compare across all keys
  (a miss touches every key); unknown key throws `InvalidTokenError`; the OIDC
  path still delegates to the provider.
- Unit, session binding: same `clientId` reuses, different `clientId` is refused.
- Unit, server: machine construction pins the base URL and uses the static token
  (reuses the `oidcTransport.test.ts` pattern); `principal` is logged per call
  and absent otherwise.
- Transport-level: no harness exists for `connectHttpTransport` (OIDC discovery
  against a live ArgoCD, `process.exit`). Manual verification on
  `argocd-mcp-non-prod` with a throwaway key: OIDC login still works; an `amk_`
  session lists tools and calls `list_applications`; a wrong key gets 401; a
  session id cannot be reused across the two paths. The gap is on OPS-6124.

## Observability

No OpenTelemetry in this repo today; this change adds none. Logging as under
Attribution.

## Rollout / rollback

- One image for every ArgoCD MCP. `AGENT_API_KEYS` is set only on
  `argocd-mcp-production`, after non-prod has confirmed OIDC login on the new
  image.
- The pod reads `AGENT_API_KEYS` from a Kubernetes secret that terraform builds
  from `global.etfvars` entries, as `projects/global/eks-apps/edge_logs_mcp.tf`
  does; the DevOps Agent's registration reads the same entry.
- Rotation: add a new name and key, roll the pod, move the caller, remove the old
  entry. ArgoCD token rotation: generate a new token, update the entry, roll the
  pod, `argocd account delete-token` the old one.
- Rollback: unset `AGENT_API_KEYS` (the machine path disappears) or pin the
  previous image tag.

## Follow-up (not this change)

Upstream's GHSA-rp45-5x3v-48mr fix (`MCP_AUTH_TOKEN`, loopback bind by default,
Host/Origin validation) is not in this fork. It does not affect oidc-mode
instances, which `requireBearerAuth` already gates, but it must be merged before
any token-mode instance is ever exposed on a network. Merging changes the bind
default, so every deployment will need `MCP_BIND_ADDRESS` or
`--allow-unauthenticated`. Separate ticket.

## Non-goals

- Per-key tool allowlists in the MCP (ArgoCD RBAC is the permission model).
- A key store or management API (keys are static configuration).
- `X-API-Key` or raw `Authorization` forms.
- Attribution of human sessions in tool-call logs.
- OpenTelemetry.
