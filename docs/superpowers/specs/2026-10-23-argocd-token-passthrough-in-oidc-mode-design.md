# ArgoCD token passthrough alongside OIDC

**Date:** 2026-10-23 (supersedes the 2026-10-22 machine-API-key design)
**Status:** Approved (team decision 2026-10-23: passthrough; validation at session start and the `x-argocd-api-token` header on Mihaela's call)
**Branch:** mb/OPS-6124-machine-keys
**Ticket:** OPS-6124

## Problem

The DevOps Agent (an AWS-hosted agent) has to use the production instance
(`AUTH_MODE=oidc`). It cannot do a browser login; it can only present a fixed
bearer token or API key. In oidc mode every `/mcp` request goes through
`requireBearerAuth`, whose only verifier accepts opaque tokens this server
minted after a Dex login, so a machine has no way in.

The first design gave machines server-issued API keys mapped to server-held
ArgoCD tokens (`AGENT_API_KEYS`). The team chose passthrough instead: the
caller presents its own ArgoCD token, as upstream's token mode already does,
and the server adds no identity of its own.

## Decision

In oidc mode, when `MCP_ALLOW_ARGOCD_TOKEN=true`, accept a caller's ArgoCD API
token in `x-argocd-api-token` and call ArgoCD with it. Permissions are the
token's ArgoCD RBAC; each machine caller gets its own local ArgoCD account.

### What is accepted with this choice

- The server authenticates no machine caller itself: anyone who can reach the
  endpoint with any valid ArgoCD token can use it, within that token's RBAC.
- The production ArgoCD token lives where the caller is configured (for the
  DevOps Agent: its service registration and `service`'s terraform state).
- Attribution is ArgoCD's account, not a server-issued identity.

None of this is privilege escalation; it is the access the token already has
against the ArgoCD API.

### Configuration

- `MCP_ALLOW_ARGOCD_TOKEN`: `true` enables passthrough (trimmed, case-insensitive,
  only `true`). Default off: nothing changes on any instance. Refused outside
  `AUTH_MODE=oidc`, where token mode is passthrough by nature.

### Routing (oidc `/mcp`)

Decided from the headers alone, before any verifier runs:

| Flag | `x-argocd-api-token` (non-blank) | `Authorization` | Path |
|---|---|---|---|
| off | any | any | OIDC bearer, unchanged |
| on | absent | any | OIDC bearer, unchanged |
| on | present | absent | passthrough |
| on | present | present | 400, the server never guesses which identity was meant |

### Passthrough path

- **Verified at session start.** On a request with no `mcp-session-id` (and on
  every request in stateless mode) the server calls
  `GET /api/v1/session/userinfo` on the pinned ArgoCD with the token. Logged in
  → continue; not logged in, 401 or 403 → 401 and no session; ArgoCD
  unreachable, silent past a 10 s deadline, 5xx, or answering something other
  than JSON → 503, never a pass (and none of those messages carry the body or
  the token). This is what keeps junk tokens from filling the session pool
  humans share, at one ArgoCD call per session.
- **Owner is the token.** The session is bound to the token's SHA-256, so a
  reuse request needs no round trip and only the same token can pick it up.
- **Principal for logs.** `argocd:<account>` when userinfo says the token is
  a local account's (issuer `argocd`) and the name matches `[a-z0-9-]+`, the
  pattern being only a guard on what is logged; otherwise `argocd-token:<8 hex
  of the fingerprint>`, SSO users included, so a person never reaches a log
  line.
- **Base URL pinned**; `x-argocd-base-url`, `argocdBaseUrl` and the token
  registry are ignored.
- One dispatcher classifies each request once from its headers and routes it
  to the SDK's bearer check (OIDC) or to the passthrough middleware (token
  header present, including the ambiguous case). The middleware attaches an
  AuthInfo of the same shape the OIDC path gets, so the handler sees one kind
  of identity; it keeps its own classification as a defence-in-depth guard.
  Nothing on the passthrough route passes through `requireBearerAuth`.

### Unchanged from the key design

Session ownership (`oidc:<session id>` for OIDC logins, fail closed without
one), per-call `{principal, tool, outcome}` logging, the session-start line
with the client address, rejection logging, the 401 for unknown opaque tokens,
the extracted and tested `createOidcMcpHandler`.

## Negative paths

| Case | Expected |
|---|---|
| Flag unset | header ignored; the request takes the OIDC path and gets 401 without a bearer |
| Flag set with `AUTH_MODE=token` | process refuses to start |
| Token header and `Authorization` together | 400, nothing verified |
| Token ArgoCD rejects (invalid, expired, revoked, deleted account) | 401 at session start, no session, reason logged |
| ArgoCD unreachable or 5xx at session start | 503, no session |
| Another token presenting the session id | 400 invalid session |
| OIDC bearer presenting a passthrough session id | 400 invalid session |
| Token revoked after the session started | ArgoCD 401 on the next call, returned as the tool result; session dies on idle timeout |
| Tool the account may not use | ArgoCD 403 as tool result |
| Session capacity full | 503 |
| Stateless | verified per request; no session kept |

## Testing

- Unit, flag/routing/naming/verification (`argocdTokenPassthrough.test.ts`):
  flag parsing and refusal; the routing table; principal naming; userinfo
  outcomes with an injected fetch; the middleware (off, no header, ambiguous,
  session start verifies and attaches, reuse does not verify, stateless
  verifies, SSO email never attached, 401/503 with a log line and no next).
- Unit, session credentials: owner by fingerprint; OIDC owner by login; fail
  closed without a session id; credentials for both paths.
- Handler (`oidcMcpHandler.test.ts`): passthrough and OIDC initialize, reuse
  by the owner, refusal of another principal, stateless, lifecycle hooks, 400
  and 503.
- Wiring (`transport.test.ts`): token mode with the flag set refuses to start
  (the one guarantee that lives in the wiring, not in a unit); the dispatcher
  is unit-tested for all four header combinations and for flag-off.
- Not unit-testable: the rest of `connectHttpTransport` (OIDC discovery against
  a live ArgoCD, `process.exit`). Covered by the local end-to-end run against a
  fake ArgoCD with a userinfo endpoint, then the non-prod validation recorded
  on OPS-6124.

## Observability

No OpenTelemetry in this repo today; this change adds none. Logging as above.

## Rollout / rollback

- One image for every ArgoCD MCP. `MCP_ALLOW_ARGOCD_TOKEN` is set only on
  `argocd-mcp-production`, after non-prod has validated the image.
- The DevOps Agent registration carries the `devops-agent` ArgoCD token as an
  `api_key` with header `x-argocd-api-token`, from one etfvars entry under
  `eu-west-1@service`. No pod secret is needed.
- Rollback: unset the flag (the passthrough path closes) or pin the previous
  image tag. Revoking the caller: `argocd account delete-token`.

## Non-goals

- Server-issued machine identities (the superseded design).
- `client_credentials` OAuth in bundled Dex.
- Per-caller tool allowlists in the server; OpenTelemetry.
