import { createHash } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { resolveAuthMode } from './config.js';
import { logger } from '../logging/logging.js';

// ArgoCD token passthrough for oidc mode: a caller presents its own ArgoCD
// API token in x-argocd-api-token (upstream's header) instead of logging in
// through Dex, and the server calls ArgoCD with that token. The server adds
// no identity of its own; who may do what is the token's ArgoCD RBAC. The
// token is checked against ArgoCD once per session (every request in
// stateless mode), so a bad token opens no session.

export const ARGOCD_TOKEN_HEADER = 'x-argocd-api-token';

// The SDK's bearer middleware refuses an AuthInfo without expiresAt; a
// passthrough token's own lifetime is ArgoCD's business, so each session start
// stamps a window that outlives the request. Nothing is stored against it.
export const PASSTHROUGH_AUTH_TTL_SEC = 60 * 60;

// What a passthrough session carries on req.auth.extra.
export interface PassthroughAuth {
  kind: 'argocd-token';
  argocdToken: string;
  // Binds the HTTP session to this exact token; derivable without ArgoCD.
  fingerprint: string;
  // For logs: "argocd:<account>" for a local account, else "argocd-token:<fp>".
  principal: string;
}

export const passthroughAuthOf = (auth: AuthInfo): PassthroughAuth | undefined => {
  const extra = auth.extra;
  if (!extra || extra.kind !== 'argocd-token') return undefined;
  const { argocdToken, fingerprint, principal } = extra;
  if (
    typeof argocdToken !== 'string' ||
    typeof fingerprint !== 'string' ||
    typeof principal !== 'string'
  ) {
    return undefined;
  }
  return { kind: 'argocd-token', argocdToken, fingerprint, principal };
};

// Read MCP_ALLOW_ARGOCD_TOKEN. Off unless exactly "true" (trimmed, any case),
// the convention of MCP_READ_ONLY. Token mode is passthrough by nature, so the
// flag is refused there rather than silently meaning nothing.
export const resolveAllowArgocdToken = (env: NodeJS.ProcessEnv = process.env): boolean => {
  const raw = (env.MCP_ALLOW_ARGOCD_TOKEN ?? '').trim().toLowerCase();
  if (raw !== 'true') return false;
  if (resolveAuthMode(env) !== 'oidc') {
    throw new Error('MCP_ALLOW_ARGOCD_TOKEN is only supported with AUTH_MODE=oidc');
  }
  return true;
};

export type RequestRoute = 'oidc' | 'passthrough' | 'ambiguous';

// Which path a request takes, from its headers alone. Off, or no token header,
// means the OIDC bearer path exactly as before. Both credentials at once is
// refused: the server must never guess which identity a caller meant.
export const classifyRequest = (
  headers: Record<string, string | string[] | undefined>,
  allowArgocdToken: boolean
): RequestRoute => {
  const token = headers[ARGOCD_TOKEN_HEADER];
  const hasToken = typeof token === 'string' && token.trim() !== '';
  if (!allowArgocdToken || !hasToken) return 'oidc';
  return headers['authorization'] ? 'ambiguous' : 'passthrough';
};

// The full SHA-256 is the owner; the first 8 hex characters name a token in
// logs. Neither can be turned back into the token.
export const fingerprintOf = (token: string): string =>
  createHash('sha256').update(token).digest('hex');

const LOCAL_ACCOUNT = /^[a-z0-9-]+$/;

// A local ArgoCD account name (devops-agent, cerberus) is fine to log. An SSO
// user's username is an email, which must not reach a log line, so such a
// token is named by its fingerprint instead.
export const principalFor = (username: string | undefined, fingerprint: string): string =>
  username && LOCAL_ACCOUNT.test(username)
    ? `argocd:${username}`
    : `argocd-token:${fingerprint.slice(0, 8)}`;

export class PassthroughRejected extends Error {
  constructor(
    public readonly status: 401 | 503,
    message: string
  ) {
    super(message);
    this.name = 'PassthroughRejected';
  }
}

// Ask ArgoCD whether the token is live, and for whom. Anything ArgoCD does
// not answer "logged in" to is a 401 (no session is created); ArgoCD being
// unreachable or failing is a 503, never a pass.
export const verifyArgocdToken = async (
  argocdBaseUrl: string,
  token: string,
  fetchImpl: typeof fetch = fetch
): Promise<{ username?: string }> => {
  let response: globalThis.Response;
  try {
    response = await fetchImpl(`${argocdBaseUrl.replace(/\/+$/, '')}/api/v1/session/userinfo`, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' }
    });
  } catch (error) {
    throw new PassthroughRejected(
      503,
      `ArgoCD unreachable while verifying a token: ${error instanceof Error ? error.message : String(error)}`
    );
  }
  if (response.status === 401 || response.status === 403) {
    throw new PassthroughRejected(401, 'ArgoCD rejected the token');
  }
  if (!response.ok) {
    throw new PassthroughRejected(503, `ArgoCD answered ${response.status} to userinfo`);
  }
  const info = (await response.json()) as { loggedIn?: boolean; username?: string };
  if (info.loggedIn !== true) throw new PassthroughRejected(401, 'ArgoCD rejected the token');
  return { username: info.username };
};

export interface PassthroughMiddlewareDeps {
  allowArgocdToken: boolean;
  argocdBaseUrl: string;
  stateless: boolean;
  verify?: typeof verifyArgocdToken;
}

// Express middleware in front of the OIDC bearer check. On the passthrough
// path it attaches an AuthInfo (so the bearer check is skipped and the handler
// sees one shape of identity for both paths); on the OIDC path it does
// nothing. The token is verified with ArgoCD when a session starts (no
// mcp-session-id) and on every request in stateless mode; a request that
// reuses a session only needs the owner, which the fingerprint gives without
// a round trip, and the session's own owner check does the rest.
export const createPassthroughMiddleware = (deps: PassthroughMiddlewareDeps) => {
  const verify = deps.verify ?? verifyArgocdToken;
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const route = classifyRequest(req.headers, deps.allowArgocdToken);
    if (route === 'oidc') return next();
    if (route === 'ambiguous') {
      logger.warn({ reason: 'both x-argocd-api-token and Authorization sent' }, 'Request rejected');
      res.status(400).json({
        error: 'invalid_request',
        error_description: 'Send either x-argocd-api-token or Authorization, not both'
      });
      return;
    }
    const token = (req.headers[ARGOCD_TOKEN_HEADER] as string).trim();
    const fingerprint = fingerprintOf(token);
    const sessionStart = deps.stateless || !req.headers['mcp-session-id'];
    let principal = `argocd-token:${fingerprint.slice(0, 8)}`;
    if (sessionStart) {
      try {
        const { username } = await verify(deps.argocdBaseUrl, token);
        principal = principalFor(username, fingerprint);
      } catch (error) {
        const rejected =
          error instanceof PassthroughRejected
            ? error
            : new PassthroughRejected(503, String(error));
        logger.warn({ reason: rejected.message, status: rejected.status }, 'Bearer token rejected');
        res.status(rejected.status).json({
          error: rejected.status === 401 ? 'invalid_token' : 'temporarily_unavailable',
          error_description:
            rejected.status === 401 ? 'ArgoCD rejected the token' : 'ArgoCD unavailable'
        });
        return;
      }
    }
    const extra: Record<string, unknown> = {
      kind: 'argocd-token',
      argocdToken: token,
      fingerprint,
      principal
    } satisfies PassthroughAuth;
    req.auth = {
      token,
      clientId: principal,
      scopes: [],
      expiresAt: Math.floor(Date.now() / 1000) + PASSTHROUGH_AUTH_TTL_SEC,
      extra
    };
    next();
  };
};
