import { timingSafeEqual } from 'node:crypto';
import { InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import type { OAuthTokenVerifier } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { type AgentKey, hashAgentKey, isAgentKeyShaped } from './agentKeys.js';
import { logger } from '../logging/logging.js';

// The SDK's requireBearerAuth refuses any AuthInfo without a numeric expiresAt.
// A machine key does not expire (it is rotated by configuration), so each
// verification stamps a window that comfortably outlives the request; nothing
// is stored against it.
export const MACHINE_AUTH_TTL_SEC = 60 * 60;

// What a machine session carries on req.auth.extra: the principal for logs and
// the ArgoCD token its tool calls are made with. kind distinguishes it from an
// OIDC session, whose extra holds the upstream session token instead.
export interface MachineAuth {
  kind: 'apikey';
  principal: string;
  argocdToken: string;
}

export const machineAuthOf = (auth: AuthInfo): MachineAuth | undefined => {
  const extra = auth.extra;
  if (!extra || extra.kind !== 'apikey') return undefined;
  const { principal, argocdToken } = extra;
  if (typeof principal !== 'string' || typeof argocdToken !== 'string') return undefined;
  return { kind: 'apikey', principal, argocdToken };
};

interface CompositeVerifierOptions {
  // Injectable for tests that count comparisons; production uses timingSafeEqual.
  equals?: (a: Buffer, b: Buffer) => boolean;
}

// Route a bearer token on its shape: a machine key ("amk_" + 64 hex) is checked
// against the configured key hashes, anything else goes to the OIDC verifier
// untouched. Header names play no part, so a credential resolves to exactly one
// verifier. With no keys configured the OIDC verifier is returned as-is, which
// is also why an "amk_" bearer on an instance without keys gets a plain 401.
export const createCompositeVerifier = (
  fallback: OAuthTokenVerifier,
  keys: AgentKey[] | undefined,
  opts: CompositeVerifierOptions = {}
): OAuthTokenVerifier => {
  if (!keys || keys.length === 0) return fallback;
  const equals = opts.equals ?? timingSafeEqual;

  return {
    verifyAccessToken: async (token: string): Promise<AuthInfo> => {
      if (!isAgentKeyShaped(token)) return fallback.verifyAccessToken(token);

      // Compare against every entry and keep the last match rather than
      // returning early, so the time taken reveals neither which entry matched
      // nor whether any did. Hashes are unique (enforced at load), so at most
      // one entry can match.
      const presented = hashAgentKey(token);
      let matched: AgentKey | undefined;
      for (const key of keys) {
        if (equals(presented, key.keySha256)) matched = key;
      }
      if (!matched) {
        // The reason, never the key: a rejected probe is worth a log line.
        logger.warn({ reason: 'unknown machine key' }, 'Bearer token rejected');
        throw new InvalidTokenError('Unknown API key');
      }

      const principal = `apikey:${matched.name}`;
      const machine: MachineAuth = { kind: 'apikey', principal, argocdToken: matched.argocdToken };
      const extra: Record<string, unknown> = { ...machine };
      return {
        token,
        clientId: principal,
        scopes: [],
        expiresAt: Math.floor(Date.now() / 1000) + MACHINE_AUTH_TTL_SEC,
        extra
      };
    }
  };
};
